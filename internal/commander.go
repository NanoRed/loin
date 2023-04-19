package internal

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Commander struct {
	Adapter  *Adapter
	Sniffer  *pcap.Handle
	Client   *Link
	Proxy    *Proxy
	Junction *Junction
	Handle   *func(packet *Packet)
}

func NewCommander(adapter *Adapter) (commander *Commander) {
	commander = &Commander{
		Adapter:  adapter,
		Proxy:    NewProxy(),
		Junction: NewJunction(),
	}
	var err error
	commander.Sniffer, err = pcap.OpenLive(adapter.Id, 65535, true, pcap.BlockForever)
	if err != nil {
		logger.Panic("pcap openlive err:%v", err)
	}
	return
}

func (c *Commander) OnDuty() {
	c.StartToCapture()
	logger.Pure("Obtaining the rest parameters...")
	c.AcquireGatewayMAC()
	logger.Pure("* gateway MAC: %s", c.Adapter.GetGatewayMAC())
	c.AcquireConsoleAddress()
	logger.Pure("* console IP: %s", c.Adapter.GetConsoleIP())
	logger.Pure("* console MAC: %s", c.Adapter.GetConsoleMAC())
	c.ConnectToServer()
	logger.Pure("Successfully connected to the server")
	c.ForwardPackets()
	logger.Pure("Start forwarding the packets...")
}

func (c *Commander) SetFilter(format string, a ...any) {
	filter := fmt.Sprintf(format, a...)
	err := c.Sniffer.SetBPFFilter(filter)
	if err != nil {
		logger.Panic("sniffer set filter err:[%s]%v", filter, err)
	}
}

func (c *Commander) BlockPackets() {
	c.SetFilter("ether src 00:00:00:00:00:00")
}

func (c *Commander) SwapSnifferHandle(newHandle func(*Packet)) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&c.Handle)), unsafe.Pointer(&newHandle))
}

func (c *Commander) Write(data []byte) (err error) {
	return c.Sniffer.WritePacketData(data)
}

func (c *Commander) StartToCapture() {
	c.BlockPackets()
	discard := func(*Packet) { logger.Warn("this log should not appear") }
	c.Handle = &discard
	go func() {
		packetSource := gopacket.NewPacketSource(c.Sniffer, c.Sniffer.LinkType())
		for p := range packetSource.Packets() {
			dp := GetDirtyPacket()
			dp.Object = p
			go func(p *Packet) {
				(*(*func(packet *Packet))(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&c.Handle)))))(p)
			}(dp)
		}
	}()
}

func (c *Commander) AcquireGatewayMAC() {
	sig := make(chan struct{}, 1)
	sig <- struct{}{}
	var once sync.Once
	c.SwapSnifferHandle(func(p *Packet) {
		if mac, ok := p.IsARPReplyFromGatewayMAC(c); ok {
			once.Do(func() {
				c.Adapter.SetGatewayMAC(mac)
				<-sig
			})
		}
		p.Recycle()
	})
	c.SetFilter("src host %s", c.Adapter.GetGatewayIP())
	if err := c.Write(MakeReqARPForGatewayMAC(c)); err != nil {
		logger.Error("failed to write request arp packet:%v", err)
	}
	sig <- struct{}{}
	close(sig)
	c.BlockPackets()
}

func (c *Commander) AcquireConsoleAddress() {
	sig := make(chan struct{}, 1)
	sig <- struct{}{}
	var once sync.Once
	c.SwapSnifferHandle(func(p *Packet) {
		if ip, mac, ok := p.IsIPv4DNSRequestFromConsole(); ok {
			once.Do(func() {
				c.Adapter.SetConsoleIP(ip)
				c.Adapter.SetConsoleMAC(mac)
				<-sig
			})
		}
		p.Recycle()
	})
	c.SetFilter("dst host %s or dst host %s", PrimaryDNS.GetIP(), SecondaryDNS.GetIP())
	sig <- struct{}{}
	close(sig)
	c.BlockPackets()
}

func (c *Commander) ConnectToServer(a ...any) {
	var err error
	c.Client, err = Dial(LANServer)
	if err != nil {
		logger.Panic("can't dial to the LAN server")
	}
	var block chan struct{}
	if len(a) == 0 {
		block = make(chan struct{}, 1)
		block <- struct{}{}
		defer func() { block <- struct{}{}; close(block) }()
	} else {
		block = a[0].(chan struct{})
	}
	go func() {
		defer func() {
			logger.Pure("Trying to reconnect to the server...")
			c.ConnectToServer(block)
		}()
		defer c.Client.Close()
		go func() {
			defer c.Client.Close()
			// register
			frame := &Frame{
				Type:    SrvRegister,
				Payload: c.Adapter.Console.Encode(),
			}
			if _, err := c.Client.SafeWrite(frame.Encode()); err != nil {
				logger.Error("failed to register:%v", err)
				return
			}
			// send heartbeat
			ticker := time.NewTicker(HeartbeatInterval)
			defer ticker.Stop()
			for {
				<-ticker.C
				frame := &Frame{
					Type: SrvHeartbeat,
				}
				if _, err := c.Client.SafeWrite(frame.Encode()); err != nil {
					logger.Error("failed to write heartbeat frame:%v", err)
					return
				}
			}
		}()
		reader := NewFrameReader(c.Client)
		for {
			frame, err := reader.NextFrame()
			if err != nil {
				logger.Error("failed to read next frame:%v", err)
				return
			}
			go func() {
				defer c.Client.Close()
				switch frame.Type {
				case CliEndToEnd:
					// TODO
				case CliBroadcast:
					// TODO
				case CliResponse:
					switch frame.Reserved {
					case 0:
						// successful, no need to do anything
					case 1:
						logger.Warn("request failed:%s", frame.Payload)
					case 2:
						logger.Error("request failed:%s", frame.Payload)
						return
					}
				case CliJunction:
					c.Junction.DecodeGuide(frame.Payload)
					var message bytes.Buffer
					consoleIP := c.Adapter.GetConsoleIP().String()
					c.Junction.Range(func(key string, id int, link *Link) {
						message.WriteByte('[')
						if strings.Compare(key, consoleIP) == 0 {
							message.WriteString("* ")
						}
						message.WriteString(key)
						message.WriteByte(']')
					})
					logger.Pure("Clients updated:%s", message.Bytes())
					<-block
				default:
					logger.Error("unknown frame type")
				}
			}()
		}
	}()
}

func (c *Commander) ForwardPackets() {
	c.SwapSnifferHandle(func(p *Packet) {
		if repackBytes, toServer := p.Repack(c); repackBytes != nil {
			if toServer {

			} else if err := c.Write(repackBytes); err != nil {
				logger.Error("failed to write repack packet:%v", err)
			}
		}
		p.Recycle()
	})
	c.SetFilter("ether src %s or ether src %s", c.Adapter.GetConsoleMAC(), c.Adapter.GetGatewayMAC())
}

func (c *Commander) OffDuty() {
	c.Sniffer.Close()
	c.Client.Close()
	c.Proxy.Close()
	c.Junction.Close()
}

package internal

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Sniffer struct {
	adapter *Adapter
	handle  *func(packet *Packet)
}

func NewSniffer(adapter *Adapter) (sniffer *Sniffer) {
	var err error
	adapter.handle, err = pcap.OpenLive(adapter.Id, 65535, true, pcap.BlockForever)
	if err != nil {
		logger.Panic("pcap openlive err:%v", err)
	}
	sniffer = &Sniffer{
		adapter: adapter,
	}
	return
}

func (s *Sniffer) Run() {
	// start the sniffer
	s.Start()

	// acquire the gateway mac
	s.AcquireGatewayMAC()

	// acquire the console address
	s.AcquireConsoleAddress()

	// forward the packets
	s.ForwardPackets()

	// ctrl+c will close the client
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT)
	<-sig
}

func (s *Sniffer) Start() {
	s.BlockPackets()
	discard := func(*Packet) { logger.Warn("this log should not appear") }
	s.handle = &discard
	go func() {
		packetSource := gopacket.NewPacketSource(s.adapter.handle, s.adapter.handle.LinkType())
		for p := range packetSource.Packets() {
			// goroutine.CommonPool.Add(goroutine.Task(func() {
			// 	(*s.handle)(&Packet{ptr})
			// }))
			go func(p *Packet) { (*s.handle)(p) }(&Packet{p})
		}
	}()
}

func (s *Sniffer) SetFilter(format string, a ...any) {
	filter := fmt.Sprintf(format, a...)
	err := s.adapter.handle.SetBPFFilter(filter)
	if err != nil {
		logger.Panic("pcap handle set filter err:[%s]%v", filter, err)
	}
}

func (s *Sniffer) BlockPackets() {
	s.SetFilter("ether src 00:00:00:00:00:00")
}

func (s *Sniffer) SwapHandle(newHandle func(*Packet)) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&s.handle)), unsafe.Pointer(&newHandle))
}

func (s *Sniffer) Write(packet *Packet) (err error) {
	err = s.adapter.handle.WritePacketData(packet.Encode())
	if err != nil {
		logger.Error("failed to write packet:%v", err)
	}
	return
}

func (s *Sniffer) WriteBuffer(buffer []byte) (err error) {
	err = s.adapter.handle.WritePacketData(buffer)
	if err != nil {
		logger.Error("failed to write packet:%v", err)
	}
	return
}

func (s *Sniffer) AcquireGatewayMAC() {
	sig := make(chan struct{}, 1)
	sig <- struct{}{}
	var once sync.Once
	s.SwapHandle(func(p *Packet) {
		if mac, ok := p.IsARPReplyFromGatewayMAC(s.adapter); ok {
			once.Do(func() {
				s.adapter.SetGatewayMAC(mac)
				<-sig
				logger.Info("obtained the gateway mac[%s]", mac)
			})
		}
	})
	s.SetFilter("src host %s", s.adapter.GetGatewayIP())
	ReqPacket := &Packet{}
	ReqPacket.MakeReqARPForObtainingGatewayMAC(s.adapter)
	s.Write(ReqPacket)
	sig <- struct{}{}
	close(sig)
	s.BlockPackets()
}

func (s *Sniffer) AcquireConsoleAddress() {
	sig := make(chan struct{}, 1)
	sig <- struct{}{}
	var once sync.Once
	s.SwapHandle(func(p *Packet) {
		if ip, mac, ok := p.IsIPv4DNSRequestFromConsole(s.adapter); ok {
			once.Do(func() {
				s.adapter.SetConsoleIP(ip)
				s.adapter.SetConsoleMAC(mac)
				<-sig
				logger.Info("obtained the console ip[%s] and mac[%s]", ip.To4(), mac)
			})
		}
	})
	s.SetFilter("dst host %s or dst host %s", PrimaryDNS.GetIP(), SecondaryDNS.GetIP())
	sig <- struct{}{}
	close(sig)
	s.BlockPackets()
}

func (s *Sniffer) ForwardPackets() {
	s.SwapHandle(func(p *Packet) {
		if b := p.Repack(s.adapter); b != nil {
			s.WriteBuffer(b)
		}
	})
	s.SetFilter("ether src %s or ether src %s", s.adapter.GetConsoleMAC(), s.adapter.GetGatewayMAC())
	// s.SetFilter("src host %s or dst host %s", s.adapter.GetConsoleIP(), s.adapter.GetLocalIP())
}

func (s *Sniffer) Close() {
	s.adapter.handle.Close()
}

package internal

import (
	"bytes"
	"net"
	"sync"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var PacketPool = sync.Pool{New: func() any { return &Packet{} }}

type Packet struct {
	Object gopacket.Packet
}

func GetDirtyPacket() (packet *Packet) {
	packet = PacketPool.Get().(*Packet)
	return
}

func MakeReqARPForGatewayMAC(commander *Commander) []byte {
	localIP := commander.Adapter.GetLocalIP()
	localMAC := commander.Adapter.GetLocalMAC()
	gatewayIP := commander.Adapter.GetGatewayIP()
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: localIP,
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    gatewayIP,
	}
	eth := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{},
		eth,
		arp,
	)
	if err != nil {
		logger.Error("make request arp for gateway error:%v", err)
	}
	return buffer.Bytes()
}

func (p *Packet) Recycle() {
	PacketPool.Put(p)
}

func (p *Packet) Decode(data []byte) {
	p.Object = gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
}

func (p *Packet) IsARPReplyFromGatewayMAC(commander *Commander) (srcMAC net.HardwareAddr, yes bool) {
	if arpLayer := p.Object.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPReply &&
			commander.Adapter.GetGatewayIP().Equal(arp.SourceProtAddress) {
			srcMAC = net.HardwareAddr(arp.SourceHwAddress)
			yes = true
		}
	}
	return
}

func (p *Packet) IsIPv4DNSRequestFromConsole() (srcIP net.IP, srcMAC net.HardwareAddr, yes bool) {
	ethLayer := p.Object.Layer(layers.LayerTypeEthernet)
	ipLayer := p.Object.Layer(layers.LayerTypeIPv4)
	if ethLayer != nil && ipLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		ip := ipLayer.(*layers.IPv4)
		if ip.DstIP.Equal(PrimaryDNS.GetIP()) ||
			ip.DstIP.Equal(SecondaryDNS.GetIP()) {
			srcIP = ip.SrcIP
			srcMAC = eth.SrcMAC
			yes = true
		}
	}
	return
}

func (p *Packet) Repack(commander *Commander) (packetBytes []byte, frameBytes []byte) {
	if ethLayer := p.Object.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		switch {

		// from gateway
		case bytes.Equal(eth.SrcMAC, commander.Adapter.GetGatewayMAC()):
			if ipLayer := p.Object.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)

				// forward the tcp packets
				if tcpLayer := p.Object.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp := tcpLayer.(*layers.TCP)
					newDstPort, ok := commander.Proxy.GetNewDstPort(PortNumber(tcp.DstPort))
					if ok {
						eth.SrcMAC = commander.Adapter.GetLocalMAC()
						eth.DstMAC = commander.Adapter.GetConsoleMAC()
						ip.DstIP = commander.Adapter.GetConsoleIP()
						tcp.DstPort = layers.TCPPort(newDstPort)
						buffer := gopacket.NewSerializeBuffer()
						tcp.SetNetworkLayerForChecksum(p.Object.NetworkLayer())
						if err := gopacket.SerializeLayers(
							buffer,
							gopacket.SerializeOptions{
								FixLengths:       true,
								ComputeChecksums: true,
							},
							eth,
							ip,
							tcp,
							gopacket.Payload(tcpLayer.LayerPayload()),
						); err != nil {
							logger.Error("repack the tcp to console error:%v", err)
						}
						packetBytes = buffer.Bytes()
						return
					}

				} else if udpLayer := p.Object.Layer(layers.LayerTypeUDP); udpLayer != nil { // forward the udp packets
					udp := udpLayer.(*layers.UDP)
					newDstPort, ok := commander.Proxy.GetNewDstPort(PortNumber(udp.DstPort))
					if ok {
						eth.SrcMAC = commander.Adapter.GetLocalMAC()
						eth.DstMAC = commander.Adapter.GetConsoleMAC()
						ip.DstIP = commander.Adapter.GetConsoleIP()
						udp.DstPort = layers.UDPPort(newDstPort)
						buffer := gopacket.NewSerializeBuffer()
						udp.SetNetworkLayerForChecksum(p.Object.NetworkLayer())
						if err := gopacket.SerializeLayers(
							buffer,
							gopacket.SerializeOptions{
								FixLengths:       true,
								ComputeChecksums: true,
							},
							eth,
							ip,
							udp,
							gopacket.Payload(udpLayer.LayerPayload()),
						); err != nil {
							logger.Error("repack the udp to console error:%v", err)
						}
						packetBytes = buffer.Bytes()
						return
					}
				}
			}

		// from console
		case bytes.Equal(eth.SrcMAC, commander.Adapter.GetConsoleMAC()):
			if arpLayer := p.Object.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)

				// request arp
				if arp.Operation == layers.ARPRequest {

					// gratuitous arp, tell other devices its mac
					if bytes.Equal(arp.SourceProtAddress, arp.DstProtAddress) {
						if id, ok := commander.Junction.GetID(net.IP(arp.SourceProtAddress).String()); ok {
							frame := &Frame{
								Type:     SrvBroadcast,
								Reserved: id,
								Payload:  p.Object.Data(),
							}
							frameBytes = frame.Encode()
							return
						}

					} else if _, ok := commander.Junction.GetID(net.IP(arp.DstProtAddress).String()); ok ||
						commander.Adapter.GetLocalIP().Equal(arp.DstProtAddress) { // reply LAN mac(i.e. local mac)
						eth.DstMAC = eth.SrcMAC
						eth.SrcMAC = commander.Adapter.GetLocalMAC()
						arp.DstHwAddress = arp.SourceHwAddress
						arp.SourceHwAddress = eth.SrcMAC
						arp.DstProtAddress, arp.SourceProtAddress = arp.SourceProtAddress, arp.DstProtAddress
						arp.Operation = layers.ARPReply
						buffer := gopacket.NewSerializeBuffer()
						if err := gopacket.SerializeLayers(
							buffer,
							gopacket.SerializeOptions{},
							eth,
							arp,
						); err != nil {
							logger.Error("repack the reply arp to console error:%v", err)
						}
						packetBytes = buffer.Bytes()
						return

					}
				}

			} else if ipLayer := p.Object.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)

				// LAN packets
				if commander.Adapter.Network.Contains(ip.DstIP) {
					if id, ok := commander.Junction.GetID(ip.DstIP.String()); ok {
						frame := &Frame{
							Type:     SrvEndToEnd,
							Reserved: id,
							Payload:  p.Object.Data(),
						}
						frameBytes = frame.Encode()
						return
					}

				} else { // internet packets

					// forward the tcp packets
					if tcpLayer := p.Object.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp := tcpLayer.(*layers.TCP)
						newSrcPort, ok := commander.Proxy.GetNewSrcPort(
							PortTypeTCP,
							PortNumber(tcp.SrcPort),
							ip.DstIP,
							PortNumber(tcp.DstPort),
						)
						if ok {
							eth.SrcMAC = commander.Adapter.GetLocalMAC()
							eth.DstMAC = commander.Adapter.GetGatewayMAC()
							ip.SrcIP = commander.Adapter.GetLocalIP()
							tcp.SrcPort = layers.TCPPort(newSrcPort)
							buffer := gopacket.NewSerializeBuffer()
							tcp.SetNetworkLayerForChecksum(p.Object.NetworkLayer())
							if err := gopacket.SerializeLayers(
								buffer,
								gopacket.SerializeOptions{
									FixLengths:       true,
									ComputeChecksums: true,
								},
								eth,
								ip,
								tcp,
								gopacket.Payload(tcpLayer.LayerPayload()),
							); err != nil {
								logger.Error("repack the tcp to gateway error:%v", err)
							}
							packetBytes = buffer.Bytes()
							return
						}

					} else if udpLayer := p.Object.Layer(layers.LayerTypeUDP); udpLayer != nil { // forward the udp packets
						udp := udpLayer.(*layers.UDP)
						newSrcPort, ok := commander.Proxy.GetNewSrcPort(
							PortTypeUDP,
							PortNumber(udp.SrcPort),
							ip.DstIP,
							PortNumber(udp.DstPort),
						)
						if ok {
							eth.SrcMAC = commander.Adapter.GetLocalMAC()
							eth.DstMAC = commander.Adapter.GetGatewayMAC()
							ip.SrcIP = commander.Adapter.GetLocalIP()
							udp.SrcPort = layers.UDPPort(newSrcPort)
							buffer := gopacket.NewSerializeBuffer()
							udp.SetNetworkLayerForChecksum(p.Object.NetworkLayer())
							if err := gopacket.SerializeLayers(
								buffer,
								gopacket.SerializeOptions{
									FixLengths:       true,
									ComputeChecksums: true,
								},
								eth,
								ip,
								udp,
								gopacket.Payload(udpLayer.LayerPayload()),
							); err != nil {
								logger.Error("repack the udp to gateway error:%v", err)
							}
							packetBytes = buffer.Bytes()
							return
						}

					} else if icmpLayer := p.Object.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
						// // for safety and performance, we should ignore this icmp packet
						// eth.SrcMAC = commander.Adapter.GetLocalMAC()
						// eth.DstMAC = commander.Adapter.GetGatewayMAC()
						// ip.SrcIP = commander.Adapter.GetLocalIP()
						// buffer := gopacket.NewSerializeBuffer()
						// if err := gopacket.SerializeLayers(
						// 	buffer,
						// 	gopacket.SerializeOptions{
						// 		FixLengths:       true,
						// 		ComputeChecksums: true,
						// 	},
						// 	eth,
						// 	ip,
						// 	gopacket.Payload(icmpLayer.LayerPayload()),
						// ); err != nil {
						// 	logger.Error("repack the icmp to gateway error:%v", err)
						// }
						// packetBytes = buffer.Bytes()
						return

					}
				}
			}

			logger.Info("other console packets need to be done:%v", p)
		}
	}
	return
}

// TODO make in the local client
func (p *Packet) ModifyLANGratuitousARP(commander *Commander) []byte {
	// eth.DstMAC: ff:ff:ff:ff:ff:ff
	// arp.DstHwAddress: 00:00:00:00:00:00
	eth := p.Object.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	arp := p.Object.Layer(layers.LayerTypeARP).(*layers.ARP)
	eth.SrcMAC = commander.Adapter.GetLocalMAC()
	arp.SourceHwAddress = eth.SrcMAC
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{},
		eth,
		arp,
	); err != nil {
		logger.Error("failed to modify the gratuitous arp:%v", err)
	}
	return buffer.Bytes()
}

// TODO save local mac and console mac to the clients
func (p *Packet) ModifyLANIPv4(commander *Commander) []byte {
	ethLayer := p.Object.Layer(layers.LayerTypeEthernet)
	eth := ethLayer.(*layers.Ethernet)
	eth.SrcMAC = commander.Adapter.GetLocalMAC()
	eth.DstMAC = commander.Adapter.GetConsoleMAC()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{},
		eth,
		gopacket.Payload(ethLayer.LayerPayload()),
	); err != nil {
		logger.Error("failed to modify the gratuitous arp:%v", err)
	}
	return buffer.Bytes()
}

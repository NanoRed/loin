package internal

import (
	"bytes"
	"net"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// type LayerKey uint8

// const (
// 	LayerEthernet LayerKey = iota
// 	LayerARP
// 	LayerIPv4
// )

type Packet struct {
	Obj gopacket.Packet
	// Layers map[LayerKey]gopacket.Layer
}

func (p *Packet) Encode() []byte {
	return p.Obj.Data()
}

func (p *Packet) MakeReqARPForObtainingGatewayMAC(adapter *Adapter) {
	localIP := adapter.GetLocalIP()
	localMAC := adapter.GetLocalMAC()
	gatewayIP := adapter.GetGatewayIP()
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
	p.Obj = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func (p *Packet) IsARPReplyFromGatewayMAC(adapter *Adapter) (srcMAC net.HardwareAddr, yes bool) {
	if arpLayer := p.Obj.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPReply &&
			adapter.GetGatewayIP().Equal(arp.SourceProtAddress) {
			srcMAC = net.HardwareAddr(arp.SourceHwAddress)
			yes = true
		}
	}
	return
}

func (p *Packet) IsIPv4DNSRequestFromConsole(adapter *Adapter) (srcIP net.IP, srcMAC net.HardwareAddr, yes bool) {
	ethLayer := p.Obj.Layer(layers.LayerTypeEthernet)
	ipLayer := p.Obj.Layer(layers.LayerTypeIPv4)
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

func (p *Packet) Repack(adapter *Adapter) []byte {
	if ethLayer := p.Obj.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		switch {

		// from gateway
		case bytes.Equal(eth.SrcMAC, adapter.GetGatewayMAC()):
			if ipLayer := p.Obj.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)

				// forward the tcp packets
				if tcpLayer := p.Obj.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp := tcpLayer.(*layers.TCP)
					newDstPort, ok := PortProxy.GetNewDstPort(int(tcp.DstPort))
					if ok {
						eth.SrcMAC = adapter.GetLocalMAC()
						eth.DstMAC = adapter.GetConsoleMAC()
						ip.DstIP = adapter.GetConsoleIP()
						tcp.DstPort = layers.TCPPort(newDstPort)
						buffer := gopacket.NewSerializeBuffer()
						tcp.SetNetworkLayerForChecksum(p.Obj.NetworkLayer())
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
						return buffer.Bytes()
					}

				} else if udpLayer := p.Obj.Layer(layers.LayerTypeUDP); udpLayer != nil { // forward the udp packets
					udp := udpLayer.(*layers.UDP)
					newDstPort, ok := PortProxy.GetNewDstPort(int(udp.DstPort))
					if ok {
						eth.SrcMAC = adapter.GetLocalMAC()
						eth.DstMAC = adapter.GetConsoleMAC()
						ip.DstIP = adapter.GetConsoleIP()
						udp.DstPort = layers.UDPPort(newDstPort)
						buffer := gopacket.NewSerializeBuffer()
						udp.SetNetworkLayerForChecksum(p.Obj.NetworkLayer())
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
						return buffer.Bytes()
					}
				}
			}

		// from console
		case bytes.Equal(eth.SrcMAC, adapter.GetConsoleMAC()):
			if arpLayer := p.Obj.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)

				// reply the arp
				if arp.Operation == layers.ARPRequest && adapter.GetLocalIP().Equal(arp.DstProtAddress) {
					eth.DstMAC = eth.SrcMAC
					eth.SrcMAC = adapter.GetLocalMAC()
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
					return buffer.Bytes()
				}
			} else if ipLayer := p.Obj.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)

				// forward the tcp packets
				if tcpLayer := p.Obj.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp := tcpLayer.(*layers.TCP)
					newSrcPort, ok := PortProxy.GetNewSrcPort(PortTypeTCP, int(tcp.SrcPort), ip.DstIP, int(tcp.DstPort))
					if ok {
						eth.SrcMAC = adapter.GetLocalMAC()
						eth.DstMAC = adapter.GetGatewayMAC()
						ip.SrcIP = adapter.GetLocalIP()
						tcp.SrcPort = layers.TCPPort(newSrcPort)
						buffer := gopacket.NewSerializeBuffer()
						tcp.SetNetworkLayerForChecksum(p.Obj.NetworkLayer())
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
						return buffer.Bytes()
					}

				} else if udpLayer := p.Obj.Layer(layers.LayerTypeUDP); udpLayer != nil { // forward the udp packets
					udp := udpLayer.(*layers.UDP)
					newSrcPort, ok := PortProxy.GetNewSrcPort(PortTypeUDP, int(udp.SrcPort), ip.DstIP, int(udp.DstPort))
					if ok {
						eth.SrcMAC = adapter.GetLocalMAC()
						eth.DstMAC = adapter.GetGatewayMAC()
						ip.SrcIP = adapter.GetLocalIP()
						udp.SrcPort = layers.UDPPort(newSrcPort)
						buffer := gopacket.NewSerializeBuffer()
						udp.SetNetworkLayerForChecksum(p.Obj.NetworkLayer())
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
						return buffer.Bytes()
					}
				}
			}
		}
	}
	return nil
}

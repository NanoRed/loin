package internal

import (
	"bytes"
	"net"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	gopacket.Packet
}

func (p *Packet) Encode() []byte {
	return p.Data()
}

func (p *Packet) IsARP() bool {
	return p.Layer(layers.LayerTypeARP) != nil
}

func (p *Packet) IsIPv4() bool {
	return p.Layer(layers.LayerTypeIPv4) != nil
}

func (p *Packet) MakeReqARPForObtainingGatewayMAC(dev *Device) {
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   dev.IPMAC.MAC,
		SourceProtAddress: dev.IPMAC.IP,
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    dev.GatewayIPMAC.IP,
	}
	ethLayer := &layers.Ethernet{
		SrcMAC:       dev.IPMAC.MAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
		ethLayer,
		arpLayer,
	)
	p.Packet = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func (p *Packet) IsARPReplyFromGatewayMAC(dev *Device) (net.HardwareAddr, bool) {
	if arpLayer := p.Layer(layers.LayerTypeARP); arpLayer != nil {
		if arp, ok := arpLayer.(*layers.ARP); ok {
			gatewayIP := dev.GetGatewayIP()
			logger.Info("found arp reply from gateway:%v", arp)
			logger.Info("arp.SourceProtAddress:%v dev.GatewayIP:%v", arp.SourceProtAddress, []byte(gatewayIP))
			if arp.Operation == layers.ARPReply &&
				bytes.Equal(arp.SourceProtAddress, gatewayIP) {
				return net.HardwareAddr(arp.SourceHwAddress), true
			}
		}
	}
	return nil, false
}

func (p *Packet) ModifyPacketsFromSubDevices() {

}

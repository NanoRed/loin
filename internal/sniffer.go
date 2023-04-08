package internal

import (
	"fmt"

	"github.com/NanoRed/loin/pkg/goroutine"
	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Sniffer struct {
	device *Device
}

func NewSniffer(device *Device) (sniffer *Sniffer) {
	var err error
	device.handle, err = pcap.OpenLive(device.Id, 65535, true, pcap.BlockForever)
	if err != nil {
		logger.Panic("pcap openlive err:%v", err)
	}
	sniffer = &Sniffer{
		device: device,
	}
	return
}

func (s *Sniffer) ReadPackets(filter string, handle func(packet *Packet)) {
	err := s.device.handle.SetBPFFilter(filter)
	if err != nil {
		logger.Panic("pcap handle set filter err:%v", err)
	}
	packetSource := gopacket.NewPacketSource(s.device.handle, s.device.handle.LinkType())
	for p := range packetSource.Packets() {
		goroutine.CommonPool.Add(goroutine.Task(func() { handle(&Packet{p}) }))
	}
}

func (s *Sniffer) WritePackets(packet *Packet) {
	fmt.Println(packet)
	err := s.device.handle.WritePacketData(packet.Encode())
	if err != nil {
		logger.Error("failed to write packet:%v", err)
	}
}

func (s *Sniffer) Close() {
	s.device.handle.Close()
}

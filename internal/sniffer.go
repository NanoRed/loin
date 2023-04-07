package internal

import (
	"github.com/NanoRed/loin/pkg/goroutine"
	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Sniffer struct {
	handle *pcap.Handle
}

func NewSniffer(device *Device, filter string) (sniffer *Sniffer) {
	handle, err := pcap.OpenLive(device.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		logger.Panic("pcap openlive err:%v", err)
	}
	err = handle.SetBPFFilter(filter)
	if err != nil {
		logger.Panic("pcap handle set filter err:%v", err)
	}

	sniffer = &Sniffer{
		handle: handle,
	}
	return
}

func (s *Sniffer) HandlePackets(f func(*Packet)) {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		goroutine.CommonPool.Add(goroutine.Task(func() { f(&Packet{packet}) }))
	}
}

func (s *Sniffer) Close() {
	s.handle.Close()
}

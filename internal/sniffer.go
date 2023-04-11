package internal

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"github.com/NanoRed/loin/pkg/goroutine"
	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Sniffer struct {
	device *Device
	filter string
	handle *func(packet *Packet)
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

func (s *Sniffer) Handle() {
	// acquire the gateway mac first
	s.AcquireGatewayMAC()

	// then modify the packets
	s.SwapHandle(func(p *Packet) {
		p.ModifyPacketsFromSubDevices()
	})
}

func (s *Sniffer) Capture(filter string) *Sniffer {
	if ip := s.device.GetGatewayIP(); len(ip) > 0 {
		filter = fmt.Sprintf("src host %s or %s", ip, filter)
	}
	err := s.device.handle.SetBPFFilter(filter)
	if err != nil {
		logger.Panic("pcap handle set filter err:%v", err)
	}
	discard := func(*Packet) {}
	s.handle = &discard
	go func() {
		packetSource := gopacket.NewPacketSource(s.device.handle, s.device.handle.LinkType())
		for p := range packetSource.Packets() {
			goroutine.CommonPool.Add(goroutine.Task(func() {
				(*s.handle)(&Packet{p})
			}))
		}
	}()
	return s
}

func (s *Sniffer) AddFilter() {

}

func (s *Sniffer) SwapHandle(newHandle func(*Packet)) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&s.handle)), unsafe.Pointer(&newHandle))
}

func (s *Sniffer) Write(packet *Packet) {
	err := s.device.handle.WritePacketData(packet.Encode())
	if err != nil {
		logger.Error("failed to write packet:%v", err)
	}
}

func (s *Sniffer) AcquireGatewayMAC() {
	if s.handle == nil {
		logger.Panic("you need to start capturing packets first")
	}
	sig := make(chan struct{}, 1)
	sig <- struct{}{}
	s.SwapHandle(func(p *Packet) {
		if mac, ok := p.IsARPReplyFromGatewayMAC(s.device); ok {
			s.device.SetGatewayMAC(mac)
			<-sig
		}
	})
	ReqPacket := &Packet{}
	ReqPacket.MakeReqARPForObtainingGatewayMAC(s.device)
	s.Write(ReqPacket)
	sig <- struct{}{}
	close(sig)
}

func (s *Sniffer) Close() {
	s.device.handle.Close()
}

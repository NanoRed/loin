package internal

import "github.com/google/gopacket"

type Packet struct {
	gopacket.Packet
}

func (p *Packet) Test() {
	p.Dump()
}

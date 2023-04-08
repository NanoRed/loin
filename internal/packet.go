package internal

import (
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

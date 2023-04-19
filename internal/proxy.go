package internal

import (
	"net"
	"sync"

	"github.com/NanoRed/loin/pkg/logger"
)

type Proxy struct {
	SrcTable map[PortNumber]PortNumber
	DstTable map[PortNumber]PortNumber
	Links    map[*Link]struct{}
	Lock     sync.RWMutex
}

func NewProxy() (proxy *Proxy) {
	proxy = &Proxy{
		SrcTable: make(map[PortNumber]PortNumber),
		DstTable: make(map[PortNumber]PortNumber),
		Links:    make(map[*Link]struct{}),
	}
	return
}

func (p *Proxy) GetNewSrcPort(
	portType PortType, srcPort PortNumber, dstIP net.IP, dstPort PortNumber,
) (newSrcPort PortNumber, ok bool) {
	p.Lock.RLock()
	if newSrcPort, ok = p.SrcTable[srcPort]; ok {
		p.Lock.RUnlock()
		return
	}
	p.Lock.RUnlock()
	// occupy a port
	link, err := DialWithSelfDestruction(
		&Endpoint{Address: &Address{IP: dstIP.To4(), Port: &Port{portType, dstPort}}},
		func(l *Link) {
			linkport := l.GetPort()
			p.Lock.Lock()
			delete(p.SrcTable, srcPort)
			delete(p.DstTable, linkport)
			delete(p.Links, l)
			p.Lock.Unlock()
		},
	)
	if err != nil {
		logger.Error("failed to occupy a port:%v", err)
		return
	}
	p.Lock.Lock()
	p.SrcTable[srcPort] = newSrcPort
	p.DstTable[newSrcPort] = srcPort
	p.Links[link] = struct{}{}
	p.Lock.Unlock()
	newSrcPort, ok = link.GetPort(), true
	return
}

func (p *Proxy) GetNewDstPort(dstPort PortNumber) (newDstPort PortNumber, ok bool) {
	p.Lock.RLock()
	newDstPort, ok = p.DstTable[dstPort]
	p.Lock.RUnlock()
	return
}

func (p *Proxy) Close() {
	p.Lock.RLock()
	defer p.Lock.RUnlock()
	for link := range p.Links {
		link.Close()
	}
}

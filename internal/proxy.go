package internal

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/NanoRed/loin/pkg/logger"
)

type Proxy struct {
	SrcTable map[int]*Port
	DstTable map[int]int
	Lock     sync.RWMutex
	Release  chan *Port
	Destruct chan struct{}
}

type PortType int8

const (
	_ PortType = iota
	PortTypeTCP
	PortTypeUDP
)

type Port struct {
	Conn    net.Conn
	Number  int
	Expires int64
}

const (
	ConnDuration time.Duration = time.Minute * 5
)

var PortProxy = NewProxy()

func NewProxy() (proxy *Proxy) {
	proxy = &Proxy{
		SrcTable: make(map[int]*Port),
		DstTable: make(map[int]int),
		Release:  make(chan *Port, 10),
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		// ticker2 := time.NewTicker(time.Second * 10)
		// defer ticker2.Stop()

		for {
			select {
			case <-ticker.C:
				now := time.Now().UnixNano()

				proxy.Lock.RLock()
				for _, v := range proxy.SrcTable {
					if now > v.Expires {
						select {
						case proxy.Release <- v:
						default:
						}
					}
				}
				proxy.Lock.RUnlock()

			// case <-ticker2.C:

			// 	var message bytes.Buffer
			// 	message.WriteString("information of the proxy:\n")
			// 	message.WriteString(fmt.Sprintf("total of the route: %d. they are:\n", len(proxy.DstTable)))
			// 	proxy.Lock.RLock()
			// 	for d, s := range proxy.DstTable {
			// 		message.WriteString(fmt.Sprintf("[Console]SrcPort:%d => [Local]SrcPort:%d\n", s, d))
			// 	}
			// 	proxy.Lock.RUnlock()
			// 	logger.Info(message.String())

			case port := <-proxy.Release:
				proxy.Lock.Lock()
				if idx, ok := proxy.DstTable[port.Number]; ok {
					delete(proxy.SrcTable, idx)
				}
				delete(proxy.DstTable, port.Number)
				port.Close()
				proxy.Lock.Unlock()

			case <-proxy.Destruct:
				proxy.Lock.Lock()
				close(proxy.Release)
				for port := range proxy.Release {
					port.Close()
				}
				for _, port := range proxy.SrcTable {
					port.Close()
				}
				proxy.SrcTable = nil
				proxy.DstTable = nil
				proxy.Lock.Unlock()

				return
			}
		}
	}()

	return
}

func (p *Proxy) GetNewSrcPort(portType PortType, srcPort int, dstIP net.IP, dstPort int) (newSrcPort int, ok bool) {
	p.Lock.RLock()
	if port, e := p.SrcTable[srcPort]; e {
		port.Refresh()
		newSrcPort = port.Number
		ok = true
		p.Lock.RUnlock()
		return
	}
	p.Lock.RUnlock()
	p.Lock.Lock()
	defer p.Lock.Unlock()
	var conn net.Conn
	var portNum int
	var err error
	switch portType {
	case PortTypeTCP:
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", dstIP.To4(), dstPort))
		portNum = conn.LocalAddr().(*net.TCPAddr).Port
	case PortTypeUDP:
		conn, err = net.Dial("udp", fmt.Sprintf("%s:%d", dstIP.To4(), dstPort))
		portNum = conn.LocalAddr().(*net.UDPAddr).Port
	default:
		err = errors.New("unknown port type")
	}
	if err != nil {
		logger.Error("failed to occupy a port:%v", err)
		return
	}
	port := &Port{
		Conn:    conn,
		Number:  portNum,
		Expires: time.Now().Add(ConnDuration).UnixNano(),
	}
	newSrcPort = port.Number
	ok = true
	p.SrcTable[srcPort] = port
	p.DstTable[newSrcPort] = srcPort
	return
}

func (p *Proxy) GetNewDstPort(dstPort int) (newDstPort int, ok bool) {
	p.Lock.RLock()
	defer p.Lock.RUnlock()
	newDstPort, ok = p.DstTable[dstPort]
	return
}

func (p *Proxy) Close() {
	p.Destruct <- struct{}{}
}

func (p *Port) Refresh() {
	p.Expires = time.Now().Add(ConnDuration).UnixNano() // allow the race condition, so that it can be faster
	// atomic.StoreInt64(&(p.Expires), time.Now().Add(ConnDuration).UnixNano())
}

func (p *Port) Close() {
	p.Conn.Close()
}

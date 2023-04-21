package internal

import (
	"net"
	"sync"
	"time"

	"github.com/NanoRed/loin/pkg/logger"
)

var (
	LinkReadDuration time.Duration = time.Minute
	LinkWriteTimeout time.Duration = time.Second * 3
)

type Link struct {
	Conn net.Conn
	To   *Endpoint
	From *Endpoint
	Lock sync.Mutex
}

func Dial(endpoint *Endpoint) (link *Link, err error) {
	conn, err := net.Dial(
		endpoint.GetPort().GetType().String(),
		endpoint.GetIPPort(),
	)
	if err != nil {
		return
	}
	link = &Link{
		Conn: conn,
		To:   endpoint,
	}
	return
}

func DialWithSelfDestruction(endpoint *Endpoint, destruct func(link *Link)) (link *Link, err error) {
	conn, err := net.Dial(
		endpoint.GetPort().GetType().String(),
		endpoint.GetIPPort(),
	)
	if err != nil {
		return
	}
	link = &Link{Conn: conn}
	go func() {
		defer conn.Close()
		defer destruct(link)
		buffer := make([]byte, 1024)
		for {
			err := conn.SetReadDeadline(time.Now().Add(LinkReadDuration))
			if err != nil {
				return
			}
			_, err = conn.Read(buffer)
			if err != nil {
				return
			}
			logger.Info("received data from network stack")
		}
	}()
	return
}

func (l *Link) GetPort() (port PortNumber) {
	if addr, ok := l.Conn.LocalAddr().(*net.TCPAddr); ok {
		port = PortNumber(addr.Port)
	} else if addr, ok := l.Conn.LocalAddr().(*net.UDPAddr); ok {
		port = PortNumber(addr.Port)
	}
	return
}

func (l *Link) Read(b []byte) (n int, err error) {
	return l.Conn.Read(b)
}

func (l *Link) SafeWrite(b []byte) (n int, err error) {
	l.Lock.Lock()
	defer l.Lock.Unlock()
	err = l.Conn.SetWriteDeadline(time.Now().Add(LinkWriteTimeout))
	if err == nil {
		n, err = l.Conn.Write(b)
	}
	return
}

func (l *Link) Close() {
	l.Conn.Close()
}

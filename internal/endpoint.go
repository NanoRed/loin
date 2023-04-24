package internal

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
)

var (
	// 90DNS
	// EndpointPrimaryDNS   *Endpoint = &Endpoint{&Address{IP: net.ParseIP("163.172.141.219")}}
	// EndpointSecondaryDNS *Endpoint = &Endpoint{&Address{IP: net.ParseIP("207.246.121.77")}}

	// Cisco OpenDNS
	PrimaryDNS   *Endpoint = &Endpoint{&Address{IPNet: &net.IPNet{IP: net.ParseIP("208.67.222.222")}}}
	SecondaryDNS *Endpoint = &Endpoint{&Address{IPNet: &net.IPNet{IP: net.ParseIP("208.67.220.220")}}}

	// lan server
	LANServer *Endpoint = &Endpoint{&Address{IPNet: &net.IPNet{IP: net.ParseIP("106.52.81.44")}, Port: &Port{PortTypeTCP, 7714}}}
)

type PortType uint8

const (
	_ PortType = iota
	PortTypeTCP
	PortTypeUDP
)

func (p PortType) String() string {
	switch p {
	case PortTypeTCP:
		return "tcp"
	case PortTypeUDP:
		return "udp"
	}
	return ""
}

type PortNumber uint16

type Port struct {
	Type   PortType
	Number PortNumber
}

func (p *Port) GetType() PortType {
	return p.Type
}

func (p *Port) GetNumber() PortNumber {
	return p.Number
}

type Address struct {
	IPNet *net.IPNet
	MAC   net.HardwareAddr
	Port  *Port
}

type Endpoint struct {
	Address *Address
}

func (e *Endpoint) InNet(ip net.IP) bool {
	return e.Address.IPNet.Contains(ip)
}

func (e *Endpoint) LocalizeIP(ip net.IP) (newIP net.IP) {
	newIP = make(net.IP, 4)
	for i, seg := range e.Address.IPNet.Mask {
		newIP[i] = ip[i] & ^seg
		newIP[i] |= e.Address.IPNet.IP[i] & seg
	}
	return
}

func (e *Endpoint) GetNetwork() string {
	ones, _ := e.Address.IPNet.Mask.Size()
	ip := make(net.IP, 4)
	for i, seg := range e.Address.IPNet.Mask {
		ip[i] |= e.Address.IPNet.IP[i] & seg
	}
	return fmt.Sprintf("%s/%d", ip.String(), ones)
}

func (e *Endpoint) GetIPPort() string {
	return fmt.Sprintf("%s:%d", e.Address.IPNet.IP, e.Address.Port.Number)
}

func (e *Endpoint) GetIP() (ip net.IP) {
	return e.Address.IPNet.IP
}

func (e *Endpoint) GetMask() (mask net.IPMask) {
	return e.Address.IPNet.Mask
}

func (e *Endpoint) SetIP(ip net.IP) {
	if e.Address == nil {
		e.Address = &Address{IPNet: &net.IPNet{}}
	} else if e.Address.IPNet == nil {
		e.Address.IPNet = &net.IPNet{}
	}
	e.Address.IPNet.IP = ip
}

func (e *Endpoint) GetMAC() (mac net.HardwareAddr) {
	return e.Address.MAC
}

func (e *Endpoint) SetMAC(mac net.HardwareAddr) {
	if e.Address == nil {
		e.Address = &Address{}
	}
	e.Address.MAC = mac
}

func (e *Endpoint) GetPort() (port *Port) {
	return e.Address.Port
}

func (e *Endpoint) SetPort(port *Port) {
	if e.Address == nil {
		e.Address = &Address{}
	}
	e.Address.Port = port
}

func (e *Endpoint) Encode() []byte {
	var buffer bytes.Buffer
	gob.NewEncoder(&buffer).Encode(e)
	return buffer.Bytes()
}

func (e *Endpoint) Decode(b []byte) {
	gob.NewDecoder(bytes.NewBuffer(b)).Decode(e)
}

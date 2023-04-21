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
	PrimaryDNS   *Endpoint = &Endpoint{&Address{IP: net.ParseIP("208.67.222.222")}}
	SecondaryDNS *Endpoint = &Endpoint{&Address{IP: net.ParseIP("208.67.220.220")}}

	// lan server
	LANServer *Endpoint = &Endpoint{&Address{IP: net.ParseIP("106.52.81.44"), Port: &Port{PortTypeTCP, 7714}}}
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
	IP   net.IP
	MAC  net.HardwareAddr
	Port *Port
}

type Endpoint struct {
	Address *Address
}

func (e *Endpoint) GetIPPort() string {
	return fmt.Sprintf("%s:%d", e.Address.IP, e.Address.Port.Number)
}

func (e *Endpoint) GetIP() (ip net.IP) {
	return e.Address.IP
}

func (e *Endpoint) SetIP(ip net.IP) {
	if e.Address == nil {
		e.Address = &Address{}
	}
	e.Address.IP = ip
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

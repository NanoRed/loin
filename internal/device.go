package internal

import "net"

var (
	// 90DNS
	// PrimaryDNS   *Device = &Device{&Address{IP: net.ParseIP("163.172.141.219")}}
	// SecondaryDNS *Device = &Device{&Address{IP: net.ParseIP("207.246.121.77")}}

	// Cisco OpenDNS
	PrimaryDNS   *Device = &Device{&Address{IP: net.ParseIP("208.67.222.222")}}
	SecondaryDNS *Device = &Device{&Address{IP: net.ParseIP("208.67.220.220")}}
)

type Device struct {
	Address *Address
}

type Address struct {
	IP  net.IP
	MAC net.HardwareAddr
}

func (d *Device) GetIP() (ip net.IP) {
	// if d.Address != nil {
	// 	if length := len(d.Address.IP); length > 0 {
	// 		ip = make(net.IP, length)
	// 		copy(ip, d.Address.IP)
	// 	}
	// }
	return d.Address.IP
}

func (d *Device) SetIP(ip net.IP) {
	if d.Address == nil {
		d.Address = &Address{}
	}
	// d.Address.IP = make(net.IP, len(ip))
	// copy(d.Address.IP, ip)
	d.Address.IP = ip
}

func (d *Device) GetMAC() (mac net.HardwareAddr) {
	// if d.Address != nil {
	// 	if length := len(d.Address.MAC); length > 0 {
	// 		mac = make(net.HardwareAddr, length)
	// 		copy(mac, d.Address.MAC)
	// 	}
	// }
	return d.Address.MAC
}

func (d *Device) SetMAC(mac net.HardwareAddr) {
	if d.Address == nil {
		d.Address = &Address{}
	}
	// d.Address.MAC = make(net.HardwareAddr, len(mac))
	// copy(d.Address.MAC, mac)
	d.Address.MAC = mac
}

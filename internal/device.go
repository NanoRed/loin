package internal

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket/pcap"
)

type Device struct {
	Id             string
	Name           string
	Description    string
	IPMAC          *IPMAC
	IPNet          *net.IPNet
	GatewayIPMAC   *IPMAC
	SubDeviceIPMAC []*IPMAC

	Lock sync.RWMutex

	handle *pcap.Handle
}

type IPMAC struct {
	IP  net.IP
	MAC net.HardwareAddr
}

func LocalDevices() (devices []*Device) {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Panic("failed to get interfaces 1:%v", err)
	}
	mapping := make(map[string]*Device)
	for _, iface := range ifaces {
		params := netshGetConfig(iface.Name)
		if ip, ok := params["IP Address"]; ok {
			dev := &Device{
				Name: iface.Name,
				IPMAC: &IPMAC{
					MAC: iface.HardwareAddr,
				},
			}
			if v, ok := params["Subnet Prefix"]; ok {
				s := strings.IndexByte(v, '/')
				e := strings.IndexByte(v[s:], ' ')
				dev.IPMAC.IP, dev.IPNet, _ = net.ParseCIDR(ip + v[s:s+e])
			}
			if v, ok := params["Default Gateway"]; ok {
				dev.GatewayIPMAC.IP = net.ParseIP(v)
			}
			mapping[ip] = dev
		}
	}
	ifacesPcap, err := pcap.FindAllDevs()
	if err != nil {
		logger.Panic("failed to get interfaces 2:%v", err)
	}
	devices = make([]*Device, 0, 4)
	for _, iface := range ifacesPcap {
		for i := 0; i < len(iface.Addresses); i++ {
			ip := iface.Addresses[i].IP
			if dev, ok := mapping[ip.String()]; ok {
				dev.Id = iface.Name
				dev.Description = iface.Description
				devices = append(devices, dev)
			}
		}
	}
	return
}

func netshGetConfig(ifaceName string) (params map[string]string) {
	cmd := exec.Command(
		"netsh",
		"interface",
		"ipv4",
		"show",
		"config",
		"name="+ifaceName,
	)
	out, _ := cmd.CombinedOutput()
	lines := strings.Split(string(out), "\n")
	params = make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if kv := strings.Split(line, ":"); len(kv) == 2 {
			params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return params
}

func (d *Device) GetIP() (ip net.IP) {
	ip = make(net.IP, len(d.IPMAC.IP))
	copy(ip, d.IPMAC.IP)
	return
}

func (d *Device) GetMaskString() (mask string) {
	if d.IPNet != nil {
		prefixLength, _ := d.IPNet.Mask.Size()
		var octets [4]string
		for i := 0; i < 4; i++ {
			if i*8+8 <= prefixLength {
				octets[i] = "255"
			} else if i*8 >= prefixLength {
				octets[i] = "0"
			} else {
				remainingBits := prefixLength - i*8
				octets[i] = strconv.Itoa(255 - (1 << uint(8-remainingBits)))
			}
		}
		mask = strings.Join(octets[:], ".")
	}
	return
}

func (d *Device) GetGatewayIP() (ip net.IP) {
	ip = make(net.IP, len(d.GatewayIPMAC.IP))
	copy(ip, d.GatewayIPMAC.IP)
	return
}

func (d *Device) GetMAC() (mac net.HardwareAddr) {
	mac = make(net.HardwareAddr, len(d.IPMAC.MAC))
	copy(mac, d.IPMAC.MAC)
	return
}

func (d *Device) GetGatewayMAC() (mac net.HardwareAddr) {
	d.Lock.RLock()
	defer d.Lock.RUnlock()
	mac = make(net.HardwareAddr, len(d.GatewayIPMAC.MAC))
	copy(mac, d.GatewayIPMAC.MAC)
	return
}

func (d *Device) SetGatewayMAC(mac net.HardwareAddr) {
	d.Lock.Lock()
	defer d.Lock.Unlock()
	copy(d.GatewayIPMAC.MAC, mac)
}

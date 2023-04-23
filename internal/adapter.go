package internal

import (
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket/pcap"
)

type Adapter struct {
	Id          string
	Name        string
	Description string
	Network     *net.IPNet
	Local       *Endpoint
	Gateway     *Endpoint
	Console     *Endpoint
}

func LocalAdapters() (adapters []*Adapter) {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Panic("failed to get local interfaces 1:%v", err)
	}
	mapping := make(map[string]*Adapter)
	for _, iface := range ifaces {
		params := WinGetInterfaceConfig(iface.Name)
		if ip, ok := params["IP Address"]; ok {
			if ipnet, ok := params["Subnet Prefix"]; ok {
				if gwip, ok := params["Default Gateway"]; ok {
					adapter := &Adapter{
						Name: iface.Name,
					}
					s := strings.IndexByte(ipnet, '/')
					e := strings.IndexByte(ipnet[s:], ' ')
					netIP, network, _ := net.ParseCIDR(ip + ipnet[s:s+e])
					adapter.SetNetwork(network)
					adapter.SetLocalIP(netIP)
					adapter.SetLocalMAC(iface.HardwareAddr)
					adapter.SetGatewayIP(net.ParseIP(gwip))
					mapping[ip] = adapter
				}
			}
		}
	}
	ifacesPcap, err := pcap.FindAllDevs()
	if err != nil {
		logger.Panic("failed to get local interfaces 2:%v", err)
	}
	adapters = make([]*Adapter, 0, 4)
	for _, iface := range ifacesPcap {
		for i := 0; i < len(iface.Addresses); i++ {
			ip := iface.Addresses[i].IP
			if adapter, ok := mapping[ip.String()]; ok {
				adapter.Id = iface.Name
				adapter.Description = iface.Description
				adapters = append(adapters, adapter)
			}
		}
	}
	return
}

func WinGetInterfaceConfig(ifaceName string) (params map[string]string) {
	cmd := exec.Command(
		"netsh",
		"interface",
		"ipv4",
		"show",
		"config",
		"name="+ifaceName,
	)
	out, _ := cmd.CombinedOutput()
	params = make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if kv := strings.Split(strings.TrimSpace(line), ":"); len(kv) == 2 {
			params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return params
}

func GetGatewayIP() (ip net.IP) {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "print", "-4")
		out, _ := cmd.CombinedOutput()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Index(line, "0.0.0.0") == 0 {
				fields := strings.Fields(line)
				ip = net.ParseIP(fields[2]).To4()
				return
			}
		}
	case "linux":
		cmd := exec.Command("route", "-n")
		out, _ := cmd.CombinedOutput()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Index(line, "0.0.0.0") == 0 {
				fields := strings.Fields(line)
				ip = net.ParseIP(fields[1]).To4()
				return
			}
		}
	}
	return
}

func LocalAdapter() (adapter *Adapter) {
	gatewayIP := GetGatewayIP()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.IsGlobalUnicast() && v.Contains(gatewayIP) {
					adapter = &Adapter{
						Name: iface.Name,
						Network: &net.IPNet{
							IP:   v.IP.Mask(v.Mask),
							Mask: v.Mask,
						},
						Local: &Endpoint{
							&Address{
								IP:  v.IP.To4(),
								MAC: iface.HardwareAddr,
							},
						},
						Gateway: &Endpoint{
							&Address{
								IP: gatewayIP,
							},
						},
					}
					ifacesPcap, _ := pcap.FindAllDevs()
					for _, ifacePcap := range ifacesPcap {
						for i := 0; i < len(ifacePcap.Addresses); i++ {
							if v.IP.Equal(ifacePcap.Addresses[i].IP) {
								adapter.Id = ifacePcap.Name
								adapter.Description = ifacePcap.Description
								return
							}
						}
					}
					return
				}
			}
		}
	}
	return
}

func ServerAdapter() (adapter *Adapter) {
	gatewayIP := GetGatewayIP()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.IsGlobalUnicast() && v.Contains(gatewayIP) {
					adapter = &Adapter{
						Name: iface.Name,
						Network: &net.IPNet{
							IP:   v.IP.Mask(v.Mask),
							Mask: v.Mask,
						},
						Local: &Endpoint{
							&Address{
								IP:  v.IP.To4(),
								MAC: iface.HardwareAddr,
								Port: &Port{
									Type:   LANServer.GetPort().GetType(),
									Number: LANServer.GetPort().GetNumber(),
								},
							},
						},
						Gateway: &Endpoint{
							&Address{
								IP: gatewayIP,
							},
						},
					}
					return
				}
			}
		}
	}
	return
}

func (d *Adapter) GetNetwork() (network *net.IPNet) {
	return d.Network
}

func (d *Adapter) SetNetwork(network *net.IPNet) {
	d.Network = network
}

func (d *Adapter) GetLocalIP() (ip net.IP) {
	return d.Local.GetIP()
}

func (d *Adapter) SetLocalIP(ip net.IP) {
	if d.Local == nil {
		d.Local = &Endpoint{}
	}
	d.Local.SetIP(ip.To4())
}

func (d *Adapter) GetLocalMAC() (mac net.HardwareAddr) {
	return d.Local.GetMAC()
}

func (d *Adapter) SetLocalMAC(mac net.HardwareAddr) {
	if d.Local == nil {
		d.Local = &Endpoint{}
	}
	d.Local.SetMAC(mac)
}

func (d *Adapter) GetGatewayIP() (ip net.IP) {
	return d.Gateway.GetIP()
}

func (d *Adapter) SetGatewayIP(ip net.IP) {
	if d.Gateway == nil {
		d.Gateway = &Endpoint{}
	}
	d.Gateway.SetIP(ip.To4())
}

func (d *Adapter) GetGatewayMAC() (mac net.HardwareAddr) {
	return d.Gateway.GetMAC()
}

func (d *Adapter) SetGatewayMAC(mac net.HardwareAddr) {
	if d.Gateway == nil {
		d.Gateway = &Endpoint{}
	}
	d.Gateway.SetMAC(mac)
}

func (d *Adapter) GetConsoleIP() (ip net.IP) {
	return d.Console.GetIP()
}

func (d *Adapter) SetConsoleIP(ip net.IP) {
	if d.Console == nil {
		d.Console = &Endpoint{}
	}
	d.Console.SetIP(ip.To4())
}

func (d *Adapter) GetConsoleMAC() (mac net.HardwareAddr) {
	return d.Console.GetMAC()
}

func (d *Adapter) SetConsoleMAC(mac net.HardwareAddr) {
	if d.Console == nil {
		d.Console = &Endpoint{}
	}
	d.Console.SetMAC(mac)
}

package internal

import (
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/google/gopacket/pcap"
)

type Adapter struct {
	Id          string
	Name        string
	Description string
	Local       *Endpoint
	Gateway     *Endpoint
	Console     *Endpoint
}

func GetGatewayIPv4() (ipv4 net.IP) {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "print", "-4")
		out, _ := cmd.CombinedOutput()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.Index(line, "0.0.0.0") == 0 {
				fields := strings.Fields(line)
				ipv4 = net.ParseIP(fields[2]).To4()
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
				ipv4 = net.ParseIP(fields[1]).To4()
				return
			}
		}
	}
	return
}

func LocalAdapter() (adapter *Adapter) {
	gatewayIPv4 := GetGatewayIPv4()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.IsGlobalUnicast() && v.Contains(gatewayIPv4) {
					v.IP = v.IP.To4()
					adapter = &Adapter{
						Name: iface.Name,
						Local: &Endpoint{
							&Address{
								IPNet: v,
								MAC:   iface.HardwareAddr,
							},
						},
						Gateway: &Endpoint{
							&Address{
								IPNet: &net.IPNet{
									IP:   gatewayIPv4,
									Mask: v.Mask,
								},
							},
						},
						Console: &Endpoint{
							&Address{
								IPNet: &net.IPNet{
									Mask: v.Mask,
								},
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
	gatewayIPv4 := GetGatewayIPv4()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.IsGlobalUnicast() && v.Contains(gatewayIPv4) {
					v.IP = v.IP.To4()
					adapter = &Adapter{
						Name: iface.Name,
						Local: &Endpoint{
							&Address{
								IPNet: v,
								MAC:   iface.HardwareAddr,
								Port: &Port{
									Type:   LANServer.GetPort().GetType(),
									Number: LANServer.GetPort().GetNumber(),
								},
							},
						},
						Gateway: &Endpoint{
							&Address{
								IPNet: &net.IPNet{
									IP:   gatewayIPv4,
									Mask: v.Mask,
								},
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

func (a *Adapter) GetLocalIP() (ip net.IP) {
	return a.Local.GetIP()
}

func (a *Adapter) GetLocalMask() (mask net.IPMask) {
	return a.Local.GetMask()
}

func (a *Adapter) GetLocalNetwork() string {
	return a.Local.GetNetwork()
}

func (a *Adapter) GetLocalMAC() (mac net.HardwareAddr) {
	return a.Local.GetMAC()
}

func (a *Adapter) GetGatewayIP() (ip net.IP) {
	return a.Gateway.GetIP()
}

func (a *Adapter) GetGatewayMAC() (mac net.HardwareAddr) {
	return a.Gateway.GetMAC()
}

func (a *Adapter) SetGatewayMAC(mac net.HardwareAddr) {
	if a.Gateway == nil {
		a.Gateway = &Endpoint{}
	}
	a.Gateway.SetMAC(mac)
}

func (a *Adapter) GetConsoleIP() (ip net.IP) {
	return a.Console.GetIP()
}

func (a *Adapter) SetConsoleIP(ip net.IP) {
	if a.Console == nil {
		a.Console = &Endpoint{}
	}
	a.Console.SetIP(ip.To4())
}

func (a *Adapter) GetConsoleMAC() (mac net.HardwareAddr) {
	return a.Console.GetMAC()
}

func (a *Adapter) SetConsoleMAC(mac net.HardwareAddr) {
	if a.Console == nil {
		a.Console = &Endpoint{}
	}
	a.Console.SetMAC(mac)
}

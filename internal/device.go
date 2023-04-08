package internal

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket/pcap"
	"github.com/songgao/water"
)

type Device struct {
	Id          string
	Description string

	handle *pcap.Handle
}

func NewDevice(ip, mask string) (device *Device) {
	// initial TAP interface
	config := water.Config{
		DeviceType: water.TAP,
	}
	iface, err := water.New(config)
	if err != nil {
		logger.Panic("failed to create TAP interface:%v", err)
	}
	// assign IP & Mask address
	cmd := exec.Command(
		"netsh",
		"interface",
		"ipv4",
		"set",
		"address",
		fmt.Sprintf("name=%s", iface.Name()),
		"source=static",
		fmt.Sprintf("address=%s", ip),
		fmt.Sprintf("mask=%s", mask),
		"gateway=192.168.0.106",
	)
	if err := cmd.Run(); err != nil {
		logger.Panic("failed to assign IP address to the interface:%v", err)
	}
	device = &Device{
		Description: "TAP-Windows Adapter V9",
	}
	for _, dev := range GetDevices() {
		if strings.Compare(device.Description, dev.Description) == 0 {
			device.Id = dev.Id
		}
	}
	return
}

func GetDevices() (devices []*Device) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		logger.Panic("failed to get devices:%v", err)
	}
	devices = make([]*Device, 0, 8)
	for _, iface := range interfaces {
		devices = append(devices, &Device{
			Id:          iface.Name,
			Description: iface.Description,
		})
	}
	return
}

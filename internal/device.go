package internal

import (
	"github.com/NanoRed/loin/pkg/logger"
	"github.com/google/gopacket/pcap"
)

type Device struct {
	Name        string
	Description string
}

func AllDevices() (devices []*Device) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		logger.Panic("fail to get devices:%v", err)
	}

	devices = make([]*Device, 0, 8)
	for _, iface := range interfaces {
		devices = append(devices, &Device{
			Name:        iface.Name,
			Description: iface.Description,
		})
	}
	return
}

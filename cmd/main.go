package main

import (
	"fmt"

	"github.com/NanoRed/loin/internal"
)

var (
	SWITCH_IP_ADDRESS = "192.168.0.201"
)

func main() {
	// select network interface
	devs := internal.LocalDevices()
	fmt.Println("Please select a network interface to sniff.")
	for idx, dev := range devs {
		fmt.Printf("[%d] %s\n", idx, dev.Description)
	}
	var id int
	fmt.Print("\nEnter the number:")
	fmt.Scanf("%d", &id)
	fmt.Printf("\nYou have chose \"%s\", now capturing the packets...\n", devs[id].Description)

	// start to capture packets
	dev := devs[id]
	sniffer := internal.NewSniffer(dev)
	defer sniffer.Close()
	// src host 192.168.0.201 (nintendo switch)
	// 20:6b:e7:68:ba:ac (router)
	sniffer.Capture("src host " + SWITCH_IP_ADDRESS).Handle()

	for {
	}
}

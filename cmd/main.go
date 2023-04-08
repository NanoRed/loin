package main

import (
	"fmt"

	"github.com/NanoRed/loin/internal"
)

func main() {
	// select network interface
	devs := internal.GetDevices()
	fmt.Println("Please select a network interface to sniff.")
	for idx, dev := range devs {
		fmt.Printf("[%d] %s\n", idx, dev.Description)
	}
	var id int
	fmt.Print("\nEnter the number:")
	fmt.Scanf("%d", &id)
	fmt.Printf("\nYou have chose \"%s\", now capturing the packets...\n", devs[id].Description)

	// start to capture packets
	sniffer := internal.NewSniffer(devs[id])
	defer sniffer.Close()
	// src host 192.168.0.201 (nintendo switch)
	// 20:6b:e7:68:ba:ac (router)
	sniffer.ReadPackets("src host 192.168.0.106", func(p *internal.Packet) {
		fmt.Println(p)
		// if !p.IsARP() {
		// 	sniffer.WritePackets(p)
		// }
	})

	// device := internal.NewDevice("10.7.0.1", "255.255.255.0")
	// sniffer := internal.NewSniffer(device)
	// defer sniffer.Close()
	// sniffer.HandlePackets("src host 10.7.0.2", func(p *internal.Packet) {
	// 	fmt.Println(p)
	// })

	for {
	}
}

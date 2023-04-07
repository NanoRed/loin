package main

import (
	"fmt"

	"github.com/NanoRed/loin/internal"
)

func main() {
	// select network interface
	devs := internal.AllDevices()
	fmt.Println("Please select a network interface to sniff.")
	for idx, dev := range devs {
		fmt.Printf("[%d] (%s) %s\n", idx, dev.Name, dev.Description)
	}
	var id int
	fmt.Print("\nEnter the number:")
	fmt.Scanf("%d", &id)
	fmt.Printf("\nYou have chose \"%s\", now capturing the packets...\n", devs[id].Description)

	// start to capture packets
	sniffer := internal.NewSniffer(devs[id], "src host 192.168.77.1")
	defer sniffer.Close()
	sniffer.HandlePackets(func(p *internal.Packet) {
		fmt.Println(p)
	})
}

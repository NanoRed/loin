package main

import (
	"fmt"
	"runtime/debug"

	"github.com/NanoRed/loin/internal"
	"github.com/NanoRed/loin/pkg/logger"
)

func main() {
	// debug
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			fmt.Println(string(debug.Stack()))
			for {
			}
		}
	}()

	// select network interface and set the console address
	var adapter *internal.Adapter
	adapters := internal.LocalAdapters()
	count := len(adapters)
	switch {
	case count == 1:
		adapter = adapters[0]
		fmt.Printf("detected your network interface is \"%s\"\nnow please awake your console(nintendo switch)...\n\n", adapter.Description)
	case count > 1:
		fmt.Println("please select a valid network interface:")
		for idx, adapter := range adapters {
			fmt.Printf("[%d] %s\n", idx, adapter.Description)
		}
		fmt.Print("\nenter the number:")
		var id int
		fmt.Scanf("%d", &id)
		adapter = adapters[id]
		fmt.Printf("\nyou have chose \"%s\"\nnow please awake your console(nintendo switch)...\n\n", adapter.Description)
	default:
		logger.Panic("It seems you don't have a valid network interface.")
	}

	// start capturing and dealing with the packets
	sniffer := internal.NewSniffer(adapter)
	defer sniffer.Close()
	sniffer.Run()
}

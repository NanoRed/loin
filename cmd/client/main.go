package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/NanoRed/loin/internal"
	"github.com/NanoRed/loin/pkg/logger"
)

func main() {
	// debug
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			debug.PrintStack()
			for i := 5; i > 0; i-- {
				logger.Pure("Close automatically in %d seconds...", i)
				time.Sleep(time.Second)
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
		logger.Pure("Detected your network interface is \"%s\"", adapter.Description)
		logger.Pure("Please awake your console(nintendo switch) and configure your console:")
		logger.Pure("step 1) go to 'Internet Settings', then choose your network to 'Change Settings'")
		logger.Pure("step 2) change the 'IP Address Settings' to manual and modify it like this:")
		logger.Pure("\t- IP Address: %s(choose a static IP in your LAN)", adapter.GetNetwork())
		logger.Pure("\t- Subnet Mask: %s", net.IP(adapter.GetNetwork().Mask))
		logger.Pure("\t- Gateway: %s", adapter.GetLocalIP())
		logger.Pure("step 3) change the 'DNS Settings' to manual and modify it like this:")
		logger.Pure("\t- Primary DNS: %s", internal.PrimaryDNS.GetIP())
		logger.Pure("\t- Secondary DNS: %s", internal.SecondaryDNS.GetIP())
		logger.Pure("step 4) save the settings and 'Connect to This Network'")
	case count > 1:
		logger.Pure("Please select a valid network interface:")
		for idx, adapter := range adapters {
			logger.Pure("[%d] %s", idx, adapter.Description)
		}
		fmt.Print("Enter the number:")
		var id int
		fmt.Scanf("%d", &id)
		adapter = adapters[id]
		logger.Pure("You have chosen \"%s\"", adapter.Description)
		logger.Pure("Please awake your console(nintendo switch) and configure your console.")
		logger.Pure("step 1) go to 'Internet Settings', then choose your network to 'Change Settings'")
		logger.Pure("step 2) change the 'IP Address Settings' to manual and modify it like this:")
		logger.Pure("\t- IP Address: %s(choose a static IP in your LAN)", adapter.GetNetwork())
		logger.Pure("\t- Subnet Mask: %s", net.IP(adapter.GetNetwork().Mask))
		logger.Pure("\t- Gateway: %s", adapter.GetLocalIP())
		logger.Pure("step 3) change the 'DNS Settings' to manual and modify it like this:")
		logger.Pure("\t- Primary DNS: %s", internal.PrimaryDNS.GetIP())
		logger.Pure("\t- Secondary DNS: %s", internal.SecondaryDNS.GetIP())
		logger.Pure("step 4) save the settings and 'Connect to This Network'")

	default:
		logger.Panic("it seems like you don't have a valid network interface")
	}

	// start to forward the packets
	commander := internal.NewCommander(adapter)
	defer commander.OffDuty()
	commander.OnDuty()

	logger.Pure("It should work now, have fun :) [press 'ctrl+c' to exit]")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	<-sig
}

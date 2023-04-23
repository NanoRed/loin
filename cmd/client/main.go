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
			logger.Pure("Close automatically in 1 minute...")
			time.Sleep(time.Minute)
		}
	}()

	// select network interface and set the console address
	adapter := internal.LocalAdapter()
	if adapter != nil {
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
	} else {
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

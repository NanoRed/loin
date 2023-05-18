package main

import (
	"fmt"
	"runtime/debug"
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

	// start to serve
	logger.Pure("Loin server started")
	adapter := internal.ServerAdapter()
	internal.NewServer(adapter.Local).ListenAndServe()
}

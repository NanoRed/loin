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
			for i := 5; i > 0; i-- {
				logger.Pure("Close automatically in %d seconds...", i)
				time.Sleep(time.Second)
			}
		}
	}()

	// start to serve
	logger.Pure("loin-server started")
	adapter := internal.ServerAdapter()
	internal.NewServer(adapter.Local).ListenAndServe()
}

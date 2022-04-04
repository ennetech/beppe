package main

import (
	"github.com/ennetech/go-common/env"
	"github.com/ennetech/go-common/logz"
	"os"
	"os/signal"
	"sync"
)

func main() {
	logz.DebugOn = env.Get("DEBUG_ENABLED", "false") == "true"

	logz.Info("BEPPE", "Starting...")
	WaitForCtrlC()
}

func WaitForCtrlC() {
	var end_waiter sync.WaitGroup
	end_waiter.Add(1)
	var signal_channel chan os.Signal
	signal_channel = make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	go func() {
		<-signal_channel
		end_waiter.Done()
	}()
	end_waiter.Wait()

	logz.Info("BEPPE", "...bye bye!")
}

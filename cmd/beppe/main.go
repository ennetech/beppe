package main

import (
	"github.com/ennetech/beppe/pkg/acme"
	"github.com/ennetech/beppe/pkg/api"
	"github.com/ennetech/beppe/pkg/cron"
	"github.com/ennetech/beppe/pkg/http"
	"github.com/ennetech/beppe/pkg/storage"
	"github.com/ennetech/go-common/env"
	"github.com/ennetech/go-common/logz"
	"os"
	"os/signal"
	"sync"
)

func main() {
	logz.DebugOn = env.Get("DEBUG_ENABLED", "false") == "true"

	logz.Info("BEPPE", "Starting...")
	storage.Init(env.Get("STORAGE_DRIVER", "vault"))
	acme.Init(env.Get("ACME_SOLVER", "route53"))
	if env.Get("BEPPE_HTTP", "false") == "true" {
		http.Start(env.Get("HTTP_PORT", "8080"))
	}
	if env.Get("BEPPE_API", "false") == "true" {
		api.Start(env.Get("API_PORT", "4367"), env.Get("API_TOKEN", "panini"))
	}
	if env.Get("BEPPE_CRON", "false") == "true" {
		cron.Init()
	}

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

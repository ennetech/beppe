package cron

import (
	"github.com/ennetech/beppe/pkg/acme"
	"github.com/ennetech/beppe/pkg/storage"
	"github.com/ennetech/go-common/logz"
	"strings"
	"time"
)

func Init() {
	logz.Info("CRON", "Starting...")
	checkAll()
	go checkChecks()
}

func checkChecks() {
	for range time.Tick(time.Hour * 24) {
		checkAll()
	}
}

func checkAll() {
	accounts := storage.ListAccounts()
	for _, account := range accounts {
		account = strings.Trim(account, "/")
		if account != "_" {
			certs := storage.ListCertificatesForAccount(account)
			for _, cert := range certs {
				info := storage.GetCertificateInfo(account, cert)
				if !info.Revoked && info.DaysRemaining < 10 {
					// Need renew
					logz.Info("CRON", "RENEWING "+cert)
					acme.RenewCertificate(account, cert)
				} else {
					logz.Info("CRON", cert+"\t NOT DUE TO RENEW OR IS REVOKED")
				}
			}
		}
	}
}

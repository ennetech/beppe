package storage

import (
	"crypto/x509"
	"github.com/ennetech/go-common/logz"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"time"
)

type StorageProvider interface {
	WriteKV(path string, data map[string]interface{}) error
	ReadKV(path string) (map[string]interface{}, error)
	WriteRaw(path string, data []byte) error
	ReadRaw(path string) ([]byte, error)
	Delete(path string) error
	Has(path string) bool
	List(path string) []string
}

var provider StorageProvider

func Init(prv string) {
	logz.Info("STORAGE", "Initializing "+prv+"...")
	switch prv {
	case "vault":
		provider = InitVault()
	}
}

func ListAccounts() []string {
	return provider.List("accounts")
}

func ListAccountsForCertificates() []string {
	return provider.List("certificates")
}

func ListCertificatesForAccount(account string) []string {
	return provider.List("certificates/" + account)
}

type CertificateInfo struct {
	X509          x509.Certificate
	Duration      int
	DaysRemaining int
	Revoked       bool
}

func HasAccount(providerName, email string) bool {
	return provider.Has("accounts/" + providerName + "|" + email)
}

func HasAccountByKey(account string) bool {
	return provider.Has("accounts/" + account)
}

func StoreAccount(providerName, email string, data map[string]interface{}) error {
	return provider.WriteKV("accounts/"+providerName+"|"+email, data)
}

func GetAccountByKey(account string) (map[string]interface{}, error) {
	return provider.ReadKV("accounts/" + account)
}

func HasCertificate(account, domain string) bool {
	return provider.Has("certificates/" + account + "/" + domain)
}

func GetCertificate(account, domain string) (map[string]interface{}, error) {
	return provider.ReadKV("certificates/" + account + "/" + domain)
}

func PutCertificate(account, domain string, data map[string]interface{}) error {
	return provider.WriteKV("certificates/"+account+"/"+domain, data)
}

func PushCertificate(account, domain string) error {
	certData, err := GetCertificate(account, domain)
	if err != nil {
		return err
	}
	return provider.WriteKV("certificates/_/"+domain, map[string]interface{}{
		// Meta
		"_account": account,
		// Under
		"cert": certData["Certificate"].(string),
		"key":  certData["PrivateKey"].(string),
	})
}

func GetAcmeCertificate(account, domain string) certificate.Resource {
	d, _ := provider.ReadKV("certificates/" + account + "/" + domain)
	return certificate.Resource{
		Domain:            d["Domain"].(string),
		CertURL:           d["CertURL"].(string),
		CertStableURL:     d["CertStableURL"].(string),
		PrivateKey:        []byte(d["PrivateKey"].(string)),
		Certificate:       []byte(d["Certificate"].(string)),
		IssuerCertificate: []byte(d["IssuerCertificate"].(string)),
		CSR:               []byte(d["CSR"].(string)),
	}
}

func PutAcmeCertificate(account, domain string, crt certificate.Resource) {
	// Debug why not
	// os.WriteFile("./"+account+domain+".pem", crt.Certificate, 0644)

	PutCertificate(account, domain, map[string]interface{}{
		"_revoked":          "false",
		"Domain":            crt.Domain,
		"CertURL":           crt.CertURL,
		"CertStableURL":     crt.CertStableURL,
		"Certificate":       string(crt.Certificate),
		"CSR":               string(crt.CSR),
		"PrivateKey":        string(crt.PrivateKey),
		"IssuerCertificate": string(crt.IssuerCertificate),
	})

	// TODO: Check if it's needed to push it
	PushCertificate(account, domain)
}

func GetCertificateInfo(account, domain string) CertificateInfo {
	c := GetAcmeCertificate(account, domain)
	cc, _ := certcrypto.ParsePEMBundle(c.Certificate)
	r := false
	d, _ := provider.ReadKV("certificates/" + account + "/" + domain)
	v, ok := d["_revoked"]
	if ok {
		r = (v == "true")
	}

	return CertificateInfo{
		X509:          *cc[0],
		Duration:      int(cc[0].NotAfter.Sub(cc[0].NotBefore).Hours() / 24.0),
		DaysRemaining: int(time.Until(cc[0].NotAfter).Hours() / 24.0),
		Revoked:       r,
	}
}

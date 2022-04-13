package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/ennetech/beppe/pkg/storage"
	"github.com/ennetech/go-common/logz"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func providerMap(p string) string {
	providers := map[string]string{
		"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
		"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
		"zero-ssl":            "https://acme.zerossl.com/v2/DV90",
		// https://github.com/acmesh-official/acme.sh/blob/master/acme.sh
		"buypass":         "https://api.buypass.com/acme/directory",
		"buypass-staging": "https://api.test4.buypass.no/acme/directory",
		"ssl-com":         "https://acme.ssl.com/sslcom-dv-rsa",
		"ssl-com-ecc":     "https://acme.ssl.com/sslcom-dv-ecc",
		"google-ca":       "https://dv.acme-v02.api.pki.goog/directory",
		"google-ca-test":  "https://dv.acme-v02.test-api.pki.goog/directory",
	}

	return providers[p]
}

var Solver string

func Init(solver string) {
	Solver = solver
}

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}
func (u AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go
func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}

func RegisterAccount(email, provider, kid, hmac string) (string, error) {
	// Sanity check
	if email == "" {
		return "", errors.New("an email must be provided")
	}
	// ZeroSSL auto magic
	if provider == "zero-ssl" && kid == "" && hmac == "" {
		newAccountURL := "http://api.zerossl.com/acme/eab-credentials-email"
		data := struct {
			Success bool   `json:"success"`
			KID     string `json:"eab_kid"`
			HMAC    string `json:"eab_hmac_key"`
		}{}

		resp, err := http.PostForm(newAccountURL, url.Values{"email": {email}})
		if err != nil {
			return "zero-ssl-create", err
		}
		err = json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			return "zero-ssl-decode", err
		}
		resp.Body.Close()

		kid = data.KID
		hmac = data.HMAC
	}
	// Duplicate check
	if storage.HasAccount(provider, email) {
		return "", errors.New("account already present")
	}

	logz.Info("ACME-REQUEST", provider+" "+kid+" "+hmac)
	// Initialize acme
	accountInfo := map[string]interface{}{
		"email": email,
	}

	privateKey, errK := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	logz.Die(errK, "ACME", "Generated new private key")
	pr, pb := encode(privateKey, &privateKey.PublicKey)
	accountInfo["public"] = pb
	accountInfo["private"] = pr

	acmeUser := AcmeUser{
		Email: email,
		key:   privateKey,
	}
	config := lego.NewConfig(&acmeUser)
	config.CADirURL = providerMap(provider)
	config.Certificate.KeyType = certcrypto.RSA2048
	acmeClient, errC := lego.NewClient(config)
	logz.Die(errC, "ACME-CLIENT", "client created")

	// Request registration
	var reg *registration.Resource
	var err error
	if kid != "" && hmac != "" {
		reg, err = acmeClient.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			Kid:                  kid,
			HmacEncoded:          hmac,
			TermsOfServiceAgreed: true,
		})
	} else {
		reg, err = acmeClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}

	b, _ := json.Marshal(reg)
	accountInfo["registration"] = string(b)

	if err == nil {
		err = storage.StoreAccount(provider, email, accountInfo)
	}

	if err != nil {
		return "registration-error", err
	} else {
		return "registered", nil
	}
}

func getClientForAccount(account string) (*lego.Client, error) {
	if !storage.HasAccountByKey(account) {
		return nil, errors.New("account not found")
	}

	sp := strings.Split(account, "|")
	provider := sp[0]

	accountData, _ := storage.GetAccountByKey(account)

	accountRawRestore := provider == "google-ca"

	priv, _ := decode(accountData["private"].(string), accountData["public"].(string))
	acmeUser := AcmeUser{
		Email: accountData["email"].(string),
		key:   priv,
	}
	if accountRawRestore {
		r := &registration.Resource{}
		d := []byte(accountData["registration"].(string))
		json.Unmarshal(d, r)
		acmeUser.Registration = r
	}
	config := lego.NewConfig(&acmeUser)
	config.CADirURL = providerMap(provider)
	if config.CADirURL == "https://acme.ssl.com/sslcom-dv-ecc" {
		config.Certificate.KeyType = certcrypto.EC256
	} else {
		config.Certificate.KeyType = certcrypto.RSA2048
	}
	acmeClient, errc := lego.NewClient(config)
	if errc != nil {
		return nil, errc
	}
	if !accountRawRestore {
		var err error
		var r *registration.Resource
		r, err = acmeClient.Registration.ResolveAccountByKey()
		logz.Die(err, "ACME", "ResolveAccountByKey")
		acmeUser.Registration = r
		//_, err = acmeClient.Registration.QueryRegistration()
		//logz.Die(err, "ACME", "QueryRegistration")
	}

	if Solver == "http" {
		//err = acmeClient.Challenge.SetHTTP01Provider(&KVProvider{})
		//logz.Die(err, "ACME", "HTTP01 setup")
	} else {
		dnsProvider, _ := dns.NewDNSChallengeProviderByName(Solver)
		acmeClient.Challenge.SetDNS01Provider(
			dnsProvider,
			dns01.AddDNSTimeout(60*time.Second),
		)
	}
	return acmeClient, nil
}

func RequestCertificate(account, domain string) error {
	if storage.HasCertificate(account, domain) {
		return errors.New("certificate already present")
	}

	acmeClient, err := getClientForAccount(account)
	if err != nil {
		return err
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := acmeClient.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	storage.PutAcmeCertificate(account, domain, *certificates)

	return nil
}

func PushCertificate(account, domain string) error {
	return storage.PushCertificate(account, domain)
}

func RevokeCertificate(account, domain string) error {
	certData, err := storage.GetCertificate(account, domain)
	if err != nil {
		return err
	}

	if certData["_revoked"] == "true" {
		return errors.New("certificate already revoked")
	}

	acmeClient, err := getClientForAccount(account)
	if err != nil {
		return err
	}

	err = acmeClient.Certificate.Revoke([]byte(certData["Certificate"].(string)))
	if err != nil {
		return err
	}

	certData["_revoked"] = "true"
	return storage.PutCertificate(account, domain, certData)
}

func RenewCertificate(account, domain string) error {
	data := storage.GetCertificateInfo(account, domain)
	if !data.Revoked && data.DaysRemaining > 10 {
		return errors.New("Certificate has still " + strconv.Itoa(data.DaysRemaining) + " days left")
	}

	acmeClient, err := getClientForAccount(account)
	if err != nil {
		return err
	}

	crt := storage.GetAcmeCertificate(account, domain)
	certificates, err := acmeClient.Certificate.Renew(crt, true, true, "")
	if err != nil {
		return err
	}
	storage.PutAcmeCertificate(account, domain, *certificates)
	return nil
}

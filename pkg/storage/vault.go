package storage

import (
	"errors"
	"github.com/ennetech/go-common/env"
	vault "github.com/hashicorp/vault/api"
	"net/http"
	"time"
)

type VaultProvider struct {
	vault    *vault.Client
	basepath string
}

func (v VaultProvider) WriteRaw(path string, data []byte) error {
	return v.WriteKV(path, map[string]interface{}{
		"raw": string(data),
	})
}

func (v VaultProvider) ReadRaw(path string) ([]byte, error) {
	d, err := v.ReadKV(path)
	if err != nil {
		return nil, err
	}

	dt := d["data"].(map[string]interface{})

	return []byte(dt["raw"].(string)), nil
}

func (v VaultProvider) List(path string) []string {
	var r []string
	d, e := v.vault.Logical().List(v.basepath + path)
	if e == nil && d != nil && d.Data != nil {
		kk := d.Data["keys"]
		for _, element := range kk.([]interface{}) {
			r = append(r, element.(string))
		}
	}
	return r
}

func (v VaultProvider) Has(path string) bool {
	_, err := v.ReadKV(path)
	return err == nil
}

func (v VaultProvider) WriteKV(path string, data map[string]interface{}) error {
	_, err := v.vault.Logical().Write(v.basepath+path, data)
	return err
}

func (v VaultProvider) ReadKV(path string) (map[string]interface{}, error) {
	data, err := v.vault.Logical().Read(v.basepath + path)
	if err == nil && data != nil {
		return data.Data, err
	}
	if err == nil {
		err = errors.New("not-found")
	}
	return nil, err
}

func (v VaultProvider) Delete(path string) error {
	_, err := v.vault.Logical().Delete(v.basepath + path)
	return err
}

// https://github.com/hashicorp/vault-examples/blob/main/examples/_quick-start/go/example.go
// https://dev.to/ankitmalikg/working-with-vault-and-golang-395m
func InitVault() StorageProvider {
	vaultAddr := env.Get("VAULT_ADDR")
	token := env.Get("VAULT_TOKEN")
	var httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	client, err := vault.NewClient(&vault.Config{Address: vaultAddr, HttpClient: httpClient})
	client.SetToken(token)
	if err != nil {
		panic(err)
	}

	return &VaultProvider{
		vault:    client,
		basepath: env.Get("VAULT_PATH", "secret/acme/"),
	}
}

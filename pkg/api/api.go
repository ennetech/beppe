package api

import (
	"embed"
	"errors"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ennetech/beppe/pkg/acme"
	"github.com/ennetech/beppe/pkg/storage"
	"github.com/ennetech/go-common/logz"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
)

//go:embed ui/*
var ui embed.FS

type HandlerX struct {
	ApiHandler http.Handler
	UiHandler  http.Handler
}

func (h HandlerX) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, "/api") {
		h.ApiHandler.ServeHTTP(writer, request)
	} else {
		h.UiHandler.ServeHTTP(writer, request)
	}
}

func Start(port, token string) {
	logz.Info("API", "Starting on port "+port+"...")
	ui, _ := fs.Sub(ui, "ui")
	uiHandler := http.FileServer(http.FS(ui))
	go http.ListenAndServe(":"+port, &HandlerX{
		ApiHandler: apiHandler(token),
		UiHandler:  uiHandler,
	})
}

type BearerTokenMiddleware struct {
	Token string
}

func (mw *BearerTokenMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {
	return func(writer rest.ResponseWriter, request *rest.Request) {
		if request.Header.Get("Authorization") != "Bearer "+mw.Token {
			writer.WriteHeader(403)
			m := make(map[string]interface{})
			m["response"] = "unauthorized"
			writer.WriteJson(m)
			return
		}
		handler(writer, request)
	}
}

type ApiResponse struct {
	Response string
}

func apiHandler(authToken string) http.Handler {
	api := rest.NewApi()

	api.Use(&rest.CorsMiddleware{
		RejectNonCorsRequests: false,
		OriginValidator: func(origin string, request *rest.Request) bool {
			return true
		},
		AllowedMethods:                []string{"GET", "POST", "DELETE", "PATCH"},
		AllowedHeaders:                []string{"Authorization", "Content-Type"},
		AccessControlAllowCredentials: true,
		AccessControlMaxAge:           3600,
	})
	api.Use(&BearerTokenMiddleware{
		Token: authToken,
	})

	router, _ := rest.MakeRouter(
		rest.Get("/api/info", func(w rest.ResponseWriter, req *rest.Request) {
			m := make(map[string]interface{})
			m["beppe_version"] = "0.0.0"
			w.WriteJson(m)
		}),

		rest.Get("/api/certificates", func(w rest.ResponseWriter, req *rest.Request) {
			type Certificate struct {
				Account string
				Domain  string
				Issuer  string
				Expiry  string
				Status  string
			}

			resp := []Certificate{}

			accounts := storage.ListAccountsForCertificates()
			for _, account := range accounts {
				account = strings.Trim(account, "/")
				if account != "_" {
					certs := storage.ListCertificatesForAccount(account)
					for _, cert := range certs {
						certInfo := storage.GetCertificateInfo(account, cert)

						status := "revoked="
						if certInfo.Revoked {
							status += "true"
						} else {
							status += "false"
						}

						status += " expire_in=" + strconv.Itoa(certInfo.DaysRemaining) + "d"
						status += " duration=" + strconv.Itoa(certInfo.Duration) + "d"

						resp = append(resp, Certificate{
							Account: account,
							Domain:  cert,
							Issuer:  certInfo.X509.Issuer.CommonName,
							Expiry:  certInfo.X509.NotAfter.UTC().Format("2006-01-02 15:04:05"),
							Status:  status,
						})
					}
				}
			}

			w.WriteJson(resp)
		}),

		rest.Get("/api/accounts", func(w rest.ResponseWriter, req *rest.Request) {
			type Account struct {
				Key      string
				Email    string
				Provider string
			}

			items := storage.ListAccounts()

			resp := []Account{}

			for _, account := range items {
				s := strings.Split(account, "|")
				resp = append(resp, Account{
					Key:      account,
					Provider: s[0],
					Email:    s[1],
				})
			}

			w.WriteJson(resp)
		}),

		rest.Post("/api/accounts", func(w rest.ResponseWriter, req *rest.Request) {
			type AccountRequest struct {
				Email     string
				Provider  string
				Kid       string
				Hmac      string
				Operation string
			}
			createRequest := AccountRequest{}
			req.DecodeJsonPayload(&createRequest)

			var err error
			var res string
			switch createRequest.Operation {
			case "register":
				res, err = acme.RegisterAccount(createRequest.Email, createRequest.Provider, createRequest.Kid, createRequest.Hmac)
			case "delete":
				err = errors.New("you can delete the account using the storage")
			default:
				err = errors.New(createRequest.Operation + " is not supported")
			}

			if err != nil {
				w.WriteHeader(500)
				w.WriteJson(&ApiResponse{
					Response: res + err.Error(),
				})
			} else {
				w.WriteJson(&ApiResponse{
					Response: res,
				})
			}
		}),

		rest.Post("/api/certificates", func(w rest.ResponseWriter, req *rest.Request) {
			type CertificateRequest struct {
				Account   string
				Domain    string
				Operation string
			}
			createRequest := CertificateRequest{}
			req.DecodeJsonPayload(&createRequest)
			var err error
			switch createRequest.Operation {
			case "create":
				err = acme.RequestCertificate(createRequest.Account, createRequest.Domain)
			case "push":
				err = acme.PushCertificate(createRequest.Account, createRequest.Domain)
			case "revoke":
				err = acme.RevokeCertificate(createRequest.Account, createRequest.Domain)
			case "renew":
				err = acme.RenewCertificate(createRequest.Account, createRequest.Domain)
			case "delete":
				err = errors.New("you can delete the certificates using the storage")
			default:
				err = errors.New(createRequest.Operation + " is not supported")
			}

			if err != nil {
				w.WriteHeader(500)
				w.WriteJson(&ApiResponse{
					Response: err.Error(),
				})
			} else {
				w.WriteJson(&ApiResponse{
					Response: createRequest.Operation + ": " + createRequest.Account + "-" + createRequest.Domain,
				})
			}
		}),
	)

	api.SetApp(router)
	return api.MakeHandler()
}

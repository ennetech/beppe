package http

import (
	"github.com/ennetech/go-common/logz"
	"net/http"
)

type HttpHandler struct {
}

func (h HttpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// Respond to all with a 301 redirect
	http.Redirect(writer, request, "https://"+request.Host+request.RequestURI, 301)
}

func Start(port string) {
	logz.Info("HTTP", "Starting on port "+port+"...")
	go http.ListenAndServe(":"+port, &HttpHandler{})
}

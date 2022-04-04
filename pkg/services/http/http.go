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

func Start() {
	logz.Info("HTTP", "Starting...")
	go http.ListenAndServe(":8080", &HttpHandler{})
}

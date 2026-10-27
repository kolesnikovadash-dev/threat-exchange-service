package server

import (
	"net/http"

	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/httputil"
)

type Config struct {
	GetByMD5 http.HandlerFunc
	Create   http.HandlerFunc
	Update   http.HandlerFunc
}

func New(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		httputil.WriteOK(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /info/{md5}", cfg.GetByMD5)
	mux.HandleFunc("POST /info", cfg.Create)
	mux.HandleFunc("PUT /info/{md5}", cfg.Update)
	return mux
}

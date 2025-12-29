package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/LdDl/esia-potato/httpapi"
)

func main() {
	var host string
	var port int
	flag.StringVar(&host, "host", "0.0.0.0", "HTTP server host")
	flag.IntVar(&port, "port", 8080, "HTTP server port")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/extract", httpapi.HandleExtract)
	mux.HandleFunc("/api/v1/sign", httpapi.HandleSign)
	mux.HandleFunc("/health", httpapi.HandleHealth)
	mux.HandleFunc("/docs", httpapi.HandleDocsUI)
	mux.HandleFunc("/docs/swagger.json", httpapi.HandleDocsJSON)

	addr := fmt.Sprintf("%s:%d", host, port)
	slog.Info("starting server", "host", host, "port", port)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

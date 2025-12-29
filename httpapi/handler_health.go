// Package httpapi provides HTTP handlers for CryptoPro key extraction and signing.
package httpapi

import (
	"net/http"
)

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

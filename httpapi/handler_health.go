// Package httpapi provides HTTP handlers for CryptoPro key extraction and signing.
package httpapi

import (
	"net/http"
)

// HandleHealth Health check endpoint
// @Summary Health check
// @Description Returns service health status
// @Tags Health
// @Produce json
// @Success 200 {object} httpapi.HealthResponse
// @Router /health [GET]
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

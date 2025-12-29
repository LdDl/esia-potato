package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ExtractResponse is the JSON response for /api/v1/extract
type ExtractResponse struct {
	PrivateKeyHex     string `json:"private_key_hex"`
	PublicKeyHex      string `json:"public_key_hex"`
	Fingerprint       string `json:"fingerprint"`
	CurveOID          string `json:"curve_oid"`
	CertificateBase64 string `json:"certificate_base64,omitempty"`
}

// SignRequest is the JSON request for /api/v1/sign
type SignRequest struct {
	PrivateKeyHex  string `json:"private_key_hex"`
	CertificateB64 string `json:"certificate_base64"`
	Message        string `json:"message"`
}

// SignResponse is the JSON response for /api/v1/sign
type SignResponse struct {
	SignatureB64 string `json:"signature_base64"`
}

// ErrorResponse is the JSON error response
type ErrorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	slog.Error("request error", "status", status, "message", message)
	writeJSON(w, status, ErrorResponse{Error: message})
}

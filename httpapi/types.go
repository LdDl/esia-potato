package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ExtractResponse is the JSON response for /api/v1/extract
// swagger:model
type ExtractResponse struct {
	// Private key in hexadecimal format
	PrivateKeyHex string `json:"private_key_hex" example:"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"`
	// Public key in hexadecimal format
	PublicKeyHex string `json:"public_key_hex" example:"e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"`
	// Key fingerprint
	Fingerprint string `json:"fingerprint" example:"0123456789abcdef"`
	// Elliptic curve OID
	CurveOID string `json:"curve_oid" example:"1.2.643.2.2.36.0"`
	// Certificate in base64 format (if found in container)
	CertificateBase64 string `json:"certificate_base64,omitempty" example:"MIIBkTCB..."`
}

// SignRequest is the JSON request for /api/v1/sign
// swagger:model
type SignRequest struct {
	// Private key in hexadecimal format
	PrivateKeyHex string `json:"private_key_hex" example:"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"`
	// Certificate in base64 format
	CertificateB64 string `json:"certificate_base64" example:"MIIBkTCB..."`
	// Message to sign
	Message string `json:"message" example:"openid2025.01.01 12:00:00 +0000CLIENT_ID12345"`
}

// SignResponse is the JSON response for /api/v1/sign
// swagger:model
type SignResponse struct {
	// Signature in base64 format (CMS/PKCS#7 SignedData)
	SignatureB64 string `json:"signature_base64" example:"MIIBygYJKoZIhvcNAQc..."`
}

// ErrorResponse is the JSON error response
// swagger:model
type ErrorResponse struct {
	// Error message
	Error string `json:"error" example:"failed to extract key: invalid PIN"`
}

// HealthResponse is the JSON response for /health
// swagger:model
type HealthResponse struct {
	// Service status
	Status string `json:"status" example:"ok"`
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

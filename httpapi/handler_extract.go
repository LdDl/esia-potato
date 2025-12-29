// Package httpapi provides HTTP handlers for CryptoPro key extraction and signing.
package httpapi

import (
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/LdDl/esia-potato/cryptopro"
)

const maxUploadSize = 10 << 20 // 10 MB

// HandleExtract Extract key from CryptoPro container
// @Summary Extract key from CryptoPro container
// @Description Extracts private key, public key and certificate from uploaded CryptoPro container archive
// @Tags Key Extraction
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "Container archive (.zip or .tar.gz)"
// @Param pin formData string false "Container PIN code"
// @Success 200 {object} httpapi.ExtractResponse
// @Failure 400 {object} httpapi.ErrorResponse
// @Failure 405 {object} httpapi.ErrorResponse
// @Failure 500 {object} httpapi.ErrorResponse
// @Router /api/v1/extract [POST]
func HandleExtract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Limit request size
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse form: "+err.Error())
		return
	}

	// Get PIN
	pin := r.FormValue("pin")

	// Get file
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to get file: "+err.Error())
		return
	}
	defer file.Close()

	slog.Info("received extract request",
		"filename", header.Filename,
		"size", header.Size,
	)

	// Create temp directory for extraction
	tempDir, err := os.MkdirTemp("", "cryptopro-extract-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create temp dir")
		return
	}
	defer os.RemoveAll(tempDir)

	// Detect archive type and extract
	containerPath, err := extractArchive(file, header.Filename, tempDir)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to extract archive: "+err.Error())
		return
	}

	// Open container
	container, err := cryptopro.OpenContainer(containerPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to open container: "+err.Error())
		return
	}

	// Extract key
	keyData, err := container.ExtractKey(pin)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to extract key: "+err.Error())
		return
	}

	slog.Info("key extracted successfully",
		"curve_oid", keyData.CurveOID,
		"fingerprint", hex.EncodeToString(keyData.Fingerprint),
	)

	resp := ExtractResponse{
		PrivateKeyHex: hex.EncodeToString(keyData.PrivateKey),
		PublicKeyHex:  hex.EncodeToString(keyData.PublicKey),
		Fingerprint:   hex.EncodeToString(keyData.Fingerprint),
		CurveOID:      keyData.CurveOID,
	}

	// Try to find and read certificate
	certPath := filepath.Join(containerPath, "certificate.cer")
	if certData, err := os.ReadFile(certPath); err == nil {
		resp.CertificateBase64 = base64.StdEncoding.EncodeToString(certData)
		slog.Info("certificate found", "path", "certificate.cer")
	} else {
		slog.Warn("certificate not found", "path", certPath)
	}

	writeJSON(w, http.StatusOK, resp)
}

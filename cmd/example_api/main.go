package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

const (
	// HTTP API server address
	APIServer = "http://localhost:8080"

	// ESIA test environment
	ESIATest = "https://esia-portal1.test.gosuslugi.ru"

	// Container settings
	containerPath = "test_container"
	containerPIN  = "your pin code"

	// ESIA oAuth settings
	clientID    = "775607_DP"
	redirectURI = "https://ya.ru"
	scope       = "openid"

	tmLayout = "2006.01.02 15:04:05 -0700"
)

// ExtractResponse matches /api/v1/extract response
type ExtractResponse struct {
	PrivateKeyHex     string `json:"private_key_hex"`
	PublicKeyHex      string `json:"public_key_hex"`
	Fingerprint       string `json:"fingerprint"`
	CurveOID          string `json:"curve_oid"`
	CertificateBase64 string `json:"certificate_base64"`
}

// SignRequest matches /api/v1/sign request
type SignRequest struct {
	PrivateKeyHex  string `json:"private_key_hex"`
	CertificateB64 string `json:"certificate_base64"`
	Message        string `json:"message"`
}

// SignResponse matches /api/v1/sign response
type SignResponse struct {
	SignatureB64 string `json:"signature_base64"`
}

// ErrorResponse matches error response
type ErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Step 1: Extract key from container via API
	slog.Info("extracting key from container via API", "path", containerPath)
	extractResp, err := extractKey(containerPath, containerPIN)
	if err != nil {
		slog.Error("failed to extract key", "error", err)
		os.Exit(1)
	}
	slog.Info("key extracted successfully",
		"fingerprint", extractResp.Fingerprint,
		"curve_oid", extractResp.CurveOID,
		"has_certificate", extractResp.CertificateBase64 != "",
	)

	// Step 2: Prepare ESIA message
	state := uuid.New().String()
	timestamp := time.Now().UTC().Format(tmLayout)
	message := scope + timestamp + clientID + state
	slog.Info("message prepared", "message", message)

	// Step 3: Sign message via API
	slog.Info("signing message via API")
	signResp, err := signMessage(extractResp.PrivateKeyHex, extractResp.CertificateBase64, message)
	if err != nil {
		slog.Error("failed to sign message", "error", err)
		os.Exit(1)
	}
	slog.Info("message signed", "signature_base64_len", len(signResp.SignatureB64))

	// Step 4: Convert signature to URL-safe base64
	// API returns standard base64, ESIA needs URL-safe base64
	sigBytes, err := base64.StdEncoding.DecodeString(signResp.SignatureB64)
	if err != nil {
		slog.Error("failed to decode signature", "error", err)
		os.Exit(1)
	}
	clientSecret := base64.URLEncoding.EncodeToString(sigBytes)

	// Step 5: Prepare authorization URL
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("client_secret", clientSecret)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("response_type", "code")
	params.Set("state", state)
	params.Set("timestamp", timestamp)
	params.Set("access_type", "offline")

	authURL := ESIATest + "/aas/oauth2/ac?" + params.Encode()
	slog.Info("authorization URL prepared", "url", authURL)

	// Step 6: Test against ESIA
	slog.Info("testing against ESIA")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(authURL)
	if err != nil {
		slog.Error("request failed", "error", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	slog.Info("response received",
		"status", resp.Status,
		"location", loc,
	)

	if loc == "/login" || loc == ESIATest+"/login" {
		slog.Info("signature accepted by ESIA")
	}
}

// extractKey calls /api/v1/extract to extract key from container
func extractKey(containerPath, pin string) (*ExtractResponse, error) {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add PIN field
	if err := writer.WriteField("pin", pin); err != nil {
		return nil, fmt.Errorf("failed to write pin field: %w", err)
	}

	// Create tar.gz of container directory
	tarData, err := createTarGz(containerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tar.gz: %w", err)
	}

	// Add file field
	part, err := writer.CreateFormFile("file", "container.tar.gz")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := part.Write(tarData); err != nil {
		return nil, fmt.Errorf("failed to write file data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	resp, err := http.Post(
		APIServer+"/api/v1/extract",
		writer.FormDataContentType(),
		&buf,
	)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			return nil, fmt.Errorf("API error: %s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result ExtractResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// signMessage calls /api/v1/sign to sign a message
func signMessage(privateKeyHex, certificateB64, message string) (*SignResponse, error) {
	reqBody := SignRequest{
		PrivateKeyHex:  privateKeyHex,
		CertificateB64: certificateB64,
		Message:        message,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	resp, err := http.Post(
		APIServer+"/api/v1/sign",
		"application/json",
		bytes.NewReader(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			return nil, fmt.Errorf("API error: %s", errResp.Error)
		}
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var result SignResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// createTarGz creates a tar.gz archive from a directory
func createTarGz(dir string) ([]byte, error) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(filepath.Dir(dir), path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Write to tar
		header := &tar.Header{
			Name: relPath,
			Mode: 0644,
			Size: int64(len(data)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(data); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gzWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

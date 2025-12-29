package main

import (
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/LdDl/esia-potato/cms"
	"github.com/ddulesov/gogost/gost3410"
	"github.com/google/uuid"
)

const (
	ESIATest = "https://esia-portal1.test.gosuslugi.ru"
	certPath = "test_container/certificate.cer"

	clientID    = "775607_DP"
	redirectURI = "https://ya.ru"
	scope       = "openid"

	tmLayout = "2006.01.02 15:04:05 -0700"

	// Aquire hex via `cryptopro_extract` CLI first
	keyHex = "YOUR_PRIVATE_KEY_HEX_HERE"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		slog.Error("failed to decode key", "error", err)
		os.Exit(1)
	}

	curve := gost3410.CurveIdGostR34102001CryptoProAParamSet()
	prv, err := gost3410.NewPrivateKey(curve, gost3410.Mode2001, keyBytes)
	if err != nil {
		slog.Error("failed to create private key", "error", err)
		os.Exit(1)
	}

	// Load certificate
	certDER, err := os.ReadFile(certPath)
	if err != nil {
		slog.Error("failed to read certificate", "error", err)
		os.Exit(1)
	}

	// Create signer
	signer, err := cms.NewSigner(prv, certDER)
	if err != nil {
		slog.Error("failed to create signer", "error", err)
		os.Exit(1)
	}

	// extra oAuth parameters
	state := uuid.New().String()
	timestamp := time.Now().UTC().Format(tmLayout)

	// Message to sign: scope + timestamp + clientID + state
	message := scope + timestamp + clientID + state
	slog.Info("message prepared", "message", message)

	// Sign
	cmsDER, err := signer.Sign([]byte(message))
	if err != nil {
		slog.Error("failed to sign", "error", err)
		os.Exit(1)
	}

	// URL-safe Base64
	clientSecret := base64.URLEncoding.EncodeToString(cmsDER)
	slog.Info("signature created",
		"signature_bytes", len(cmsDER),
		"base64_chars", len(clientSecret),
	)

	// prepare authorization URL
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

	// prepare and execute request
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

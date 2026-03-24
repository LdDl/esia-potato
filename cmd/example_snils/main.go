package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/LdDl/esia-potato/cms"
	"github.com/ddulesov/gogost/gost3410"
	"github.com/google/uuid"
)

const (
	ESIATest = "https://esia-portal1.test.gosuslugi.ru"
	certPath = "test_container/certificate.cer"

	clientID    = "775607_DP"
	redirectURI = "http://localhost:8765/callback"
	scope       = "openid snils"

	tmLayout = "2006.01.02 15:04:05 -0700"

	// Acquire hex via `cryptopro_extract` CLI first
	keyHex = "your_private_key_hex_here"
)

// TokenResponse from /aas/oauth2/te
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	State       string `json:"state"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// SnilsInfo from /rs/prns/{oid}/snils
type SnilsInfo struct {
	Snils string `json:"snils"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Step 1: Prepare signer from private key and certificate
	slog.Info("preparing signer", "cert", certPath)
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
	certDER, err := os.ReadFile(certPath)
	if err != nil {
		slog.Error("failed to read certificate", "error", err)
		os.Exit(1)
	}
	signer, err := cms.NewSigner(prv, certDER)
	if err != nil {
		slog.Error("failed to create signer", "error", err)
		os.Exit(1)
	}
	slog.Info("signer ready")

	// Step 2: Prepare ESIA message and sign it
	state := uuid.New().String()
	timestamp := time.Now().UTC().Format(tmLayout)
	message := scope + timestamp + clientID + state
	slog.Info("message prepared", "message", message)

	cmsDER, err := signer.Sign([]byte(message))
	if err != nil {
		slog.Error("failed to sign", "error", err)
		os.Exit(1)
	}
	clientSecret := base64.URLEncoding.EncodeToString(cmsDER)
	slog.Info("message signed", "signature_bytes", len(cmsDER))

	// Step 3: Build authorization URL
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

	// Step 4: Wait for ESIA callback with authorization code
	slog.Info("waiting for callback", "addr", redirectURI)
	authCode, callbackState, err := waitForCallback(":8765", 5*time.Minute)
	if err != nil {
		slog.Error("failed to receive callback", "error", err)
		os.Exit(1)
	}
	if callbackState != state {
		slog.Error("state mismatch", "expected", state, "got", callbackState)
		os.Exit(1)
	}
	slog.Info("authorization code received", "code", authCode)

	// Step 5: Exchange authorization code for access token
	slog.Info("exchanging code for access token")
	accessToken, err := exchangeCodeForToken(signer, authCode, state)
	if err != nil {
		slog.Error("failed to exchange code", "error", err)
		os.Exit(1)
	}
	slog.Info("access token received", "token_length", len(accessToken))

	// Step 6: Extract subject OID from JWT
	oid, err := extractOIDFromToken(accessToken)
	if err != nil {
		slog.Error("failed to extract OID", "error", err)
		os.Exit(1)
	}
	slog.Info("subject OID extracted", "oid", oid)

	// Step 7: Fetch person info (SNILS) from ESIA REST API
	slog.Info("fetching person info", "oid", oid)
	snilsInfo, err := fetchSnils(accessToken, oid)
	if err != nil {
		slog.Error("failed to fetch SNILS", "error", err)
		os.Exit(1)
	}
	slog.Info("SNILS received",
		"oid", oid,
		"snils", snilsInfo.Snils,
	)
}

// waitForCallback starts an HTTP server and waits for ESIA to redirect back with code.
func waitForCallback(addr string, timeout time.Duration) (code, state string, err error) {
	codeCh := make(chan [2]string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		c := r.URL.Query().Get("code")
		s := r.URL.Query().Get("state")
		if c == "" {
			errMsg := r.URL.Query().Get("error")
			errDesc := r.URL.Query().Get("error_description")
			http.Error(w, "ESIA error: "+errMsg, http.StatusBadRequest)
			errCh <- fmt.Errorf("ESIA returned error: %s (%s)", errMsg, errDesc)
			return
		}
		fmt.Fprintln(w, "Код авторизации получен. Можно закрыть эту страницу.")
		codeCh <- [2]string{c, s}
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", "", fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		if serveErr := srv.Serve(ln); serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
	}()

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	select {
	case pair := <-codeCh:
		return pair[0], pair[1], nil
	case e := <-errCh:
		return "", "", e
	case <-time.After(timeout):
		return "", "", fmt.Errorf("timeout waiting for callback (%v)", timeout)
	}
}

// exchangeCodeForToken exchanges the authorization code for an access token.
// A NEW signature is required for this request.
func exchangeCodeForToken(signer *cms.Signer, code, state string) (string, error) {
	timestamp := time.Now().UTC().Format(tmLayout)
	message := scope + timestamp + clientID + state

	cmsDER, err := signer.Sign([]byte(message))
	if err != nil {
		return "", fmt.Errorf("failed to sign token request: %w", err)
	}
	clientSecret := base64.URLEncoding.EncodeToString(cmsDER)

	data := url.Values{
		"client_id":     {clientID},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"client_secret": {clientSecret},
		"state":         {state},
		"redirect_uri":  {redirectURI},
		"scope":         {scope},
		"timestamp":     {timestamp},
		"token_type":    {"Bearer"},
	}

	resp, err := http.PostForm(ESIATest+"/aas/oauth2/te", data)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// extractOIDFromToken decodes the JWT payload and extracts the subject OID.
func extractOIDFromToken(accessToken string) (string, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	slog.Info("JWT claims", "claims", claims)

	// ESIA puts subject ID in "urn:esia:sbj_id" claim
	sbjID, ok := claims["urn:esia:sbj_id"]
	if !ok {
		// Fallback: sometimes it's in "sbj_id" or "sub"
		if sbjID, ok = claims["sbj_id"]; !ok {
			if sub, ok2 := claims["sub"]; ok2 {
				sbjID = sub
			} else {
				return "", fmt.Errorf("no subject ID found in JWT claims: %v", claims)
			}
		}
	}

	// JSON unmarshals numbers as float64, so we need to convert properly
	switch v := sbjID.(type) {
	case float64:
		return fmt.Sprintf("%d", int64(v)), nil
	case json.Number:
		return v.String(), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

// fetchSnils calls ESIA REST API to get person data including SNILS.
func fetchSnils(accessToken, oid string) (*SnilsInfo, error) {
	reqURL := fmt.Sprintf("%s/rs/prns/%s", ESIATest, oid)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SNILS request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read SNILS response: %w", err)
	}

	slog.Info("SNILS response", "status", resp.StatusCode, "body", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SNILS endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var snils SnilsInfo
	if err := json.Unmarshal(body, &snils); err != nil {
		return nil, fmt.Errorf("failed to parse SNILS response: %w", err)
	}

	return &snils, nil
}

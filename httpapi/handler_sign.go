// Package httpapi provides HTTP handlers for CryptoPro key extraction and signing.
package httpapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/LdDl/esia-potato/cms"
	"github.com/ddulesov/gogost/gost3410"
)

func HandleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse JSON: "+err.Error())
		return
	}

	// Decode private key
	keyBytes, err := hex.DecodeString(req.PrivateKeyHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid private key hex: "+err.Error())
		return
	}

	// Decode certificate
	certDER, err := base64.StdEncoding.DecodeString(req.CertificateB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid certificate base64: "+err.Error())
		return
	}

	// Create private key (using default curve - CryptoPro A)
	curve := gost3410.CurveIdGostR34102001CryptoProAParamSet()
	prv, err := gost3410.NewPrivateKey(curve, gost3410.Mode2001, keyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to create private key: "+err.Error())
		return
	}

	// Create signer
	signer, err := cms.NewSigner(prv, certDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to create signer: "+err.Error())
		return
	}

	// Sign message
	cmsDER, err := signer.Sign([]byte(req.Message))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign: "+err.Error())
		return
	}

	slog.Info("message signed",
		"message_len", len(req.Message),
		"signature_len", len(cmsDER),
	)

	resp := SignResponse{
		SignatureB64: base64.StdEncoding.EncodeToString(cmsDER),
	}

	writeJSON(w, http.StatusOK, resp)
}

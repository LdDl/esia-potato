// Package cryptopro implements extraction of private keys from CryptoPro containers.
package cryptopro

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/LdDl/esia-potato/utils"
	"github.com/ddulesov/gogost/gost28147"
	"github.com/ddulesov/gogost/gost3410"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/pkg/errors"
)

// Sentinel errors
var (
	ErrCurveOIDNotFound    = fmt.Errorf("could not find curve OID in header.key")
	ErrCurveOIDUnknown     = fmt.Errorf("unknown curve OID")
	ErrFingerprintMismatch = fmt.Errorf("fingerprint mismatch (wrong password?)")
	ErrModInverseFailed    = fmt.Errorf("failed to calculate modular inverse")
)

// CurveOID maps OID strings to gogost curves
var CurveOID = map[string]*gost3410.Curve{
	// GOST 2012 256-bit
	"1.2.643.7.1.2.1.1.1": gost3410.CurveIdtc26gost34102012256paramSetA(),
	// GOST 2001 / CryptoPro A
	"1.2.643.2.2.35.1": gost3410.CurveIdGostR34102001CryptoProAParamSet(),
	// CryptoPro B
	"1.2.643.2.2.35.2": gost3410.CurveIdGostR34102001CryptoProBParamSet(),
	// CryptoPro C
	"1.2.643.2.2.35.3": gost3410.CurveIdGostR34102001CryptoProCParamSet(),
	// CryptoPro XchA
	"1.2.643.2.2.36.0": gost3410.CurveIdGostR34102001CryptoProXchAParamSet(),
	// CryptoPro XchB
	"1.2.643.2.2.36.1": gost3410.CurveIdGostR34102001CryptoProXchBParamSet(),
}

// OID patterns to search in header.key
var oidPatterns = map[string][]byte{
	// CryptoPro A
	"1.2.643.2.2.35.1": {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01},
	// CryptoPro B
	"1.2.643.2.2.35.2": {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02},
	// CryptoPro C
	"1.2.643.2.2.35.3": {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03},
	// CryptoPro XchA
	"1.2.643.2.2.36.0": {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00},
	// CryptoPro XchB
	"1.2.643.2.2.36.1": {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01},
	// GOST 2012-256-A
	"1.2.643.7.1.2.1.1.1": {0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01},
	// GOST 2012-256-B
	"1.2.643.7.1.2.1.1.2": {0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x02},
}

// KeyData contains extracted key information
type KeyData struct {
	PrivateKey  []byte
	PublicKey   []byte
	CurveOID    string
	Fingerprint []byte
}

// Container represents a CryptoPro key container
type Container struct {
	Path   string
	Header []byte
	Curve  *gost3410.Curve
	OID    string
}

// maskData is ASN.1 structure for masks.key
// SEQUENCE { OCTET STRING mask, OCTET STRING salt, OCTET STRING hmac }
type maskData struct {
	Mask []byte
	Salt []byte
	HMAC []byte
}

// primaryData is ASN.1 structure for primary.key
// SEQUENCE { OCTET STRING value }
type primaryData struct {
	Value []byte
}

// OpenContainer opens and parses a CryptoPro container
func OpenContainer(path string) (*Container, error) {
	// Read header.key
	headerPath := filepath.Join(path, "header.key")
	header, err := os.ReadFile(headerPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read header.key")
	}

	// Find curve OID
	oid := findCurveOID(header)
	if oid == "" {
		return nil, ErrCurveOIDNotFound
	}

	curve, ok := CurveOID[oid]
	if !ok {
		return nil, errors.Wrapf(ErrCurveOIDUnknown, "oid: %s", oid)
	}

	return &Container{
		Path:   path,
		Header: header,
		Curve:  curve,
		OID:    oid,
	}, nil
}

// ExtractKey extracts the private key using the provided password
func (c *Container) ExtractKey(password string) (*KeyData, error) {
	// Read masks.key
	masksPath := filepath.Join(c.Path, "masks.key")
	masksData, err := os.ReadFile(masksPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read masks.key")
	}

	// Read primary.key
	primaryPath := filepath.Join(c.Path, "primary.key")
	primaryKeyData, err := os.ReadFile(primaryPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read primary.key")
	}

	// Parse ASN.1 structures
	var mask maskData
	_, err = asn1.Unmarshal(masksData, &mask)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse masks.key")
	}

	var primary primaryData
	_, err = asn1.Unmarshal(primaryKeyData, &primary)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse primary.key")
	}

	// Derive key from password using CPKDF
	derivedKey, err := cpkdf([]byte(password), mask.Salt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive key")
	}

	// Decrypt with GOST 28147 ECB
	decrypted := gost28147ECBDecrypt(derivedKey, primary.Value)

	// Reverse the decrypted key (little-endian to big-endian)
	utils.ReverseBytesInPlace(decrypted)

	// Unmask the key
	privateKey, err := unmaskKey(decrypted, mask.Mask, c.Curve)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmask key")
	}

	// Calculate public key for verification
	prv, err := gost3410.NewPrivateKey(c.Curve, gost3410.Mode2001, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create private key")
	}

	pub, err := prv.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive public key")
	}

	publicKey := pub.Raw()

	// Verify fingerprint
	expectedFP := findFingerprint(c.Header, 0x8a)
	actualFP := publicKey[:8]
	if expectedFP != nil && !bytes.Equal(actualFP, expectedFP) {
		return nil, errors.Wrapf(ErrFingerprintMismatch, "expected %x, got %x", expectedFP, actualFP)
	}

	return &KeyData{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		CurveOID:    c.OID,
		Fingerprint: actualFP,
	}, nil
}

// cpkdf implements CryptoPro Key Derivation Function
// it is just four steps of hashing with some XOR and iterations
func cpkdf(password, salt []byte) ([]byte, error) {
	h := gost34112012256.New()
	bs := h.Size() * 2 // 64 bytes I guess?

	// Expand password 4x (CryptoPro specific)
	var pin []byte
	if len(password) > 0 {
		pin = make([]byte, len(password)*4)
		for i := 0; i < len(password); i++ {
			pin[i*4] = password[i]
		}
	}

	// Stage 1: hash salt and password
	if _, err := h.Write(salt); err != nil {
		return nil, errors.Wrap(err, "failed to hash salt")
	}
	if len(pin) > 0 {
		if _, err := h.Write(pin); err != nil {
			return nil, errors.Wrap(err, "failed to hash pin")
		}
	}
	hashResult := h.Sum(nil)
	h.Reset()

	// Create working arrays
	c := []byte("DENEFH028.760246785.IUEFHWUIO.EF")
	if len(c) < bs {
		c = append(c, make([]byte, bs-len(c))...)
	}
	m0 := make([]byte, 64)
	m1 := make([]byte, 64)

	// Set iterations
	iterations := 2
	if len(password) > 0 {
		iterations = 2000
	}

	// Stage 2: multi-iterative hashing
	for i := 0; i < iterations; i++ {
		for j := 0; j < len(c); j++ {
			m0[j] = c[j] ^ 0x36
			m1[j] = c[j] ^ 0x5C
		}

		if _, err := h.Write(m0); err != nil {
			return nil, errors.Wrap(err, "failed to hash m0")
		}
		if _, err := h.Write(hashResult); err != nil {
			return nil, errors.Wrap(err, "failed to hash result")
		}
		if _, err := h.Write(m1); err != nil {
			return nil, errors.Wrap(err, "failed to hash m1")
		}
		if _, err := h.Write(hashResult); err != nil {
			return nil, errors.Wrap(err, "failed to hash result")
		}

		c = h.Sum(nil)
		if len(c) < bs {
			c = append(c, make([]byte, bs-len(c))...)
		}
		h.Reset()
	}

	// Stage 3: hash salt with derived arrays
	for j := 0; j < len(c); j++ {
		m0[j] = c[j] ^ 0x36
		m1[j] = c[j] ^ 0x5C
	}

	if _, err := h.Write(m0[:32]); err != nil {
		return nil, errors.Wrap(err, "failed to hash m0")
	}
	if _, err := h.Write(salt); err != nil {
		return nil, errors.Wrap(err, "failed to hash salt")
	}
	if _, err := h.Write(m1[:32]); err != nil {
		return nil, errors.Wrap(err, "failed to hash m1")
	}
	if len(pin) > 0 {
		if _, err := h.Write(pin); err != nil {
			return nil, errors.Wrap(err, "failed to hash pin")
		}
	}
	c = h.Sum(nil)

	// Stage 4: final hash
	if len(c) < bs {
		c = append(c, make([]byte, bs-len(c))...)
	}
	h.Reset()
	if _, err := h.Write(c[:32]); err != nil {
		return nil, errors.Wrap(err, "failed to hash final")
	}
	return h.Sum(nil), nil
}

// gost28147ECBDecrypt decrypts data using GOST 28147 ECB mode
func gost28147ECBDecrypt(key, data []byte) []byte {
	cipher := gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
	decrypter := cipher.NewECBDecrypter()

	result := make([]byte, len(data))
	decrypter.CryptBlocks(result, data)
	return result
}

// unmaskKey applies the mask to get the real private key
func unmaskKey(encrypted, mask []byte, curve *gost3410.Curve) ([]byte, error) {
	// Reverse mask
	maskCopy := make([]byte, len(mask))
	copy(maskCopy, mask)
	utils.ReverseBytesInPlace(maskCopy)

	// Convert to big integers
	pk := new(big.Int).SetBytes(encrypted)
	m := new(big.Int).SetBytes(maskCopy)

	// Calculate: (pk * modInverse(m, q)) mod q
	mInv := new(big.Int).ModInverse(m, curve.Q)
	if mInv == nil {
		return nil, ErrModInverseFailed
	}

	raw := new(big.Int).Mul(pk, mInv)
	raw.Mod(raw, curve.Q)

	// Convert back to bytes and reverse
	result := raw.Bytes()
	// Pad to 32 bytes if needed
	if len(result) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(result):], result)
		result = padded
	}
	utils.ReverseBytesInPlace(result)

	return result, nil
}

// findCurveOID searches for a curve OID pattern in header data
func findCurveOID(header []byte) string {
	for oid, pattern := range oidPatterns {
		if bytes.Contains(header, pattern) {
			return oid
		}
	}
	return ""
}

// findFingerprint finds fingerprint in header.key
func findFingerprint(header []byte, tag byte) []byte {
	pattern := []byte{tag, 0x08}
	idx := bytes.Index(header, pattern)
	if idx != -1 && idx+10 <= len(header) {
		return header[idx+2 : idx+10]
	}
	return nil
}

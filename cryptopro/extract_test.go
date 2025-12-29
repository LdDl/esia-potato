package cryptopro

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/LdDl/esia-potato/utils"
	"github.com/ddulesov/gogost/gost28147"
	"github.com/ddulesov/gogost/gost3410"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// go test -timeout 30s -run ^TestCPKDF_EmptyPassword$ github.com/LdDl/esia-potato/cryptopro
func TestCPKDF_EmptyPassword(t *testing.T) {
	salt, err := hex.DecodeString("aabbccdd11223344aabbccdd")
	require.NoError(t, err)

	password := []byte("")

	key, err := cpkdf(password, salt)
	require.NoError(t, err)

	assert.Len(t, key, 32, "CPKDF should return 32 bytes")

	key2, err := cpkdf(password, salt)
	require.NoError(t, err)
	assert.Equal(t, key, key2, "CPKDF should be deterministic")
}

// go test -timeout 30s -run ^TestCPKDF_WithPassword$ github.com/LdDl/esia-potato/cryptopro
func TestCPKDF_WithPassword(t *testing.T) {
	salt, err := hex.DecodeString("aabbccdd11223344aabbccdd")
	require.NoError(t, err)

	password := []byte("testpassword")

	key, err := cpkdf(password, salt)
	require.NoError(t, err)

	assert.Len(t, key, 32, "CPKDF should return 32 bytes")

	key2, err := cpkdf([]byte("otherpassword"), salt)
	require.NoError(t, err)
	assert.NotEqual(t, key, key2, "Different passwords should produce different keys")

	salt2, err := hex.DecodeString("11223344aabbccdd11223344")
	require.NoError(t, err)

	key3, err := cpkdf(password, salt2)
	require.NoError(t, err)
	assert.NotEqual(t, key, key3, "Different salts should produce different keys")
}

// go test -timeout 30s -run ^TestGOST28147_ECB_Roundtrip$ github.com/LdDl/esia-potato/cryptopro
func TestGOST28147_ECB_Roundtrip(t *testing.T) {
	key, err := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)

	plaintext, err := hex.DecodeString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	require.NoError(t, err)

	cipher := gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
	encrypter := cipher.NewECBEncrypter()
	encrypted := make([]byte, len(plaintext))
	encrypter.CryptBlocks(encrypted, plaintext)

	decrypter := cipher.NewECBDecrypter()
	decrypted := make([]byte, len(encrypted))
	decrypter.CryptBlocks(decrypted, encrypted)

	assert.Equal(t, plaintext, decrypted, "Roundtrip should preserve data")
}

// go test -timeout 30s -run ^TestUnmaskMath$ github.com/LdDl/esia-potato/cryptopro
func TestUnmaskMath(t *testing.T) {
	curve := gost3410.CurveIdGostR34102001CryptoProAParamSet()

	a := new(big.Int)
	_, ok := a.SetString("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16)
	require.True(t, ok, "Failed to parse a")

	b := new(big.Int)
	_, ok = b.SetString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 16)
	require.True(t, ok, "Failed to parse b")

	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, curve.Q)

	bInv := new(big.Int).ModInverse(b, curve.Q)
	require.NotNil(t, bInv, "modInverse failed")

	result := new(big.Int).Mul(ab, bInv)
	result.Mod(result, curve.Q)

	expected := new(big.Int).Mod(a, curve.Q)

	assert.Equal(t, 0, result.Cmp(expected), "Modular math failed")
}

// go test -timeout 30s -run ^TestReverseBytes$ github.com/LdDl/esia-potato/cryptopro
func TestReverseBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0102030405060708", "0807060504030201"},
		{"aabbccdd", "ddccbbaa"},
		{"00", "00"},
		{"", ""},
	}

	for _, tt := range tests {
		input, err := hex.DecodeString(tt.input)
		require.NoError(t, err)

		expected, err := hex.DecodeString(tt.expected)
		require.NoError(t, err)

		utils.ReverseBytesInPlace(input)

		assert.Equal(t, expected, input, "ReverseBytesInPlace(%s) failed", tt.input)
	}
}

// go test -timeout 30s -run ^TestFindCurveOID$ github.com/LdDl/esia-potato/cryptopro
func TestFindCurveOID(t *testing.T) {
	header := []byte{0x30, 0x82, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, 0x00}

	oid := findCurveOID(header)
	assert.Equal(t, "1.2.643.2.2.35.1", oid)

	header2 := []byte{0x30, 0x82, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00, 0x00}
	oid2 := findCurveOID(header2)
	assert.Equal(t, "1.2.643.2.2.36.0", oid2)

	header3 := []byte{0x30, 0x82, 0x00, 0x00, 0x00}
	oid3 := findCurveOID(header3)
	assert.Empty(t, oid3, "findCurveOID should return empty for unknown OID")
}

// go test -timeout 30s -run ^TestFindFingerprint$ github.com/LdDl/esia-potato/cryptopro
func TestFindFingerprint(t *testing.T) {
	header := []byte{0x30, 0x82, 0x8a, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00}

	fp := findFingerprint(header, 0x8a)
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	assert.Equal(t, expected, fp)

	header2 := []byte{0x30, 0x82, 0x00, 0x00, 0x00}
	fp2 := findFingerprint(header2, 0x8a)
	assert.Nil(t, fp2, "findFingerprint should return nil for header without fingerprint")
}

// go test -timeout 30s -run ^TestCurveOIDMap$ github.com/LdDl/esia-potato/cryptopro
func TestCurveOIDMap(t *testing.T) {
	expectedOIDs := []string{
		"1.2.643.2.2.35.1",
		"1.2.643.2.2.36.0",
		"1.2.643.2.2.36.1",
		"1.2.643.7.1.2.1.1.1",
	}

	for _, oid := range expectedOIDs {
		curve := CurveOID[oid]
		assert.NotNil(t, curve, "CurveOID[%s] should not be nil", oid)
	}
}

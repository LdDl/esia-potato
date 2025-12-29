package cms

import (
	"crypto/rand"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/ddulesov/gogost/gost3410"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestPrivateKey(t *testing.T) *gost3410.PrivateKey {
	curve := gost3410.CurveIdGostR34102001CryptoProAParamSet()

	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	require.NoError(t, err, "Failed to generate random key")

	prv, err := gost3410.NewPrivateKey(curve, gost3410.Mode2001, keyBytes)
	require.NoError(t, err, "Failed to create private key")

	return prv
}

func createTestCertDER() []byte {
	cert := []byte{
		0x30, 0x82, 0x01, 0x00, // SEQUENCE
		0x30, 0x81, 0xf0, // tbsCertificate SEQUENCE
		0xa0, 0x03, 0x02, 0x01, 0x02, // version
		0x02, 0x01, 0x01, // serialNumber
		0x30, 0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02, // algorithm
		0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x00, // issuer
		0x30, 0x1e, // validity
		0x17, 0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
		0x17, 0x0d, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
		0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x00, // subject
		0x30, 0x66, // subjectPublicKeyInfo
		0x30, 0x1f, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01,
		0x30, 0x13, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01,
		0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02,
		0x03, 0x43, 0x00, 0x04, 0x40,
	}
	cert = append(cert, make([]byte, 64)...)
	cert = append(cert, []byte{
		0x30, 0x0a, 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02,
		0x03, 0x41, 0x00,
	}...)
	cert = append(cert, make([]byte, 64)...)

	return cert
}

// go test -timeout 30s -run ^TestStreebog256$ github.com/LdDl/esia-potato/cms
func TestStreebog256(t *testing.T) {
	h := gost34112012256.New()
	h.Write([]byte("test"))
	result := h.Sum(nil)

	assert.Len(t, result, 32, "Streebog-256 should produce 32 bytes")

	h2 := gost34112012256.New()
	h2.Write([]byte("test"))
	result2 := h2.Sum(nil)

	assert.Equal(t, result, result2, "Streebog-256 should be deterministic")

	h3 := gost34112012256.New()
	h3.Write([]byte("other"))
	result3 := h3.Sum(nil)

	assert.NotEqual(t, result, result3, "Different inputs should produce different hashes")
}

// go test -timeout 30s -run ^TestGOSTSignature$ github.com/LdDl/esia-potato/cms
func TestGOSTSignature(t *testing.T) {
	prv := createTestPrivateKey(t)
	pub, err := prv.PublicKey()
	require.NoError(t, err, "Failed to get public key")

	h := gost34112012256.New()
	h.Write([]byte("test message"))
	digest := h.Sum(nil)

	signature, err := prv.SignDigest(digest, rand.Reader)
	require.NoError(t, err, "SignDigest failed")

	assert.Len(t, signature, 64, "Signature should be 64 bytes")

	valid, err := pub.VerifyDigest(digest, signature)
	require.NoError(t, err, "VerifyDigest failed")

	assert.True(t, valid, "Signature verification failed")

	digest[0] ^= 0xff
	valid2, err := pub.VerifyDigest(digest, signature)
	require.NoError(t, err)
	assert.False(t, valid2, "Modified digest should fail verification")
}

// go test -timeout 30s -run ^TestDigestReversal$ github.com/LdDl/esia-potato/cms
func TestDigestReversal(t *testing.T) {
	digest := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	expected := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

	reversed := make([]byte, len(digest))
	for i := 0; i < len(digest); i++ {
		reversed[i] = digest[len(digest)-1-i]
	}

	assert.Equal(t, expected, reversed, "Digest reversal failed")
}

// go test -timeout 30s -run ^TestOIDEncoding$ github.com/LdDl/esia-potato/cms
func TestOIDEncoding(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}

	encoded, err := asn1.Marshal(oid)
	require.NoError(t, err, "Failed to encode OID")

	var decoded asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(encoded, &decoded)
	require.NoError(t, err, "Failed to decode OID")

	assert.True(t, oid.Equal(decoded), "OID roundtrip failed")
}

// go test -timeout 30s -run ^TestESIATimeFormat$ github.com/LdDl/esia-potato/cms
func TestESIATimeFormat(t *testing.T) {
	now := time.Date(2024, 12, 29, 15, 30, 45, 0, time.FixedZone("MSK", 3*3600))
	formatted := now.Format("2006.01.02 15:04:05 -0700")

	expected := "2024.12.29 15:30:45 +0300"
	assert.Equal(t, expected, formatted, "Time format mismatch")
}

// go test -timeout 30s -run ^TestSignedAttributesOrder$ github.com/LdDl/esia-potato/cms
func TestSignedAttributesOrder(t *testing.T) {
	contentTypeOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	signingTimeOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	messageDigestOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	assert.False(t, contentTypeOID.Equal(signingTimeOID), "contentType and signingTime should be different")
	assert.False(t, contentTypeOID.Equal(messageDigestOID), "contentType and messageDigest should be different")
	assert.False(t, signingTimeOID.Equal(messageDigestOID), "signingTime and messageDigest should be different")
}

// go test -timeout 30s -run ^TestNewSignerValidation$ github.com/LdDl/esia-potato/cms
func TestNewSignerValidation(t *testing.T) {
	prv := createTestPrivateKey(t)

	_, err := NewSigner(prv, []byte{})
	assert.Error(t, err, "NewSigner should fail with empty certificate")
}

// go test -timeout 30s -run ^TestSignProducesDER$ github.com/LdDl/esia-potato/cms
func TestSignProducesDER(t *testing.T) {
	prv := createTestPrivateKey(t)
	certDER := createTestCertDER()

	signer, err := NewSigner(prv, certDER)
	require.NoError(t, err, "NewSigner failed")

	message := []byte("test message for signing")
	cmsDER, err := signer.Sign(message)
	require.NoError(t, err, "Sign failed")

	assert.GreaterOrEqual(t, len(cmsDER), 4, "CMS DER too short")
	assert.Equal(t, byte(0x30), cmsDER[0], "CMS should start with SEQUENCE tag (0x30)")
	assert.GreaterOrEqual(t, len(cmsDER), 100, "CMS DER seems too small")
}

// go test -timeout 30s -run ^TestSignDeterministicContent$ github.com/LdDl/esia-potato/cms
func TestSignDeterministicContent(t *testing.T) {
	prv := createTestPrivateKey(t)
	certDER := createTestCertDER()

	signer, err := NewSigner(prv, certDER)
	require.NoError(t, err, "NewSigner failed")

	message := []byte("test message")

	cms1, err := signer.Sign(message)
	require.NoError(t, err, "First Sign failed")

	cms2, err := signer.Sign(message)
	require.NoError(t, err, "Second Sign failed")

	sizeDiff := len(cms1) - len(cms2)
	assert.InDelta(t, 0, sizeDiff, 10, "CMS sizes differ too much")
}

// Package cms implements CMS/PKCS#7 SignedData with GOST cryptography support
package cms

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/LdDl/esia-potato/utils"
	"github.com/ddulesov/gogost/gost3410"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/pkg/errors"
)

// Sentinel errors
var (
	ErrCertificateParse  = fmt.Errorf("failed to parse certificate")
	ErrSignedAttributes  = fmt.Errorf("failed to create signed attributes")
	ErrSign              = fmt.Errorf("failed to sign")
	ErrMarshalSignedData = fmt.Errorf("failed to marshal SignedData")
)

// OIDs for GOST algorithms
var (
	// GOST R 34.11-2012 256-bit hash
	OIDGostR341112256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	// GOST R 34.10-2012 256-bit signature
	OIDGostR341012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	// GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)
	OIDGostR341012256WithGostR341112256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}

	// PKCS#7 OIDs
	OIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// Attribute OIDs
	OIDAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// ContentInfo is the top-level CMS structure
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData represents CMS SignedData structure
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

// EncapsulatedContentInfo holds the content being signed
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// SignerInfo contains information about a signer
type SignerInfo struct {
	Version            int
	IssuerAndSerial    IssuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// IssuerAndSerial identifies the signer's certificate
type IssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute represents a signed attribute
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// Signer holds the signing context
type Signer struct {
	PrivateKey *gost3410.PrivateKey
	// DER-encoded certificate
	Certificate []byte
	certParsed  *certificate
}

// certificate is a minimal structure to extract issuer and serial
type certificate struct {
	TBSCertificate struct {
		Raw          asn1.RawContent
		Version      int `asn1:"optional,explicit,tag:0,default:0"`
		SerialNumber *big.Int
		Signature    pkix.AlgorithmIdentifier
		Issuer       asn1.RawValue
	}
}

// NewSigner creates a new CMS signer
func NewSigner(privateKey *gost3410.PrivateKey, certDER []byte) (*Signer, error) {
	var cert certificate
	_, err := asn1.Unmarshal(certDER, &cert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	return &Signer{
		PrivateKey:  privateKey,
		Certificate: certDER,
		certParsed:  &cert,
	}, nil
}

// Sign creates a CMS SignedData structure (detached mode with signedAttributes)
func (s *Signer) Sign(content []byte) ([]byte, error) {
	// 1. Compute digest of content
	h := gost34112012256.New()
	if _, err := h.Write(content); err != nil {
		return nil, errors.Wrap(err, "failed to hash content")
	}
	contentDigest := h.Sum(nil)

	// 2. Create signedAttributes
	signedAttrs, attrsForSigning, err := s.createSignedAttributes(contentDigest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signed attributes")
	}

	// 3. Hash the signedAttributes (what we actually sign)
	h = gost34112012256.New()
	if _, err := h.Write(attrsForSigning); err != nil {
		return nil, errors.Wrap(err, "failed to hash attributes")
	}
	attrsDigest := h.Sum(nil)

	// 4. Sign the attributes digest
	// GOST-engine reverses the digest (little-endian to big-endian) before signing
	// gogost expects the same format, so we need to reverse the digest
	reversedDigest := utils.ReverseBytes(attrsDigest)
	rawSig, err := s.PrivateKey.SignDigest(reversedDigest, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign")
	}

	// 5. Build SignerInfo with signedAttributes
	signerInfo := SignerInfo{
		Version: 1,
		IssuerAndSerial: IssuerAndSerial{
			Issuer:       s.certParsed.TBSCertificate.Issuer,
			SerialNumber: s.certParsed.TBSCertificate.SerialNumber,
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDGostR341112256,
			Parameters: asn1.NullRawValue,
		},
		SignedAttrs: signedAttrs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDGostR341012256,
			Parameters: asn1.NullRawValue,
		},
		Signature: rawSig,
	}

	// 6. Build SignedData (detached mode - no eContent)
	signedData := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{
				Algorithm:  OIDGostR341112256,
				Parameters: asn1.NullRawValue,
			},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
			// Detached mode: eContent is omitted
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      s.Certificate,
		},
		SignerInfos: []SignerInfo{signerInfo},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal SignedData")
	}

	// 7. Wrap in ContentInfo
	contentInfo := ContentInfo{
		ContentType: OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	return asn1.Marshal(contentInfo)
}

func (s *Signer) createSignedAttributes(digest []byte) (asn1.RawValue, []byte, error) {
	// Content type attribute
	contentTypeBytes, err := asn1.Marshal(OIDData)
	if err != nil {
		return asn1.RawValue{}, nil, errors.Wrap(err, "failed to marshal content type OID")
	}
	contentTypeAttr := Attribute{
		Type: OIDAttributeContentType,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      contentTypeBytes,
		},
	}

	// Signing time attribute
	signingTime := time.Now().UTC()
	signingTimeBytes, err := asn1.Marshal(signingTime)
	if err != nil {
		return asn1.RawValue{}, nil, errors.Wrap(err, "failed to marshal signing time")
	}
	signingTimeAttr := Attribute{
		Type: OIDAttributeSigningTime,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      signingTimeBytes,
		},
	}

	// Message digest attribute
	digestBytes, err := asn1.Marshal(digest)
	if err != nil {
		return asn1.RawValue{}, nil, errors.Wrap(err, "failed to marshal digest")
	}
	messageDigestAttr := Attribute{
		Type: OIDAttributeMessageDigest,
		Values: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      digestBytes,
		},
	}

	// Marshal attributes as SET
	// Order matches OpenSSL: contentType (1.9.3), signingTime (1.9.5), messageDigest (1.9.4)
	attrs := []Attribute{contentTypeAttr, signingTimeAttr, messageDigestAttr}
	attrsBytes, err := asn1.Marshal(attrs)
	if err != nil {
		return asn1.RawValue{}, nil, errors.Wrap(err, "failed to marshal attributes")
	}

	// For signing, we need SET tag (0x31) instead of IMPLICIT [0] (0xA0)
	// The attrsBytes starts with SEQUENCE tag, we need to replace with SET
	attrsForSigning := make([]byte, len(attrsBytes))
	copy(attrsForSigning, attrsBytes)
	attrsForSigning[0] = 0x31 // SET tag

	// For embedding, use implicit tag [0]
	signedAttrs := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      attrsBytes[2:], // skip SEQUENCE tag and length
	}

	return signedAttrs, attrsForSigning, nil
}


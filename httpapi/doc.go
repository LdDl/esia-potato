// Package httpapi provides HTTP handlers for CryptoPro key extraction and signing.
//
// @title ESIA CryptoPro Key Extraction API
// @version 1.0
// @description HTTP API for extracting keys from CryptoPro containers and signing messages with GOST cryptography.
// @description
// @description Supports:
// @description - GOST R 34.10-2012 signature (256 bit)
// @description - GOST R 34.11-2012 hash (Streebog-256)
// @description - CMS/PKCS#7 SignedData generation
// @description - CryptoPro container key extraction
//
// @contact.name API Support
// @contact.url https://github.com/LdDl/esia-potato
//
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
//
// @host localhost:8080
// @BasePath /
// @schemes http https
//
// @externalDocs.description GitHub Repository
// @externalDocs.url https://github.com/LdDl/esia-potato
//
// @tag.name Health
// @tag.description Health check endpoints
//
// @tag.name Key Extraction
// @tag.description Extract keys from CryptoPro containers
//
// @tag.name Signing
// @tag.description Sign messages with GOST cryptography
package httpapi

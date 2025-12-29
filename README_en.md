# ESIA oAuth Client for Go

Two versions of README:

🇷🇺 [Русский](README.md) | 🇺🇸 [English](README_en.md)

Native Go implementation of oAuth via ESIA (Russian government authentication service) with GOST cryptography support.
No Docker builds with patched OpenSSL or external OpenSSL dependencies required.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Extracting Private Key from CryptoPro Container](#extracting-private-key-from-cryptopro-container)
- [ESIA Client Example](#esia-client-example)

## Features

- GOST R 34.10-2012 signature (256 bit)
- GOST R 34.11-2012 hash (Streebog-256)
- CMS/PKCS#7 SignedData generation
- CryptoPro container key extraction

## Prerequisites

- Go 1.21+ for building from source
- CryptoPro container with private key and certificate. The term "container" - is just a directory (could be an archive though) created when exporting a key from CryptoPro CSP.

## Project Structure

```
esia-potato/
|--- cms/
|    --- cms.go                   # CMS/PKCS#7 SignedData
|--- cryptopro/
|    --- extract.go               # Key extraction library
|--- utils/
|    --- bytes.go                 # Utility functions
|--- cmd/
|    |--- cryptopro_extract/
|    |    --- main.go             # CLI for key extraction
|    `--- example/
|         --- main.go             # ESIA client example
`--- test_container/              # Test keys (in .gitignore)
```

## Installation

* For the CryptoPro container key extraction utility
- If you just need the CLI:
  ```bash
  go install github.com/LdDl/esia-potato/cmd/cryptopro_extract@latest
  cryptopro_extract -h
  ```

- If you want to build from source:
  ```bash
  git clone git@github.com:LdDl/esia-potato.git --depth 1
  cd esia-potato
  go run ./cmd/cryptopro_extract -h
  ```

## Extracting Private Key from CryptoPro Container

CryptoPro container stores keys in a proprietary format encrypted with [GOST 28147](https://en.wikipedia.org/wiki/GOST_(block_cipher)).

- Using the installed CLI:
  ```bash
  cryptopro_extract -p YOUR_PIN_PASSWORD ./container.000
  ```

- Or from source:
  ```bash
  go run ./cmd/cryptopro_extract -p YOUR_PIN_PASSWORD ./container.000
  ```

If successful, the console output will look like:

```
{"time":"2025-12-29T20:36:00.591340886+03:00","level":"INFO","msg":"container opened","path":"./test_container","curve_oid":"1.2.643.2.2.36.0"}
{"time":"2025-12-29T20:36:01.065829042+03:00","level":"INFO","msg":"primary key extracted","curve_oid":"1.2.643.2.2.36.0","fingerprint":"0123456789abcdef","private_key":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
{"time":"2025-12-29T20:36:01.065854001+03:00","level":"WARN","msg":"secondary key found but not extracted","masks":"masks2.key","primary":"primary2.key"}
{"time":"2025-12-29T20:36:01.065858097+03:00","level":"INFO","msg":"done"}
```

If you see a warning message:
```
secondary key found but not extracted
```
this is normal - the secondary key is not needed for signing, as ESIA oAuth only uses the primary key.

Now you have the private key to use for signing ESIA requests.

## ESIA Client Example

- Take the private key from the previous step output and paste it into `cmd/example/main.go` in `keyHex`.
- Run the example:
  ```bash
  go run ./cmd/example/main.go
  ```

If successful, the console output will look like:
```
{"time":"2025-12-29T20:47:23.876107574+03:00","level":"INFO","msg":"message prepared","message":"openid2025.12.29 17:47:23 +0000775607_DP0f9439ef-3581-4de5-9b8c-d20135960331"}
{"time":"2025-12-29T20:47:23.878111012+03:00","level":"INFO","msg":"signature created","signature_bytes":2927,"base64_chars":3904}
{"time":"2025-12-29T20:47:23.8781677+03:00","level":"INFO","msg":"authorization URL prepared","url":"https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac?..."}
{"time":"2025-12-29T20:47:23.878185114+03:00","level":"INFO","msg":"testing against ESIA"}
{"time":"2025-12-29T20:47:23.95390256+03:00","level":"INFO","msg":"response received","status":"302 ","location":"https://esia-portal1.test.gosuslugi.ru/login"}
{"time":"2025-12-29T20:47:23.953918261+03:00","level":"INFO","msg":"signature accepted by ESIA"}
```

A redirect to /login means the signature passed verification and everything is OK.

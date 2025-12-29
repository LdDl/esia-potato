package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/LdDl/esia-potato/cryptopro"
	"golang.org/x/term"
)

func main() {
	var password string
	var output string

	flag.StringVar(&password, "password", "", "Container password (PIN)")
	flag.StringVar(&password, "p", "", "Container password (PIN) (shorthand)")
	flag.StringVar(&output, "output", "", "Output file prefix for saving keys")
	flag.StringVar(&output, "o", "", "Output file prefix (shorthand)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <container_path>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s ./container.000 -p 12345\n", os.Args[0])
		os.Exit(1)
	}

	containerPath := flag.Arg(0)

	// Check if container exists
	if _, err := os.Stat(containerPath); os.IsNotExist(err) {
		slog.Error("container not found", "path", containerPath)
		os.Exit(1)
	}

	// Open container
	container, err := cryptopro.OpenContainer(containerPath)
	if err != nil {
		slog.Error("failed to open container", "error", err)
		os.Exit(1)
	}

	slog.Info("container opened", "path", containerPath, "curve_oid", container.OID)

	// Get password if not provided and stdin is a terminal
	passwordProvided := false
	for _, arg := range os.Args[1:] {
		if arg == "-p" || arg == "-password" || arg == "--password" ||
			len(arg) > 2 && (arg[:3] == "-p=" || arg[:3] == "-p ") {
			passwordProvided = true
			break
		}
	}

	if !passwordProvided && term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print("Enter password: ")
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			slog.Error("failed to read password", "error", err)
			os.Exit(1)
		}
		password = string(pwBytes)
	}

	// Extract key
	keyData, err := container.ExtractKey(password)
	if err != nil {
		slog.Error("failed to extract key", "error", err)
		os.Exit(1)
	}

	slog.Info("primary key extracted",
		"curve_oid", keyData.CurveOID,
		"fingerprint", hex.EncodeToString(keyData.Fingerprint),
		"private_key", hex.EncodeToString(keyData.PrivateKey),
	)

	// Save to file if requested
	if output != "" {
		outFile := output + "_primary.bin"
		if err := os.WriteFile(outFile, keyData.PrivateKey, 0600); err != nil {
			slog.Error("failed to save key", "error", err)
			os.Exit(1)
		}
		slog.Info("key saved", "file", outFile)

		// Also save hex version
		hexFile := output + "_primary.hex"
		hexData := []byte(hex.EncodeToString(keyData.PrivateKey))
		if err := os.WriteFile(hexFile, hexData, 0600); err != nil {
			slog.Error("failed to save hex", "error", err)
			os.Exit(1)
		}
		slog.Info("hex saved", "file", hexFile)
	}

	// Try secondary key
	masks2Path := filepath.Join(containerPath, "masks2.key")
	primary2Path := filepath.Join(containerPath, "primary2.key")

	if _, err := os.Stat(masks2Path); err == nil {
		if _, err := os.Stat(primary2Path); err == nil {
			slog.Warn("secondary key found but not extracted", "masks", "masks2.key", "primary", "primary2.key")
		}
	}

	slog.Info("done")
}

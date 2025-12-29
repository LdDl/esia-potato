package httpapi

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
)

func extractArchive(file multipart.File, filename string, destDir string) (string, error) {
	lowerName := strings.ToLower(filename)

	switch {
	case strings.HasSuffix(lowerName, ".zip"):
		return extractZip(file, destDir)
	case strings.HasSuffix(lowerName, ".tar.gz") || strings.HasSuffix(lowerName, ".tgz"):
		return extractTarGz(file, destDir)
	default:
		return "", fmt.Errorf("unsupported archive format: %s (use .zip or .tar.gz)", filename)
	}
}

func extractZip(file multipart.File, destDir string) (string, error) {
	// Need to read entire file for zip (requires seeking)
	tempFile, err := os.CreateTemp("", "upload-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	size, err := io.Copy(tempFile, file)
	if err != nil {
		return "", fmt.Errorf("failed to copy upload: %w", err)
	}

	zipReader, err := zip.NewReader(tempFile, size)
	if err != nil {
		return "", fmt.Errorf("failed to open zip: %w", err)
	}

	for _, f := range zipReader.File {
		// Security: prevent path traversal
		cleanPath := filepath.Clean(f.Name)
		if strings.HasPrefix(cleanPath, "..") {
			continue
		}

		destPath := filepath.Join(destDir, cleanPath)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return "", fmt.Errorf("failed to create dir: %w", err)
			}
			continue
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return "", fmt.Errorf("failed to create parent dir: %w", err)
		}

		// Extract file
		srcFile, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("failed to open zip entry: %w", err)
		}

		dstFile, err := os.Create(destPath)
		if err != nil {
			srcFile.Close()
			return "", fmt.Errorf("failed to create file: %w", err)
		}

		_, err = io.Copy(dstFile, srcFile)
		srcFile.Close()
		dstFile.Close()
		if err != nil {
			return "", fmt.Errorf("failed to extract file: %w", err)
		}
	}

	// Find container directory (the one with header.key)
	return findContainerDir(destDir)
}

func extractTarGz(file multipart.File, destDir string) (string, error) {
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		// Security: prevent path traversal
		cleanPath := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanPath, "..") {
			continue
		}

		destPath := filepath.Join(destDir, cleanPath)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0755); err != nil {
				return "", fmt.Errorf("failed to create dir: %w", err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return "", fmt.Errorf("failed to create parent dir: %w", err)
			}

			dstFile, err := os.Create(destPath)
			if err != nil {
				return "", fmt.Errorf("failed to create file: %w", err)
			}

			_, err = io.Copy(dstFile, tarReader)
			dstFile.Close()
			if err != nil {
				return "", fmt.Errorf("failed to extract file: %w", err)
			}
		}
	}

	// Find container directory (the one with header.key)
	return findContainerDir(destDir)
}

func findContainerDir(root string) (string, error) {
	var containerDir string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "header.key" {
			containerDir = filepath.Dir(path)
			return filepath.SkipAll
		}
		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return "", fmt.Errorf("failed to walk directory: %w", err)
	}

	if containerDir == "" {
		return "", fmt.Errorf("container not found (no header.key)")
	}

	return containerDir, nil
}

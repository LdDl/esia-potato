// Package utils provides utility functions for GOST cryptography operations.
package utils

// ReverseBytes returns a new byte slice with bytes in reverse order.
func ReverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// ReverseBytesInPlace reverses a byte slice in place.
func ReverseBytesInPlace(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

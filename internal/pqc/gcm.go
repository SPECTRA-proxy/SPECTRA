// Package pqc — AES-256-GCM transport framing helpers (Option 1 application framing).
//
// Once the SPECTRA handshake establishes a 32-byte session key, all subsequent
// HTTP payloads exchanged over the SPECTRA tunnel are encrypted using AES-256-GCM.
//
// Wire format (as raw bytes over the POST body):
//
//	[ 12-byte nonce ][ encrypted ciphertext ][ 16-byte GCM auth tag ]
//
// The nonce is randomly generated per message; never reused for the same key.
package pqc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Seal encrypts plaintext using AES-256-GCM with the provided 32-byte key.
// Returns [ nonce (12 bytes) || ciphertext || tag (16 bytes) ].
// A fresh random nonce is generated per call — never reuse a key+nonce pair.
func Seal(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("gcm: AES cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: GCM init failed: %w", err)
	}

	// 12-byte random nonce (standard GCM nonce size)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("gcm: nonce generation failed: %w", err)
	}

	// gcm.Seal appends the auth tag to ciphertext automatically
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Open decrypts a wire message produced by Seal.
// Input must be [ nonce (12 bytes) || ciphertext || tag (16 bytes) ].
// Returns the plaintext on success, or an error if authentication fails.
func Open(key [32]byte, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("gcm: AES cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: GCM init failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("gcm: ciphertext too short (%d bytes)", len(sealed))
	}

	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm: authentication failed — tampered or incorrect key: %w", err)
	}
	return plaintext, nil
}

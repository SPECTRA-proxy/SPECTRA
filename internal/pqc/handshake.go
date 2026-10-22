// Package pqc implements the SPECTRA Module 1 adaptive post-quantum handshake
// using Cloudflare's circl library (100% native Go, no CGO, no Python sidecar).
//
// Protocol — SPECTRA Handshake (1-RTT):
//
//	Client                                       Proxy
//	  │── SPECTRA_HELLO (POST /spectra/hello) ──►  │
//	  │   {client_id, supported_kems,              │
//	  │    supported_sigs, kem_share (pk),          │
//	  │    client_nonce, timestamp}                 │
//	  │                                             │  Validate timestamp & nonce (replay guard)
//	  │                                             │  Encapsulate shared secret with kem_share
//	  │                                             │  Sign transcript (client_nonce||server_nonce||kem_share||ct)
//	  │◄── SPECTRA_SERVER_HELLO ───────────────────  │
//	  │   {selected_kem, selected_sig,              │
//	  │    ciphertext, server_nonce,                │
//	  │    server_signature, server_public_key}     │
//	  │  Verify server_signature                   │
//	  │  Decapsulate ciphertext → shared_secret    │
//	  Both sides derive AES-256-GCM key via HKDF-SHA256
package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	// Cloudflare circl — pure Go, no CGO, NIST FIPS 203/204 compliant
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/hkdf"
)

// maxTimestampSkew is the maximum age of a SPECTRA_HELLO that the server accepts.
// Any request older than this is rejected as a potential replay.
const maxTimestampSkew = 30 * time.Second

// ────────────────────────────────────────────────────────────────────────────
// Replay Protection: Nonce Store
// ────────────────────────────────────────────────────────────────────────────

type seenNoncesCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var nonceStore = &seenNoncesCache{
	seen: make(map[string]time.Time),
}

// checkAndAdd returns true if nonce is fresh and added, false if already seen (replay).
func (c *seenNoncesCache) checkAndAdd(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Prune expired entries
	for n, t := range c.seen {
		if now.Sub(t) > maxTimestampSkew {
			delete(c.seen, n)
		}
	}

	if _, exists := c.seen[nonce]; exists {
		return false
	}
	c.seen[nonce] = now
	return true
}

// ────────────────────────────────────────────────────────────────────────────
// Wire types: SPECTRA_HELLO / SPECTRA_SERVER_HELLO
// ────────────────────────────────────────────────────────────────────────────

// ClientHello is the JSON payload the SPECTRA Client Connector sends when
// opening a new session (POST /spectra/hello).
type ClientHello struct {
	ClientID      string   `json:"client_id"`      // MAC address / device fingerprint
	SupportedKEMs []string `json:"supported_kems"` // e.g. ["ML-KEM-768","ML-KEM-512"]
	SupportedSigs []string `json:"supported_sigs"` // e.g. ["ML-DSA-65","ML-DSA-44"]
	KEMShare      string   `json:"kem_share"`      // base64 of speculative KEM public key
	ClientNonce   string   `json:"client_nonce"`   // base64 of 32 random bytes (replay guard)
	Timestamp     int64    `json:"timestamp"`      // Unix nanoseconds (replay guard)
}

// ServerHello is the JSON payload the proxy returns after a successful handshake.
type ServerHello struct {
	SelectedKEM     string `json:"selected_kem"`        // e.g. "ML-KEM-768"
	SelectedSig     string `json:"selected_sig"`        // e.g. "ML-DSA-65"
	Ciphertext      string `json:"ciphertext"`          // base64 of KEM-encapsulated shared secret
	ServerNonce     string `json:"server_nonce"`        // base64 of 32 random bytes (replay guard)
	ServerSignature string `json:"server_signature"`    // base64 ML-DSA signature of transcript hash
	ServerPublicKey string `json:"server_public_key"`   // base64 ML-DSA public key of server
	SessionID       string `json:"session_id"`          // opaque token for subsequent encrypted requests
}

// HandshakeResult is the internal result used by the engine after a successful
// SPECTRA_HELLO exchange. The session key (32 raw bytes) is stored in the
// proxy's key store and used by the AES-GCM transport framing layer.
type HandshakeResult struct {
	KEMScheme  string
	SigScheme  string
	Tier       string
	SessionKey [32]byte // AES-256-GCM key derived via HKDF-SHA256
	SessionID  string
}

// ClientCreds holds everything the client generates locally before sending
// SPECTRA_HELLO. The caller must keep this to call DecapsulateServerHello.
type ClientCreds struct {
	Hello         ClientHello
	KEMPrivateKey []byte // kept secret; used to Decapsulate the server's ciphertext
	SelectedKEM   string // the speculative KEM whose public key is in Hello.KEMShare
}

// ────────────────────────────────────────────────────────────────────────────
// Server-side long-lived ML-DSA signing keypairs (generated once at startup)
// ────────────────────────────────────────────────────────────────────────────

var (
	serverDSA44PK *mldsa44.PublicKey
	serverDSA44SK *mldsa44.PrivateKey
	serverDSA65PK *mldsa65.PublicKey
	serverDSA65SK *mldsa65.PrivateKey
	serverDSA87PK *mldsa87.PublicKey
	serverDSA87SK *mldsa87.PrivateKey
)

func init() {
	var err error

	serverDSA44PK, serverDSA44SK, err = mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("pqc: failed to generate ML-DSA-44 server keypair: %v", err))
	}
	serverDSA65PK, serverDSA65SK, err = mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("pqc: failed to generate ML-DSA-65 server keypair: %v", err))
	}
	serverDSA87PK, serverDSA87SK, err = mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("pqc: failed to generate ML-DSA-87 server keypair: %v", err))
	}
	log.Println("[MOD 1 - PQC] Server ML-DSA keypairs generated (ML-DSA-44 / 65 / 87) ✓")
}

// ────────────────────────────────────────────────────────────────────────────
// Proxy-side: HandleHello — processes POST /spectra/hello
// ────────────────────────────────────────────────────────────────────────────

// HandleHello reads the ClientHello, validates replay protection fields,
// performs KEM encapsulation, signs the transcript, and writes the ServerHello.
// On success, a *HandshakeResult is returned for the caller to store.
// On error, it writes the HTTP error and returns (nil, err).
func HandleHello(w http.ResponseWriter, r *http.Request) (*HandshakeResult, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return nil, fmt.Errorf("pqc: reading SPECTRA_HELLO body: %w", err)
	}

	var hello ClientHello
	if err := json.Unmarshal(body, &hello); err != nil {
		http.Error(w, "malformed SPECTRA_HELLO JSON", http.StatusBadRequest)
		return nil, fmt.Errorf("pqc: malformed SPECTRA_HELLO JSON: %w", err)
	}

	// ── Replay Prevention: timestamp freshness check ────────────────────
	requestTime := time.Unix(0, hello.Timestamp)
	age := time.Since(requestTime)
	if age < 0 {
		age = -age // clock skew tolerance
	}
	if age > maxTimestampSkew {
		http.Error(w, "SPECTRA_HELLO timestamp too old — replay rejected", http.StatusUnauthorized)
		return nil, fmt.Errorf("pqc: timestamp age %v exceeds max %v — replay rejected",
			age.Round(time.Millisecond), maxTimestampSkew)
	}

	// ── Replay Prevention: client nonce validation ──────────────────────
	clientNonceBytes, err := base64.StdEncoding.DecodeString(hello.ClientNonce)
	if err != nil || len(clientNonceBytes) < 16 {
		http.Error(w, "invalid or missing client_nonce", http.StatusBadRequest)
		return nil, fmt.Errorf("pqc: invalid client_nonce")
	}

	// ── Replay Prevention: nonce reuse check (Zero-Trust Anti-Replay) ────
	if !nonceStore.checkAndAdd(hello.ClientNonce, time.Now()) {
		http.Error(w, "SPECTRA_HELLO replay detected: client_nonce already consumed", http.StatusUnauthorized)
		return nil, fmt.Errorf("pqc: replay detected for client_nonce %s", hello.ClientNonce)
	}

	// ── Generate 32-byte server nonce ────────────────────────────────────
	serverNonceBytes := make([]byte, 32)
	if _, err := rand.Read(serverNonceBytes); err != nil {
		http.Error(w, "internal error generating server nonce", http.StatusInternalServerError)
		return nil, fmt.Errorf("pqc: server nonce generation failed: %w", err)
	}
	serverNonce := base64.StdEncoding.EncodeToString(serverNonceBytes)

	// ── Algorithm negotiation: pick strongest mutually supported KEM ─────
	selectedKEM := selectKEM(hello.SupportedKEMs)
	if selectedKEM == "" {
		http.Error(w, "no mutually supported KEM", http.StatusBadRequest)
		return nil, fmt.Errorf("pqc: no mutually supported KEM — client offered %v", hello.SupportedKEMs)
	}

	// ── Algorithm negotiation: pick strongest mutually supported DSA ─────
	selectedSig := selectSig(hello.SupportedSigs)
	if selectedSig == "" {
		http.Error(w, "no mutually supported DSA scheme", http.StatusBadRequest)
		return nil, fmt.Errorf("pqc: no mutually supported DSA — client offered %v", hello.SupportedSigs)
	}

	// ── Decode the client's speculative KEM public key share ─────────────
	kemShareBytes, err := base64.StdEncoding.DecodeString(hello.KEMShare)
	if err != nil {
		http.Error(w, "failed to decode kem_share", http.StatusBadRequest)
		return nil, fmt.Errorf("pqc: failed to decode kem_share: %w", err)
	}

	// ── KEM Encapsulation: derive shared secret + ciphertext ─────────────
	sharedSecret, ciphertextBytes, err := encapsulate(selectedKEM, kemShareBytes)
	if err != nil {
		http.Error(w, "KEM encapsulation failed", http.StatusInternalServerError)
		return nil, fmt.Errorf("pqc: KEM encapsulation failed (%s): %w", selectedKEM, err)
	}

	// ── Derive AES-256-GCM session key via HKDF-SHA256 ───────────────────
	info := fmt.Sprintf("SPECTRA-v1|%s|%s|%s|%s",
		selectedKEM, hello.ClientNonce, serverNonce, hello.ClientID)
	sessionKey, err := deriveSessionKey(sharedSecret, clientNonceBytes, []byte(info))
	if err != nil {
		http.Error(w, "session key derivation failed", http.StatusInternalServerError)
		return nil, fmt.Errorf("pqc: HKDF derivation failed: %w", err)
	}

	// ── Build transcript: SHA-256(client_nonce || server_nonce || kem_share || ciphertext) ─
	transcript := buildTranscript(clientNonceBytes, serverNonceBytes, kemShareBytes, ciphertextBytes)

	// ── Sign transcript with server's ML-DSA private key ─────────────────
	sigBytes, err := signTranscript(selectedSig, transcript)
	if err != nil {
		http.Error(w, "transcript signing failed", http.StatusInternalServerError)
		return nil, fmt.Errorf("pqc: transcript signing failed (%s): %w", selectedSig, err)
	}

	// ── Marshal server's ML-DSA public key for transmission ──────────────
	var serverPKBytes []byte
	switch selectedSig {
	case "ML-DSA-44":
		serverPKBytes, _ = serverDSA44PK.MarshalBinary()
	case "ML-DSA-65":
		serverPKBytes, _ = serverDSA65PK.MarshalBinary()
	case "ML-DSA-87":
		serverPKBytes, _ = serverDSA87PK.MarshalBinary()
	}
	serverPublicKey := base64.StdEncoding.EncodeToString(serverPKBytes)

	// ── Generate opaque session ID ────────────────────────────────────────
	sessionIDBytes := make([]byte, 24)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		http.Error(w, "session ID generation failed", http.StatusInternalServerError)
		return nil, fmt.Errorf("pqc: session ID generation failed: %w", err)
	}
	sessionID := base64.URLEncoding.EncodeToString(sessionIDBytes)

	// ── Write ServerHello JSON response ───────────────────────────────────
	serverHello := ServerHello{
		SelectedKEM:     selectedKEM,
		SelectedSig:     selectedSig,
		Ciphertext:      base64.StdEncoding.EncodeToString(ciphertextBytes),
		ServerNonce:     serverNonce,
		ServerSignature: base64.StdEncoding.EncodeToString(sigBytes),
		ServerPublicKey: serverPublicKey,
		SessionID:       sessionID,
	}

	tier := kemToTier(selectedKEM)
	log.Printf("[MOD 1 - PQC] ✓ SPECTRA_SERVER_HELLO | ClientID: %s | KEM: %s | DSA: %s | Tier: %s | Session: %s",
		hello.ClientID, selectedKEM, selectedSig, tier, sessionID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(serverHello); err != nil {
		log.Printf("[MOD 1 - PQC] WARNING: failed to write ServerHello JSON: %v", err)
	}

	return &HandshakeResult{
		KEMScheme:  selectedKEM,
		SigScheme:  selectedSig,
		Tier:       tier,
		SessionKey: sessionKey,
		SessionID:  sessionID,
	}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Client-side: BuildHello
// ────────────────────────────────────────────────────────────────────────────

// BuildHello generates a ready-to-send ClientHello for the given preferences.
// preferredKEMs and preferredSigs are ordered highest-priority first.
// The caller must keep the returned *ClientCreds to call DecapsulateServerHello.
func BuildHello(clientID string, preferredKEMs, preferredSigs []string) (*ClientCreds, error) {
	if len(preferredKEMs) == 0 {
		preferredKEMs = []string{"ML-KEM-768", "ML-KEM-512"}
	}
	if len(preferredSigs) == 0 {
		preferredSigs = []string{"ML-DSA-65", "ML-DSA-44"}
	}

	// Generate KEM keypair for the most preferred (speculative) KEM
	speculativeKEM := preferredKEMs[0]
	pkBytes, skBytes, err := generateKEMKeypair(speculativeKEM)
	if err != nil {
		return nil, fmt.Errorf("pqc: BuildHello KEM keygen failed (%s): %w", speculativeKEM, err)
	}

	// Generate 32-byte client nonce
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("pqc: failed to generate client nonce: %w", err)
	}

	hello := ClientHello{
		ClientID:      clientID,
		SupportedKEMs: preferredKEMs,
		SupportedSigs: preferredSigs,
		KEMShare:      base64.StdEncoding.EncodeToString(pkBytes),
		ClientNonce:   base64.StdEncoding.EncodeToString(nonceBytes),
		Timestamp:     time.Now().UnixNano(),
	}

	return &ClientCreds{
		Hello:         hello,
		KEMPrivateKey: skBytes,
		SelectedKEM:   speculativeKEM,
	}, nil
}

// DecapsulateServerHello verifies the server_signature against the transcript
// and decapsulates the shared secret to derive the AES-256-GCM session key.
func DecapsulateServerHello(creds *ClientCreds, sh *ServerHello) ([32]byte, error) {
	var zero [32]byte

	// Decode ciphertext
	ct, err := base64.StdEncoding.DecodeString(sh.Ciphertext)
	if err != nil {
		return zero, fmt.Errorf("pqc: malformed ciphertext in ServerHello: %w", err)
	}

	// Decapsulate → shared secret
	sharedSecret, err := decapsulate(sh.SelectedKEM, creds.KEMPrivateKey, ct)
	if err != nil {
		return zero, fmt.Errorf("pqc: KEM decapsulation failed (%s): %w", sh.SelectedKEM, err)
	}

	// Decode client kem_share bytes for transcript
	kemShareBytes, err := base64.StdEncoding.DecodeString(creds.Hello.KEMShare)
	if err != nil {
		return zero, fmt.Errorf("pqc: invalid creds KEMShare: %w", err)
	}

	// Reproduce transcript on client side (must match server's computation exactly)
	clientNonceBytes, _ := base64.StdEncoding.DecodeString(creds.Hello.ClientNonce)
	serverNonceBytes, _ := base64.StdEncoding.DecodeString(sh.ServerNonce)
	transcript := buildTranscript(clientNonceBytes, serverNonceBytes, kemShareBytes, ct)

	// Verify the server's ML-DSA signature using the server's public key
	sigBytes, err := base64.StdEncoding.DecodeString(sh.ServerSignature)
	if err != nil {
		return zero, fmt.Errorf("pqc: malformed server_signature base64: %w", err)
	}

	serverPKBytes, err := base64.StdEncoding.DecodeString(sh.ServerPublicKey)
	if err != nil || len(serverPKBytes) == 0 {
		return zero, fmt.Errorf("pqc: missing or invalid server_public_key in ServerHello: %w", err)
	}

	if err := verifyTranscriptWithKey(sh.SelectedSig, serverPKBytes, transcript, sigBytes); err != nil {
		return zero, fmt.Errorf("pqc: SERVER SIGNATURE VERIFICATION FAILED — possible MITM: %w", err)
	}

	// Derive the same AES-256-GCM session key as the server
	info := fmt.Sprintf("SPECTRA-v1|%s|%s|%s|%s",
		sh.SelectedKEM, creds.Hello.ClientNonce, sh.ServerNonce, creds.Hello.ClientID)
	sessionKey, err := deriveSessionKey(sharedSecret, clientNonceBytes, []byte(info))
	if err != nil {
		return zero, fmt.Errorf("pqc: HKDF derivation failed on client: %w", err)
	}

	log.Printf("[MOD 1 - PQC] ✓ Server signature verified | ✓ Session key derived | KEM: %s | DSA: %s",
		sh.SelectedKEM, sh.SelectedSig)
	return sessionKey, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers — KEM
// ────────────────────────────────────────────────────────────────────────────

// kemScheme returns the circl kem.Scheme for a given algorithm name.
func kemScheme(name string) (kem.Scheme, error) {
	switch name {
	case "ML-KEM-512":
		return mlkem512.Scheme(), nil
	case "ML-KEM-768":
		return mlkem768.Scheme(), nil
	case "ML-KEM-1024":
		return mlkem1024.Scheme(), nil
	default:
		return nil, fmt.Errorf("unknown KEM: %s", name)
	}
}

// encapsulate returns (sharedSecret, ciphertext).
func encapsulate(kemName string, pkBytes []byte) (sharedSecret, ciphertext []byte, err error) {
	s, err := kemScheme(kemName)
	if err != nil {
		return nil, nil, err
	}
	pk, err := s.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key for %s: %w", kemName, err)
	}
	ct, ss, err := s.Encapsulate(pk)
	return ss, ct, err
}

// decapsulate returns the shared secret from a ciphertext using the private key bytes.
func decapsulate(kemName string, skBytes, ct []byte) ([]byte, error) {
	s, err := kemScheme(kemName)
	if err != nil {
		return nil, err
	}
	sk, err := s.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key for %s: %w", kemName, err)
	}
	return s.Decapsulate(sk, ct)
}

// generateKEMKeypair generates a fresh keypair and returns (pkBytes, skBytes).
func generateKEMKeypair(kemName string) (pkBytes, skBytes []byte, err error) {
	s, err := kemScheme(kemName)
	if err != nil {
		return nil, nil, err
	}
	pk, sk, err := s.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("keygen failed for %s: %w", kemName, err)
	}
	pkB, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	skB, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pkB, skB, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers — ML-DSA signatures
// ────────────────────────────────────────────────────────────────────────────

// signTranscript signs the transcript hash with the server's appropriate ML-DSA key.
func signTranscript(sigName string, transcript []byte) ([]byte, error) {
	switch sigName {
	case "ML-DSA-44":
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(serverDSA44SK, transcript, nil, false, sig); err != nil {
			return nil, err
		}
		return sig, nil

	case "ML-DSA-65":
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(serverDSA65SK, transcript, nil, false, sig); err != nil {
			return nil, err
		}
		return sig, nil

	case "ML-DSA-87":
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(serverDSA87SK, transcript, nil, false, sig); err != nil {
			return nil, err
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("unknown DSA scheme: %s", sigName)
	}
}

// verifyTranscriptWithKey verifies an ML-DSA signature against the transcript using the provided public key bytes.
func verifyTranscriptWithKey(sigName string, pkBytes, transcript, sig []byte) error {
	switch sigName {
	case "ML-DSA-44":
		pk := new(mldsa44.PublicKey)
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return fmt.Errorf("invalid ML-DSA-44 public key: %w", err)
		}
		if !mldsa44.Verify(pk, transcript, nil, sig) {
			return fmt.Errorf("ML-DSA-44 signature verification failed")
		}
	case "ML-DSA-65":
		pk := new(mldsa65.PublicKey)
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return fmt.Errorf("invalid ML-DSA-65 public key: %w", err)
		}
		if !mldsa65.Verify(pk, transcript, nil, sig) {
			return fmt.Errorf("ML-DSA-65 signature verification failed")
		}
	case "ML-DSA-87":
		pk := new(mldsa87.PublicKey)
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return fmt.Errorf("invalid ML-DSA-87 public key: %w", err)
		}
		if !mldsa87.Verify(pk, transcript, nil, sig) {
			return fmt.Errorf("ML-DSA-87 signature verification failed")
		}
	default:
		return fmt.Errorf("unknown DSA scheme: %s", sigName)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers — Transcript & Key Derivation
// ────────────────────────────────────────────────────────────────────────────

// buildTranscript computes SHA-256(client_nonce || server_nonce || kem_share || ciphertext).
// Both server and client run this identically with binary parameters.
func buildTranscript(clientNonce, serverNonce, kemShare, ciphertext []byte) []byte {
	h := sha256.New()
	h.Write(clientNonce)
	h.Write(serverNonce)
	h.Write(kemShare)
	h.Write(ciphertext)
	return h.Sum(nil)
}

// deriveSessionKey derives a 32-byte AES-256-GCM key from the raw KEM shared
// secret using HKDF-SHA256, salted with the client nonce and bound to the info string.
func deriveSessionKey(sharedSecret, salt []byte, info []byte) ([32]byte, error) {
	var key [32]byte
	kdf := hkdf.New(sha256.New, sharedSecret, salt, info)
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return key, err
	}
	return key, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers — Algorithm selection
// ────────────────────────────────────────────────────────────────────────────

// selectKEM returns the strongest KEM supported by both sides.
// Proxy preference: ML-KEM-1024 > ML-KEM-768 > ML-KEM-512.
func selectKEM(clientOffers []string) string {
	for _, pref := range []string{"ML-KEM-1024", "ML-KEM-768", "ML-KEM-512"} {
		for _, offer := range clientOffers {
			if pref == offer {
				return pref
			}
		}
	}
	return ""
}

// selectSig returns the strongest DSA supported by both sides.
// Proxy preference: ML-DSA-87 > ML-DSA-65 > ML-DSA-44.
func selectSig(clientOffers []string) string {
	for _, pref := range []string{"ML-DSA-87", "ML-DSA-65", "ML-DSA-44"} {
		for _, offer := range clientOffers {
			if pref == offer {
				return pref
			}
		}
	}
	return ""
}

// kemToTier maps a KEM algorithm name to a human-readable tier label.
func kemToTier(kem string) string {
	switch kem {
	case "ML-KEM-512":
		return "Tier 1 — Lightweight (IoT / Edge Sensor)"
	case "ML-KEM-768":
		return "Tier 2 — Standard (Laptop / Desktop)"
	case "ML-KEM-1024":
		return "Tier 3 — High Assurance (Server / Admin)"
	default:
		return "Tier 2 — Standard"
	}
}

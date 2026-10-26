package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/SPECTRA-proxy/SPECTRA/internal/engine"
	"github.com/SPECTRA-proxy/SPECTRA/internal/pqc"
)

// ────────────────────────────────────────────────────────────────────────────
// Proxy-side session key store
// Stores AES-256-GCM session keys indexed by session ID.
// Populated by POST /spectra/hello; consumed by POST /spectra/relay.
// ────────────────────────────────────────────────────────────────────────────

type keyStore struct {
	mu   sync.RWMutex
	keys map[string][32]byte // sessionID → AES-256-GCM key
	meta map[string]string   // sessionID → "KEM / DSA" label
}

func newKeyStore() *keyStore {
	return &keyStore{
		keys: make(map[string][32]byte),
		meta: make(map[string]string),
	}
}

func (ks *keyStore) Store(sessionID string, key [32]byte, scheme string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[sessionID] = key
	ks.meta[sessionID] = scheme
}

func (ks *keyStore) Load(sessionID string) ([32]byte, string, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, ok := ks.keys[sessionID]
	return k, ks.meta[sessionID], ok
}

// ────────────────────────────────────────────────────────────────────────────
// Mock upstream micro-service
// ────────────────────────────────────────────────────────────────────────────

func startMockUpstream(port string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "═══════════════════════════════════════════\n")
		fmt.Fprintf(w, "  SPECTRA PROTECTED MICRO-SERVICE          \n")
		fmt.Fprintf(w, "═══════════════════════════════════════════\n")
		fmt.Fprintf(w, "Status            : Upstream OK ✓\n")
		fmt.Fprintf(w, "Handshake Protocol: %s\n", r.Header.Get("X-Spectra-PQC"))
		fmt.Fprintf(w, "PQC Tier          : %s\n", r.Header.Get("X-Spectra-PQC-Tier"))
		fmt.Fprintf(w, "Telemetry Risk    : %s\n", r.Header.Get("X-Spectra-Risk-Score"))
		fmt.Fprintf(w, "Transport Layer   : %s\n", r.Header.Get("X-Spectra-Encrypted"))
		fmt.Fprintf(w, "Method            : %s\n", r.Method)
		fmt.Fprintf(w, "Path              : %s\n", r.URL.Path)
	})

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	log.Printf("[Mock Backend] Upstream service active on http://127.0.0.1:%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Mock backend failed: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────────

func main() {
	proxyPort    := flag.String("port", "8443", "Port for SPECTRA proxy to listen on")
	upstreamPort := flag.String("upstream", "9000", "Port of backend micro-service")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// ── 1. Start mock upstream ────────────────────────────────────────────
	go startMockUpstream(*upstreamPort)
	time.Sleep(100 * time.Millisecond)

	// ── 2. Build the SPECTRA proxy engine ─────────────────────────────────
	upstreamURL := fmt.Sprintf("http://127.0.0.1:%s", *upstreamPort)
	spectra, err := engine.NewSpectraProxy(upstreamURL)
	if err != nil {
		log.Fatalf("Proxy initialization error: %v", err)
	}

	// ── 3. Shared session key store ───────────────────────────────────────
	ks := newKeyStore()

	// ── 4. Build the HTTP mux ─────────────────────────────────────────────
	mux := newProxyMux(spectra, ks)

	// ── 5. Print startup banner ───────────────────────────────────────────
	log.Println("══════════════════════════════════════════════════════════════")
	log.Println("  SPECTRA Edge Zero-Trust Reverse Proxy Engine")
	log.Printf("  Listening on     : http://0.0.0.0:%s", *proxyPort)
	log.Printf("  Upstream target  : %s", upstreamURL)
	log.Println("  PQC Engine       : cloudflare/circl (native Go — no Python) ✓")
	log.Println("  Handshake        : POST /spectra/hello  (SPECTRA_HELLO 1-RTT)")
	log.Println("  Encrypted relay  : POST /spectra/relay  (AES-256-GCM)")
	log.Println("  Plain HTTP       : GET|POST /* (browser / curl)")
	log.Println("══════════════════════════════════════════════════════════════")

	if err := http.ListenAndServe(":"+*proxyPort, mux); err != nil {
		log.Fatalf("Proxy server failed: %v", err)
	}
}

// newProxyMux wires the SPECTRA proxy endpoints:
//   - POST /spectra/hello (1-RTT PQC handshake)
//   - POST /spectra/relay (AES-256-GCM encrypted relay)
//   - Catch-all / (plain HTTP proxying with PQC fallback)
func newProxyMux(spectra *engine.SpectraProxy, ks *keyStore) http.Handler {
	mux := http.NewServeMux()

	// POST /spectra/hello — 1-RTT PQC handshake (SPECTRA Client Connector)
	mux.HandleFunc("/spectra/hello", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		result, err := pqc.HandleHello(w, r)
		if err != nil {
			log.Printf("[MOD 1 - PQC] HELLO REJECTED: %v", err)
			return
		}
		scheme := fmt.Sprintf("%s / %s", result.KEMScheme, result.SigScheme)
		ks.Store(result.SessionID, result.SessionKey, scheme)
	})

	// POST /spectra/relay — receive AES-256-GCM encrypted HTTP payload from Connector
	mux.HandleFunc("/spectra/relay", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sessionID := r.Header.Get("X-Spectra-Session-ID")
		if sessionID == "" {
			http.Error(w, "missing X-Spectra-Session-ID header", http.StatusUnauthorized)
			return
		}

		aesKey, scheme, ok := ks.Load(sessionID)
		if !ok {
			log.Printf("[MOD 1 - PQC] RELAY REJECTED: unknown session ID %s", sessionID)
			http.Error(w, "unknown session — perform /spectra/hello first", http.StatusUnauthorized)
			return
		}

		// Read the encrypted body
		sealed, err := io.ReadAll(io.LimitReader(r.Body, 20*1024*1024))
		if err != nil {
			http.Error(w, "failed to read relay body", http.StatusInternalServerError)
			return
		}

		// AES-256-GCM decrypt — authentication tag is verified inside Open()
		plaintext, err := pqc.Open(aesKey, sealed)
		if err != nil {
			log.Printf("[MOD 1 - PQC] RELAY DECRYPT FAILED session %s: %v", sessionID, err)
			http.Error(w, "integrity check failed — possible tampering", http.StatusForbidden)
			return
		}

		log.Printf("[MOD 1 - PQC] ✓ Relay decrypted | session: %s | scheme: %s | %d bytes",
			sessionID, scheme, len(plaintext))

		// Parse the decrypted plaintext as a raw HTTP/1.1 request
		syntheticReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(plaintext)))
		if err != nil {
			log.Printf("[MOD 1 - PQC] RELAY: cannot parse decrypted request: %v", err)
			http.Error(w, "malformed decrypted HTTP request", http.StatusBadRequest)
			return
		}

		// Inject context headers so the engine treats this as a pre-negotiated session
		syntheticReq.Header.Set("X-Spectra-Session-ID", sessionID)
		syntheticReq.Header.Set("X-Session-ID", sessionID)
		syntheticReq.Header.Set("X-Spectra-PQC-Scheme", scheme)
		syntheticReq.Header.Set("X-Spectra-Encrypted", "AES-256-GCM")
		syntheticReq.RemoteAddr = r.RemoteAddr
		// Clear RequestURI so reverse proxy director functions properly
		syntheticReq.RequestURI = ""

		// Capture response from the SPECTRA engine (IDS + risk scoring + upstream routing)
		rec := httptest.NewRecorder()
		spectra.ServeHTTP(rec, syntheticReq)

		// Serialize captured response (status code, headers, body) to HTTP/1.1 wire format
		resp := rec.Result()
		defer resp.Body.Close()

		var rawRespBuf bytes.Buffer
		if err := resp.Write(&rawRespBuf); err != nil {
			log.Printf("[MOD 1 - PQC] RELAY: failed to serialize response: %v", err)
			http.Error(w, "internal server error serializing response", http.StatusInternalServerError)
			return
		}

		// Encrypt response payload using AES-256-GCM with the PQC session key
		sealedResp, err := pqc.Seal(aesKey, rawRespBuf.Bytes())
		if err != nil {
			log.Printf("[MOD 1 - PQC] RELAY ENCRYPT FAILED session %s: %v", sessionID, err)
			http.Error(w, "failed to encrypt response payload", http.StatusInternalServerError)
			return
		}

		log.Printf("[MOD 1 - PQC] ✓ Response encrypted | session: %s | %d raw bytes -> %d encrypted bytes",
			sessionID, rawRespBuf.Len(), len(sealedResp))

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Spectra-Session-ID", sessionID)
		w.Header().Set("X-Spectra-Encrypted", "AES-256-GCM")
		w.WriteHeader(http.StatusOK)
		w.Write(sealedResp)
	})

	// Catch-all: plain HTTP from browsers / curl / dev tools
	mux.HandleFunc("/", spectra.ServeHTTP)

	return mux
}
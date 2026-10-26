// SPECTRA Client Connector — cmd/client/main.go
//
// The Client Connector is a local proxy that sits between the user's application
// (e.g. curl, a browser, or any HTTP client) and the SPECTRA reverse proxy.
//
// Architecture:
//
//	[curl / browser]
//	    │  plain HTTP on localhost:8080
//	    ▼
//	[SPECTRA Client Connector] ← THIS BINARY
//	    │  1. Self-benchmark (500ms): selects Tier 1/2/3 from device capability
//	    │  2. POST /spectra/hello → SPECTRA Proxy (:8443) — 1-RTT PQC handshake
//	    │  3. Decapsulate + verify server signature → derive AES-256-GCM session key
//	    │  4. For every inbound HTTP request from curl/browser:
//	    │       Encrypt full HTTP payload using AES-256-GCM
//	    │       POST encrypted blob to http://proxy:8443/spectra/relay
//	    ▼
//	[SPECTRA Reverse Proxy (:8443)]
//	    │  Decrypt, IDS inspect, risk-score, forward to upstream (:9000)
//	    ▼
//	[Upstream Micro-Service (:9000)]
//
// Usage:
//
//	Terminal 1: go run ./cmd/proxy
//	Terminal 2: go run ./cmd/client --proxy http://127.0.0.1:8443 --listen :8080
//	Terminal 3: curl http://localhost:8080/api/hello
package main

import (
	"bytes"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
	"crypto/rand"

	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"

	"github.com/SPECTRA-proxy/SPECTRA/internal/pqc"
)

// ────────────────────────────────────────────────────────────────────────────
// Benchmark constants
// ────────────────────────────────────────────────────────────────────────────

const (
	benchDuration   = 500 * time.Millisecond
	kemLatencyLimit = 10 * time.Millisecond // if KEM round-trip exceeds this, downgrade tier
)

// ────────────────────────────────────────────────────────────────────────────
// Connector state
// ────────────────────────────────────────────────────────────────────────────

type Connector struct {
	proxyAddr  string   // e.g. "http://127.0.0.1:8443"
	clientID   string   // device fingerprint (MAC or random)
	sessionID  string   // assigned by proxy in ServerHello
	sessionKey [32]byte // AES-256-GCM key
	kemScheme  string   // negotiated KEM
	sigScheme  string   // negotiated DSA
	tier       string   // e.g. "Tier 2 — Standard"
}

// ────────────────────────────────────────────────────────────────────────────
// Step 1: Self-Benchmark — picks the strongest PQC tier this device can sustain
// ────────────────────────────────────────────────────────────────────────────

func benchmark() (preferredKEMs, preferredSigs []string) {
	log.Println("[Benchmark] Running 500ms PQC capability self-test...")

	// ── Test ML-KEM-1024 (Tier 3 — High Assurance) ───────────────────────
	s1024 := mlkem1024.Scheme()
	start := time.Now()
	ops := 0
	for time.Since(start) < benchDuration {
		pk, sk, _ := s1024.GenerateKeyPair()
		ct, _, _ := s1024.Encapsulate(pk)
		s1024.Decapsulate(sk, ct)
		ops++
	}
	lat1024 := benchDuration / time.Duration(max(ops, 1))
	log.Printf("[Benchmark] ML-KEM-1024: %d ops → avg %v per op", ops, lat1024)

	if lat1024 <= kemLatencyLimit {
		log.Println("[Benchmark] ✓ Tier 3 selected — ML-KEM-1024 / ML-DSA-87")
		return []string{"ML-KEM-1024", "ML-KEM-768", "ML-KEM-512"},
			[]string{"ML-DSA-87", "ML-DSA-65", "ML-DSA-44"}
	}

	// ── Test ML-KEM-768 (Tier 2 — Standard) ──────────────────────────────
	s768 := mlkem768.Scheme()
	start = time.Now()
	ops = 0
	for time.Since(start) < benchDuration {
		pk, sk, _ := s768.GenerateKeyPair()
		ct, _, _ := s768.Encapsulate(pk)
		s768.Decapsulate(sk, ct)
		ops++
	}
	lat768 := benchDuration / time.Duration(max(ops, 1))
	log.Printf("[Benchmark] ML-KEM-768:  %d ops → avg %v per op", ops, lat768)

	if lat768 <= kemLatencyLimit {
		log.Println("[Benchmark] ✓ Tier 2 selected — ML-KEM-768 / ML-DSA-65")
		return []string{"ML-KEM-768", "ML-KEM-512"},
			[]string{"ML-DSA-65", "ML-DSA-44"}
	}

	// ── Fallback: ML-KEM-512 (Tier 1 — Lightweight) ──────────────────────
	s512 := mlkem512.Scheme()
	start = time.Now()
	ops = 0
	for time.Since(start) < benchDuration {
		pk, sk, _ := s512.GenerateKeyPair()
		ct, _, _ := s512.Encapsulate(pk)
		s512.Decapsulate(sk, ct)
		ops++
	}
	log.Printf("[Benchmark] ML-KEM-512:  %d ops in 500ms", ops)
	log.Println("[Benchmark] ✓ Tier 1 selected — ML-KEM-512 / ML-DSA-44")
	return []string{"ML-KEM-512"}, []string{"ML-DSA-44"}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ────────────────────────────────────────────────────────────────────────────
// Step 2 + 3: SPECTRA_HELLO negotiation
// ────────────────────────────────────────────────────────────────────────────

func (c *Connector) doHandshake(preferredKEMs, preferredSigs []string) error {
	// Build the ClientHello with a speculative KEM pre-share
	creds, err := pqc.BuildHello(c.clientID, preferredKEMs, preferredSigs)
	if err != nil {
		return fmt.Errorf("BuildHello failed: %w", err)
	}

	helloBody, err := json.Marshal(creds.Hello)
	if err != nil {
		return fmt.Errorf("JSON encode failed: %w", err)
	}

	log.Printf("[Handshake] → SPECTRA_HELLO to %s/spectra/hello", c.proxyAddr)
	log.Printf("[Handshake]   ClientID    : %s", creds.Hello.ClientID)
	log.Printf("[Handshake]   Offered KEMs: %v", creds.Hello.SupportedKEMs)
	log.Printf("[Handshake]   Offered SIGs: %v", creds.Hello.SupportedSigs)

	resp, err := http.Post(c.proxyAddr+"/spectra/hello",
		"application/json", bytes.NewReader(helloBody))
	if err != nil {
		return fmt.Errorf("POST /spectra/hello failed: %w", err)
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading ServerHello failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy rejected SPECTRA_HELLO (HTTP %d): %s",
			resp.StatusCode, string(rawResp))
	}

	var serverHello pqc.ServerHello
	if err := json.Unmarshal(rawResp, &serverHello); err != nil {
		return fmt.Errorf("failed to decode ServerHello: %w", err)
	}

	log.Printf("[Handshake] ← SPECTRA_SERVER_HELLO received")
	log.Printf("[Handshake]   Selected KEM : %s", serverHello.SelectedKEM)
	log.Printf("[Handshake]   Selected DSA : %s", serverHello.SelectedSig)
	log.Printf("[Handshake]   Session ID   : %s", serverHello.SessionID)

	// Step 3: Decapsulate shared secret + verify server ML-DSA signature + derive key
	sessionKey, err := pqc.DecapsulateServerHello(creds, &serverHello)
	if err != nil {
		return fmt.Errorf("DecapsulateServerHello failed: %w", err)
	}

	c.sessionID = serverHello.SessionID
	c.sessionKey = sessionKey
	c.kemScheme = serverHello.SelectedKEM
	c.sigScheme = serverHello.SelectedSig
	c.tier = kemToTierLabel(serverHello.SelectedKEM)
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Step 4: Local proxy — encrypt each inbound request and relay to the proxy
// ────────────────────────────────────────────────────────────────────────────

func (c *Connector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read the full incoming plaintext request body
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "connector: failed to read request body", http.StatusInternalServerError)
		return
	}

	// Determine URI reliably
	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.RequestURI()
		if uri == "" {
			uri = "/"
		}
	}

	// Serialize HTTP request (method + path + headers + body) as plaintext payload.
	// Format mirrors raw HTTP/1.1 so the proxy can reconstruct a synthetic request.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", r.Method, uri)
	fmt.Fprintf(&buf, "Host: %s\r\n", r.Host)
	for k, vv := range r.Header {
		for _, v := range vv {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	buf.WriteString("\r\n")
	buf.Write(rawBody)
	plaintext := buf.Bytes()

	// AES-256-GCM encrypt
	sealed, err := pqc.Seal(c.sessionKey, plaintext)
	if err != nil {
		http.Error(w, "connector: AES-GCM encryption failed", http.StatusInternalServerError)
		log.Printf("[Connector] ENCRYPT ERROR: %v", err)
		return
	}

	// POST encrypted blob to /spectra/relay on the SPECTRA proxy
	req, err := http.NewRequest(http.MethodPost, c.proxyAddr+"/spectra/relay",
		bytes.NewReader(sealed))
	if err != nil {
		http.Error(w, "connector: failed to build relay request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Spectra-Session-ID", c.sessionID)
	req.Header.Set("X-Spectra-PQC-Scheme", fmt.Sprintf("%s / %s", c.kemScheme, c.sigScheme))
	req.Header.Set("X-Spectra-Tier", c.tier)

	relayResp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "connector: relay to proxy failed", http.StatusBadGateway)
		log.Printf("[Connector] RELAY ERROR: %v", err)
		return
	}
	defer relayResp.Body.Close()

	// If proxy rejected the relay request with non-200 (e.g. unknown session or tampering before decryption)
	if relayResp.StatusCode != http.StatusOK {
		for k, vv := range relayResp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(relayResp.StatusCode)
		io.Copy(w, relayResp.Body)
		return
	}

	// Read encrypted response payload
	sealedResp, err := io.ReadAll(io.LimitReader(relayResp.Body, 20*1024*1024))
	if err != nil {
		http.Error(w, "connector: failed to read relay response body", http.StatusBadGateway)
		return
	}

	// Decrypt response using AES-256-GCM with the PQC session key
	plainRespBytes, err := pqc.Open(c.sessionKey, sealedResp)
	if err != nil {
		log.Printf("[Connector] DECRYPT FAILED: response tampered or key mismatch: %v", err)
		http.Error(w, "connector: proxy response integrity check failed — tampering detected", http.StatusBadGateway)
		return
	}

	// Parse the decrypted raw HTTP response
	decryptedResp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(plainRespBytes)), r)
	if err != nil {
		log.Printf("[Connector] PARSE ERROR: failed to parse decrypted response: %v", err)
		http.Error(w, "connector: malformed decrypted response from proxy", http.StatusBadGateway)
		return
	}
	defer decryptedResp.Body.Close()

	// Forward decrypted status, headers, and body to the local caller
	for k, vv := range decryptedResp.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(decryptedResp.StatusCode)
	io.Copy(w, decryptedResp.Body)

	log.Printf("[Connector] ✓ Relayed %s %s → HTTP %d (bidirectional PQC decrypted) | %s / %s",
		r.Method, uri, decryptedResp.StatusCode, c.kemScheme, c.sigScheme)
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func deviceClientID() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				if mac := iface.HardwareAddr.String(); mac != "" {
					return mac
				}
			}
		}
	}
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("anon-%x", b)
}

func kemToTierLabel(kem string) string {
	switch kem {
	case "ML-KEM-512":
		return "Tier 1 — Lightweight"
	case "ML-KEM-768":
		return "Tier 2 — Standard"
	case "ML-KEM-1024":
		return "Tier 3 — High Assurance"
	default:
		return "Tier 2 — Standard"
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────────────

func main() {
	listenAddr := flag.String("listen", ":8080", "Local address for connector to listen on")
	proxyAddr  := flag.String("proxy", "http://127.0.0.1:8443", "Address of the SPECTRA reverse proxy")
	skipBench  := flag.Bool("skip-bench", false, "Skip benchmark and use Tier 2 (ML-KEM-768)")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("══════════════════════════════════════════════════════")
	log.Println("  SPECTRA Client Connector")
	log.Printf("  Local proxy  : http://localhost%s", *listenAddr)
	log.Printf("  Proxy target : %s", *proxyAddr)
	log.Printf("  Runtime      : %s | %s/%s",
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
	log.Println("══════════════════════════════════════════════════════")

	clientID := deviceClientID()
	log.Printf("[Init] Device client ID : %s", clientID)

	// ── Step 1: Self-benchmark ─────────────────────────────────────────────
	var preferredKEMs, preferredSigs []string
	if *skipBench {
		log.Println("[Init] Skipping benchmark — using Tier 2 (ML-KEM-768 / ML-DSA-65)")
		preferredKEMs = []string{"ML-KEM-768", "ML-KEM-512"}
		preferredSigs = []string{"ML-DSA-65", "ML-DSA-44"}
	} else {
		preferredKEMs, preferredSigs = benchmark()
	}

	conn := &Connector{
		proxyAddr: *proxyAddr,
		clientID:  clientID,
	}

	// ── Step 2 + 3: SPECTRA_HELLO PQC handshake ───────────────────────────
	if err := conn.doHandshake(preferredKEMs, preferredSigs); err != nil {
		log.Fatalf("[Handshake] FATAL: %v", err)
		os.Exit(1)
	}

	log.Println("══════════════════════════════════════════════════════")
	log.Printf("[Ready] Session : %s", conn.sessionID)
	log.Printf("[Ready] PQC     : %s / %s | %s", conn.kemScheme, conn.sigScheme, conn.tier)
	log.Printf("[Ready] Routing : curl http://localhost%s/<path>", *listenAddr)
	log.Println("══════════════════════════════════════════════════════")

	// ── Step 4: Local plaintext → AES-encrypted relay ─────────────────────
	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      conn,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[Connector] Server error: %v", err)
	}
}

// ensure bufio is imported for potential use in future extension
var _ = bufio.NewReader

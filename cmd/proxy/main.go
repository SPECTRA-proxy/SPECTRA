package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/SPECTRA-proxy/SPECTRA/internal/engine"
)

func startMockUpstream(port string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pqcScheme := r.Header.Get("X-Spectra-PQC")
		riskScore := r.Header.Get("X-Spectra-Risk-Score")
		
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "=== SPECTRA PROTECTED MICRO-SERVICE ===\n")
		fmt.Fprintf(w, "Status: Upstream request successfully received\n")
		fmt.Fprintf(w, "Handshake Protocol : %s\n", pqcScheme)
		fmt.Fprintf(w, "Telemetry Risk Score: %s\n", riskScore)
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

func main() {
	proxyPort := flag.String("port", "8443", "Port for SPECTRA proxy to listen on")
	upstreamPort := flag.String("upstream", "9000", "Port of backend micro-service")
	flag.Parse()

	// Launch local mock upstream micro-service in background goroutine
	go startMockUpstream(*upstreamPort)

	// Wait 500ms for mock service to bind
	time.Sleep(500 * time.Millisecond)

	upstreamURL := fmt.Sprintf("http://127.0.0.1:%s", *upstreamPort)
	spectra, err := engine.NewSpectraProxy(upstreamURL)
	if err != nil {
		log.Fatalf("Initialization error: %v", err)
	}

	serverAddr := ":" + *proxyPort
	log.Printf("==================================================")
	log.Printf("  SPECTRA Edge Zero-Trust Reverse Proxy Engine    ")
	log.Printf("  Listening on http://0.0.0.0:%s                 ", *proxyPort)
	log.Printf("  Routing target: %s                              ", upstreamURL)
	log.Printf("==================================================")

	if err := http.ListenAndServe(serverAddr, spectra); err != nil {
		log.Fatalf("Proxy server failed: %v", err)
	}
}
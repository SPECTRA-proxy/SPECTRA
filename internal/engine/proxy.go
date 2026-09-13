package engine

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/SPECTRA-proxy/SPECTRA/internal/stubs"
)

type SpectraProxy struct {
	UpstreamURL *url.URL
	ReverseProxy *httputil.ReverseProxy
}

func NewSpectraProxy(upstreamTarget string) (*SpectraProxy, error) {
	target, err := url.Parse(upstreamTarget)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	return &SpectraProxy{
		UpstreamURL:  target,
		ReverseProxy: proxy,
	}, nil
}

func (sp *SpectraProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[MOD 2 - Engine] Inbound request intercepted: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Step 1: Module 1 Validation (Adaptive PQC Handshake)
	validPQC, scheme := stubs.VerifyPQC(r)
	if !validPQC {
		http.Error(w, "Access Denied: Quantum Cryptographic Handshake Failed", http.StatusUnauthorized)
		return
	}

	// Step 2: Module 3 Telemetry Interception (eBPF Kernel Layer)
	telemetry := stubs.ExtractKernelTelemetry(r)

	// Step 3: Module 4 Risk Scoring (AI Behavior Evaluation)
	riskScore, allowed := stubs.EvaluateRisk(telemetry)
	if !allowed {
		log.Printf("[MOD 2 - Enforcement] Dropping connection. Risk score %.2f exceeds policy threshold", riskScore)
		http.Error(w, "Access Denied: Zero-Trust Policy Threshold Breached", http.StatusForbidden)
		return
	}

	// Step 4: Inject Zero-Trust Verification Headers for upstream service
	r.Header.Set("X-Spectra-Verified", "true")
	r.Header.Set("X-Spectra-PQC", scheme)
	r.Header.Set("X-Spectra-Risk-Score", fmt.Sprintf("%.2f", riskScore))

	// Step 5: Policy Enforced Upstream Routing
	log.Printf("[MOD 2 - Router] Policy check passed. Forwarding to micro-service -> %s", sp.UpstreamURL.String())
	sp.ReverseProxy.ServeHTTP(w, r)
}
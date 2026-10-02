package engine

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/SPECTRA-proxy/SPECTRA/internal/stubs"
)

// Zero-Trust Policy Thresholds (Graduated Response)
const (
	ThresholdStepUp    = 0.40 // Moderate risk: trigger Step-Up MFA challenge
	ThresholdTerminate = 0.70 // Severe risk: immediate session termination
)

type SpectraProxy struct {
	UpstreamURL  *url.URL
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
	riskScore := stubs.EvaluateRisk(telemetry)

	// Step 4: Graduated Policy Enforcement (3-Tier Zero-Trust Response)
	switch {

	// TIER 3 — SEVERE RISK (>= 0.70): Immediate Session Termination
	case riskScore >= ThresholdTerminate:
		log.Printf("[MOD 2 - Enforcement] TERMINATE: Risk score %.2f exceeds severe threshold (%.2f). Dropping connection.",
			riskScore, ThresholdTerminate)
		http.Error(w, "Access Denied: Zero-Trust Policy Threshold Breached — Session Terminated", http.StatusForbidden)
		return

	// TIER 2 — MODERATE RISK (0.40 - 0.69): Step-Up MFA Challenge
	case riskScore >= ThresholdStepUp:
		log.Printf("[MOD 2 - Enforcement] CHALLENGE: Risk score %.2f exceeds step-up threshold (%.2f). Requesting MFA re-authentication.",
			riskScore, ThresholdStepUp)
		w.Header().Set("WWW-Authenticate", "SPECTRA-MFA")
		w.Header().Set("X-Spectra-Risk-Score", fmt.Sprintf("%.2f", riskScore))
		w.Header().Set("X-Spectra-Challenge-Reason", telemetry.AnomalyCategory)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Step-Up Authentication Required\n")
		fmt.Fprintf(w, "Moderate behavioral anomaly detected (Score: %.2f)\n", riskScore)
		fmt.Fprintf(w, "Anomaly: %s\n", telemetry.AnomalyCategory)
		fmt.Fprintf(w, "Re-authenticate with MFA to proceed.\n")
		return

	// TIER 1 — LOW RISK (< 0.40): Clean Traffic — Forward to Upstream
	default:
		log.Printf("[MOD 2 - Enforcement] PASS: Risk score %.2f within safe threshold (< %.2f). Traffic cleared.",
			riskScore, ThresholdStepUp)
	}

	// Step 5: Inject Zero-Trust Verification Headers for upstream service
	r.Header.Set("X-Spectra-Verified", "true")
	r.Header.Set("X-Spectra-PQC", scheme)
	r.Header.Set("X-Spectra-Risk-Score", fmt.Sprintf("%.2f", riskScore))

	// Step 6: Policy Enforced Upstream Routing
	log.Printf("[MOD 2 - Router] Policy check passed. Forwarding to micro-service -> %s", sp.UpstreamURL.String())
	sp.ReverseProxy.ServeHTTP(w, r)
}
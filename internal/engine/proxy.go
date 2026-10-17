package engine

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/SPECTRA-proxy/SPECTRA/internal/ids"
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
	Sessions     *SessionStore
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
		Sessions:     NewSessionStore(),
	}, nil
}

func (sp *SpectraProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	effectiveIP := GetEffectiveClientIP(r)
	log.Printf("[MOD 2 - Engine] Inbound request intercepted: %s %s from %s (Effective IP: %s)",
		r.Method, r.URL.Path, r.RemoteAddr, effectiveIP)

	// Step 0: Handle Step-Up MFA Verification Endpoint
	if r.URL.Path == "/spectra/verify-mfa" && (r.Method == http.MethodPost || r.Method == http.MethodGet) {
		sessionID := ExtractSessionID(r)
		if sessionID == "" {
			http.Error(w, "Missing X-Session-ID header or session cookie", http.StatusBadRequest)
			return
		}

		sp.Sessions.VerifyMFA(sessionID, effectiveIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"MFA_VERIFIED","session_id":"%s","bound_ip":"%s","message":"Identity re-verified. Session bound to new network."}`+"\n",
			sessionID, effectiveIP)
		return
	}

	// Step 1: Module 1 Validation (Adaptive PQC Handshake)
	validPQC, scheme := stubs.VerifyPQC(r)
	if !validPQC {
		http.Error(w, "Access Denied: Quantum Cryptographic Handshake Failed", http.StatusUnauthorized)
		return
	}

	// Step 1.5: Module 3 L7 Deep Packet Inspection (Fast-Path Static Coarse Filter)
	idsAlert := ids.InspectRequest(r)
	if idsAlert != nil && idsAlert.Matched && (idsAlert.Severity == ids.SeverityCritical || idsAlert.Severity == ids.SeverityHigh) {
		log.Printf("[MOD 3 - IDS Fast-Path] CRITICAL EXPLOIT DROPPED: Rule %d [%s: %s] in %s. Short-circuiting connection.",
			idsAlert.RuleID, idsAlert.Category, idsAlert.Description, idsAlert.Location)
		w.Header().Set("X-Spectra-IDS-Rule", fmt.Sprintf("%d", idsAlert.RuleID))
		w.Header().Set("X-Spectra-IDS-Category", idsAlert.Category)
		http.Error(w, fmt.Sprintf("Access Denied: Zero-Trust Exploit Signature Detected [%s: Rule %d (%s)]",
			idsAlert.Category, idsAlert.RuleID, idsAlert.Description), http.StatusForbidden)
		return
	}

	// Step 2: Session Tracking & State Verification (Continuous Zero-Trust)
	sessionID := ExtractSessionID(r)
	if sessionID == "" {
		sessionID = "anon-" + effectiveIP
	}
	sess, _, ipMismatch := sp.Sessions.GetOrCreate(sessionID, effectiveIP, scheme)

	// Step 3: Module 3 Telemetry Interception (eBPF Kernel Layer)
	telemetry := stubs.ExtractKernelTelemetry(r)

	// If IP shifted mid-session without MFA, flag it as an anomaly!
	if ipMismatch {
		telemetry.AnomalyCategory = "Network Roaming (IP Shift)"
		telemetry.DetectedThreat = fmt.Sprintf("Session %s IP shifted from %s to %s", sess.ID, sess.BoundIP, effectiveIP)
		log.Printf("[MOD 2 - Session] ANOMALY: %s — Flagging for Step-Up Verification", telemetry.DetectedThreat)
	}

	// Step 4: Module 4 Risk Scoring (AI Behavior Evaluation)
	riskScore := stubs.EvaluateRisk(telemetry)
	if ipMismatch && riskScore < ThresholdStepUp {
		riskScore = 0.55 // IP mismatch guarantees at least moderate risk (Step-Up MFA)
	}

	// Step 5: Graduated Policy Enforcement (3-Tier Zero-Trust Response)
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
		w.Header().Set("X-Spectra-Session-ID", sess.ID)
		w.Header().Set("X-Spectra-Risk-Score", fmt.Sprintf("%.2f", riskScore))
		w.Header().Set("X-Spectra-Challenge-Reason", telemetry.AnomalyCategory)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Step-Up Authentication Required\n")
		fmt.Fprintf(w, "Moderate behavioral anomaly detected (Score: %.2f)\n", riskScore)
		fmt.Fprintf(w, "Anomaly: %s\n", telemetry.AnomalyCategory)
		fmt.Fprintf(w, "Session ID: %s | Re-authenticate via POST /spectra/verify-mfa to proceed.\n", sess.ID)
		return

	// TIER 1 — LOW RISK (< 0.40): Clean Traffic — Forward to Upstream
	default:
		log.Printf("[MOD 2 - Enforcement] PASS: Risk score %.2f within safe threshold (< %.2f). Traffic cleared.",
			riskScore, ThresholdStepUp)
	}

	// Step 6: Inject Zero-Trust Verification Headers for upstream service
	r.Header.Set("X-Spectra-Verified", "true")
	r.Header.Set("X-Spectra-Session-ID", sess.ID)
	r.Header.Set("X-Spectra-PQC", scheme)
	r.Header.Set("X-Spectra-Risk-Score", fmt.Sprintf("%.2f", riskScore))

	// Step 7: Policy Enforced Upstream Routing
	log.Printf("[MOD 2 - Router] Policy check passed. Forwarding to micro-service -> %s", sp.UpstreamURL.String())
	sp.ReverseProxy.ServeHTTP(w, r)
}
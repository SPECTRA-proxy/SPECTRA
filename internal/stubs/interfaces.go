package stubs

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// TelemetryVector represents features extracted by eBPF & IDS (Module 3)
type TelemetryVector struct {
	SourceIP        string
	DestPort        string
	PacketSize      int64
	Timestamp       time.Time
	CapturedHook    string
	DetectedThreat  string // Ingested from IDS / Deep-Packet Inspection
	AnomalyCategory string // e.g. "Payload-level exploit", "Abnormal access pattern"
}

// VerifyPQC simulates Module 1 (Adaptive PQC Transport Layer)
func VerifyPQC(r *http.Request) (bool, string) {
	// In Review 1 MVP: Check for client handshake headers or mock verification
	scheme := r.Header.Get("X-PQC-Scheme")
	if strings.EqualFold(scheme, "none") || strings.EqualFold(scheme, "rsa") || strings.EqualFold(scheme, "insecure") {
		log.Printf("[MOD 1 - PQC] REJECTED: Non-quantum safe handshake detected (%s). PQC mandatory.", scheme)
		return false, scheme
	}

	if scheme == "" {
		scheme = "ML-KEM-768 (Default Simulated)"
	}
	log.Printf("[MOD 1 - PQC] Validated quantum-safe handshake using: %s", scheme)
	return true, scheme
}

// ExtractKernelTelemetry simulates Module 3 (Kernel Telemetry / eBPF & IDS)
func ExtractKernelTelemetry(r *http.Request) TelemetryVector {
	vec := TelemetryVector{
		SourceIP:     r.RemoteAddr,
		DestPort:     "8443",
		PacketSize:   r.ContentLength,
		Timestamp:    time.Now(),
		CapturedHook: "kprobe/sock_recvmsg",
	}

	// Detect simulated attack vectors / anomalies (via header, query param, or path)
	threatHeader := r.Header.Get("X-Threat-Signature")
	anomalyLevel := r.Header.Get("X-Anomaly-Level")
	threatQuery := r.URL.Query().Get("threat")
	path := strings.ToLower(r.URL.Path)

	// Priority 1: Confirmed exploit signatures (HIGH severity)
	if threatHeader != "" {
		vec.DetectedThreat = threatHeader
		vec.AnomalyCategory = "Payload-level exploit"
	} else if threatQuery != "" {
		vec.DetectedThreat = threatQuery
		vec.AnomalyCategory = "Abnormal access pattern"
	} else if strings.Contains(path, "exploit") || strings.Contains(path, "malicious") || strings.Contains(path, "attack") {
		vec.DetectedThreat = "SIG_CVE_DEEP_PACKET_ANOMALY"
		vec.AnomalyCategory = "Payload-level exploit"

	// Priority 2: Moderate behavioral anomalies (MEDIUM severity)
	} else if strings.EqualFold(anomalyLevel, "moderate") || strings.EqualFold(anomalyLevel, "medium") {
		vec.DetectedThreat = "BEHAVIORAL_DRIFT_DETECTED"
		vec.AnomalyCategory = "Behavioral anomaly"
	} else if strings.Contains(path, "/admin") || strings.Contains(path, "/debug") || strings.Contains(path, "/internal") {
		vec.DetectedThreat = "SENSITIVE_ENDPOINT_PROBE"
		vec.AnomalyCategory = "Suspicious access pattern"
	}

	if vec.DetectedThreat != "" {
		log.Printf("[MOD 3 - eBPF/IDS] ALERT: Ingested signature [%s | %s] on socket %s",
			vec.AnomalyCategory, vec.DetectedThreat, vec.SourceIP)
	} else {
		log.Printf("[MOD 3 - eBPF] Hooked socket event from %s | Payload size: %d bytes", vec.SourceIP, vec.PacketSize)
	}

	return vec
}

// EvaluateRisk simulates Module 4 (Asynchronous AI Risk Engine)
// Returns the raw risk score for the proxy's graduated policy engine to act upon.
func EvaluateRisk(vec TelemetryVector) float64 {
	var riskScore float64

	switch vec.AnomalyCategory {
	// Confirmed exploit payload or deep-packet signature match → SEVERE
	case "Payload-level exploit", "Abnormal access pattern":
		riskScore = 0.88
		log.Printf("[MOD 4 - AI Engine] RISK SEVERE: Anomaly [%s | %s] -> Score: %.2f",
			vec.AnomalyCategory, vec.DetectedThreat, riskScore)

	// Behavioral drift or suspicious access pattern → MODERATE
	case "Behavioral anomaly", "Suspicious access pattern":
		riskScore = 0.55
		log.Printf("[MOD 4 - AI Engine] RISK MODERATE: Anomaly [%s | %s] -> Score: %.2f",
			vec.AnomalyCategory, vec.DetectedThreat, riskScore)

	// No anomaly detected → BENIGN
	default:
		riskScore = 0.12
		log.Printf("[MOD 4 - AI Engine] Behavioral Risk Score computed: %.2f (Benign)", riskScore)
	}

	return riskScore
}
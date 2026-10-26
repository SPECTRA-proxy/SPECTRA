package stubs

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

var m4Client = &http.Client{
	Timeout: 40 * time.Millisecond,
}

type m4Payload struct {
	PacketSize       int64   `json:"packet_size"`
	RequestRate      float64 `json:"request_rate"`
	ConnectionCount  int     `json:"connection_count"`
	InterArrivalTime float64 `json:"inter_arrival_time"`
	STTL             int     `json:"sttl"`
	SJIT             float64 `json:"sjit"`
	DMean            float64 `json:"dmean"`
	SynAck           float64 `json:"synack"`
}

type m4Response struct {
	Anomaly        bool    `json:"anomaly"`
	IsolationScore float64 `json:"isolation_score"`
	RiskScore      float64 `json:"risk_score"`
	Decision       string  `json:"decision"`
}

func queryM4Live(vec TelemetryVector) (float64, bool) {
	reqBody := m4Payload{
		PacketSize:       vec.PacketSize,
		RequestRate:      vec.RequestRate,
		ConnectionCount:  vec.ConnectionCount,
		InterArrivalTime: vec.InterArrivalTime,
		STTL:             vec.STTL,
		SJIT:             vec.SJIT,
		DMean:            vec.DMean,
		SynAck:           vec.SynAck,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return 0, false
	}

	resp, err := m4Client.Post("http://127.0.0.1:7000/score", "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, false
	}

	var m4Resp m4Response
	if err := json.NewDecoder(resp.Body).Decode(&m4Resp); err != nil {
		return 0, false
	}

	log.Printf("[MOD 4 - Live AI] Ingested 8-feature vector -> Score: %.4f | Risk: %.2f | Action: %s",
		m4Resp.IsolationScore, m4Resp.RiskScore, m4Resp.Decision)
	return m4Resp.RiskScore, true
}

// TelemetryVector represents features extracted by eBPF & IDS (Module 3)
type TelemetryVector struct {
	SourceIP         string
	DestPort         string
	PacketSize       int64   // 1. packet_size / smean (bytes)
	RequestRate      float64 // 2. request_rate (pkts/sec)
	ConnectionCount  int     // 3. connection_count (active flows)
	InterArrivalTime float64 // 4. inter_arrival_time (sinpkt in milliseconds, ms)
	STTL             int     // 5. sttl (source IPv4 TTL in hops)
	SJIT             float64 // 6. sjit (source jitter in milliseconds, ms)
	DMean            float64 // 7. dmean (destination response mean size in bytes)
	SynAck           float64 // 8. synack / tcprtt (handshake latency in milliseconds, ms)
	Timestamp        time.Time
	CapturedHook     string
	DetectedThreat   string // Ingested from IDS / Deep-Packet Inspection
	AnomalyCategory  string // e.g. "Payload-level exploit", "Abnormal access pattern"
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
	pktSize := r.ContentLength
	if pktSize <= 0 {
		pktSize = 512
	}

	vec := TelemetryVector{
		SourceIP:         r.RemoteAddr,
		DestPort:         "8443",
		PacketSize:       pktSize,
		RequestRate:      5.0,
		ConnectionCount:  1,
		InterArrivalTime: 45.0, // ms
		STTL:             64,
		SJIT:             3.0,  // ms
		DMean:            1280.0,
		SynAck:           12.4, // ms
		Timestamp:        time.Now(),
		CapturedHook:     "ebpf/bidirectional_socket_filter",
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

// EvaluateRisk evaluates Module 4 (Asynchronous AI Risk Engine)
// It queries the live 8-feature M4 Python service on port 7000 if available,
// falling back safely to calibrated baseline heuristics.
func EvaluateRisk(vec TelemetryVector) float64 {
	// Priority 1: Confirmed exploit payload or deep-packet signature match → SEVERE
	switch vec.AnomalyCategory {
	case "Payload-level exploit", "Abnormal access pattern":
		riskScore := 0.88
		log.Printf("[MOD 4 - AI Engine] RISK SEVERE: Anomaly [%s | %s] -> Score: %.2f",
			vec.AnomalyCategory, vec.DetectedThreat, riskScore)
		return riskScore
	}

	// Priority 2: Query Live M4 Isolation Forest service with the 8-feature vector
	if liveScore, ok := queryM4Live(vec); ok {
		return liveScore
	}

	// Priority 3: Fallback baseline heuristics
	var riskScore float64
	switch vec.AnomalyCategory {
	case "Behavioral anomaly", "Suspicious access pattern":
		riskScore = 0.55
		log.Printf("[MOD 4 - AI Engine] RISK MODERATE: Anomaly [%s | %s] -> Score: %.2f",
			vec.AnomalyCategory, vec.DetectedThreat, riskScore)

	default:
		riskScore = 0.12
		log.Printf("[MOD 4 - AI Engine] Behavioral Risk Score computed: %.2f (Benign)", riskScore)
	}

	return riskScore
}
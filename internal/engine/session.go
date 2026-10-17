package engine

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Session represents an authenticated client session tracked at the edge
type Session struct {
	ID          string
	BoundIP     string
	Created     time.Time
	LastSeen    time.Time
	MFAVerified bool
	RiskScore   float64
	PQCScheme   string
}

// SessionStore provides thread-safe in-memory session tracking
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// ExtractClientIP extracts the host IP without port
func ExtractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// GetEffectiveClientIP checks for simulated test headers (X-Client-IP, X-Forwarded-For)
// before falling back to the raw TCP RemoteAddr.
func GetEffectiveClientIP(r *http.Request) string {
	if cip := r.Header.Get("X-Client-IP"); cip != "" {
		return cip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	return ExtractClientIP(r.RemoteAddr)
}

// ExtractSessionID extracts the session token from header, cookie, or generates a default
func ExtractSessionID(r *http.Request) string {
	// 1. Check custom header
	if sid := r.Header.Get("X-Session-ID"); sid != "" {
		return sid
	}

	// 2. Check Cookie
	if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// 3. Check Authorization header (Bearer token)
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// GetOrCreate retrieves an existing session or creates a new one
// Returns: (session, isNew, ipMismatch)
func (ss *SessionStore) GetOrCreate(sessionID, clientIP, pqcScheme string) (*Session, bool, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	cleanIP := ExtractClientIP(clientIP)

	sess, exists := ss.sessions[sessionID]
	if !exists {
		sess = &Session{
			ID:          sessionID,
			BoundIP:     cleanIP,
			Created:     time.Now(),
			LastSeen:    time.Now(),
			MFAVerified: true, // First login on bound IP is clean
			RiskScore:   0.12,
			PQCScheme:   pqcScheme,
		}
		ss.sessions[sessionID] = sess
		log.Printf("[MOD 2 - SessionStore] NEW SESSION: %s registered from bound IP %s (PQC: %s)",
			sessionID, cleanIP, pqcScheme)
		return sess, true, false
	}

	// Existing session: update timestamp and check IP binding
	sess.LastSeen = time.Now()
	ipMismatch := false

	if sess.BoundIP != cleanIP {
		log.Printf("[MOD 2 - SessionStore] IP MISMATCH DETECTED: Session %s bound to %s but requested from %s",
			sessionID, sess.BoundIP, cleanIP)
		ipMismatch = true
	}

	return sess, false, ipMismatch
}

// VerifyMFA rebinds a session to the new IP after successful MFA verification
func (ss *SessionStore) VerifyMFA(sessionID, newIP string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	cleanIP := ExtractClientIP(newIP)
	sess, exists := ss.sessions[sessionID]
	if !exists {
		// Create session with verified status
		sess = &Session{
			ID:          sessionID,
			BoundIP:     cleanIP,
			Created:     time.Now(),
			LastSeen:    time.Now(),
			MFAVerified: true,
			RiskScore:   0.12,
		}
		ss.sessions[sessionID] = sess
		log.Printf("[MOD 2 - SessionStore] MFA VERIFIED: New session %s bound to IP %s", sessionID, cleanIP)
		return true
	}

	sess.BoundIP = cleanIP
	sess.MFAVerified = true
	sess.RiskScore = 0.12
	sess.LastSeen = time.Now()
	log.Printf("[MOD 2 - SessionStore] MFA VERIFIED: Session %s successfully rebound to new IP %s. Risk reset to 0.12.",
		sessionID, cleanIP)
	return true
}

// GetSession returns a session if present (read-only)
func (ss *SessionStore) GetSession(sessionID string) (*Session, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	sess, exists := ss.sessions[sessionID]
	return sess, exists
}

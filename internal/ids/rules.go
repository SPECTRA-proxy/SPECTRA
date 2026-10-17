package ids

import (
	"regexp"
)

// SeverityLevel indicates threat severity
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "CRITICAL" // Immediate Fast-path drop
	SeverityHigh     SeverityLevel = "HIGH"     // Immediate Fast-path drop
	SeverityMedium   SeverityLevel = "MEDIUM"   // Informational / Elevate AI risk
)

// Rule defines an individual static signature rule
type Rule struct {
	ID          int
	Category    string
	Description string
	Severity    SeverityLevel
	Regex       *regexp.Regexp
}

// DetectionResult contains detailed match metadata
type DetectionResult struct {
	Matched     bool
	RuleID      int
	Category    string
	Description string
	Severity    SeverityLevel
	Location    string
	Sample      string
}

// Precompiled Static Signature Ruleset (OWASP Core Rule Set subset + CVEs + Scanners)
var StaticRules = []Rule{
	// ==========================================
	// 1. RECONNAISSANCE & AUTOMATED SCANNERS
	// ==========================================
	{
		ID:          1001,
		Category:    "SCANNER_PROBE",
		Description: "Automated vulnerability scanner / attack tool",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(sqlmap|nikto|acunetix|wpscan|dirbuster|gobuster|masscan|zgrab|nmap)`),
	},

	// ==========================================
	// 2. SQL INJECTION (SQLi)
	// ==========================================
	{
		ID:          2001,
		Category:    "SQL_INJECTION",
		Description: "SQL UNION or SELECT statement extraction",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(union\s+(all\s+)?select|select\s+.*\s+from\s+information_schema)`),
	},
	{
		ID:          2002,
		Category:    "SQL_INJECTION",
		Description: "SQL Boolean-based authentication bypass / tautology",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)('\s*or\s*'|or\s+1\s*=\s*1|'\s*or\s*1\s*=\s*1|admin'\s*--)`),
	},
	{
		ID:          2003,
		Category:    "SQL_INJECTION",
		Description: "Destructive SQL DDL statement injection",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(drop\s+table|delete\s+from|insert\s+into.*values|update\s+.*\s+set)`),
	},
	{
		ID:          2004,
		Category:    "SQL_INJECTION",
		Description: "SQL Time-based blind injection",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(waitfor\s+delay\s+'|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+)`),
	},

	// ==========================================
	// 3. REMOTE COMMAND EXECUTION (RCE)
	// ==========================================
	{
		ID:          3001,
		Category:    "COMMAND_INJECTION",
		Description: "OS shell command injection sequence",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(;\s*(cat\s+/etc|ls\s+-|whoami|id|bash|sh|nc|curl|wget)\b|\|\s*(bash|sh)|` + "`" + `\s*(cat|whoami|id)` + "`" + `|\$\(\s*(whoami|id|cat)\s*\))`),
	},
	{
		ID:          3002,
		Category:    "COMMAND_INJECTION",
		Description: "Log4Shell (CVE-2021-44228) JNDI lookup exploit",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(\$\{jndi:(ldap|rmi|dns|nis|iiop|corba):)`),
	},

	// ==========================================
	// 4. PATH TRAVERSAL & LOCAL FILE INCLUSION
	// ==========================================
	{
		ID:          4001,
		Category:    "PATH_TRAVERSAL",
		Description: "Directory traversal / sensitive file inclusion",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|win\.ini|boot\.ini)`),
	},

	// ==========================================
	// 5. CROSS-SITE SCRIPTING (XSS)
	// ==========================================
	{
		ID:          5001,
		Category:    "XSS_EXPLOIT",
		Description: "Script tag or inline javascript protocol injection",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(<script[\s>]|javascript:|vbscript:|<iframe|<object|<embed)`),
	},
	{
		ID:          5002,
		Category:    "XSS_EXPLOIT",
		Description: "Event-handler attribute injection",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)(onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=)`),
	},

	// ==========================================
	// 6. SERVER-SIDE REQUEST FORGERY (SSRF)
	// ==========================================
	{
		ID:          6001,
		Category:    "SSRF_EXPLOIT",
		Description: "Cloud instance metadata or internal loopback probe",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1:|\blocalhost:)`),
	},
}

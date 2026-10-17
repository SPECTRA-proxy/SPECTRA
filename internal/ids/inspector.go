package ids

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Normalize performs recursive decoding and canonicalization to prevent evasion
func Normalize(input string) string {
	decoded := input

	// Attempt up to 2 passes of URL decoding to neutralize double-encoding attacks (%2527 -> %27 -> ')
	for i := 0; i < 2; i++ {
		if unescaped, err := url.QueryUnescape(decoded); err == nil && unescaped != decoded {
			decoded = unescaped
		} else {
			break
		}
	}

	// Strip null bytes and control characters used in evasion
	decoded = strings.ReplaceAll(decoded, "\x00", "")

	return decoded
}

// matchString tests a normalized string against all static rules
func matchString(input, location string) *DetectionResult {
	if input == "" {
		return nil
	}

	normalized := Normalize(input)

	for _, rule := range StaticRules {
		if loc := rule.Regex.FindStringIndex(normalized); loc != nil {
			sample := normalized[loc[0]:loc[1]]
			return &DetectionResult{
				Matched:     true,
				RuleID:      rule.ID,
				Category:    rule.Category,
				Description: rule.Description,
				Severity:    rule.Severity,
				Location:    location,
				Sample:      sample,
			}
		}
	}

	return nil
}

// InspectRequest inspects URI, Query, Headers, and Body against the static ruleset
func InspectRequest(r *http.Request) *DetectionResult {
	// 1. Inspect URL Path
	if res := matchString(r.URL.Path, "URL_PATH"); res != nil {
		logMatch(res)
		return res
	}

	// 2. Inspect Query Parameters
	if r.URL.RawQuery != "" {
		if res := matchString(r.URL.RawQuery, "URL_QUERY"); res != nil {
			logMatch(res)
			return res
		}
	}

	// 3. Inspect Sensitive HTTP Headers (User-Agent, Cookies, Custom)
	if ua := r.Header.Get("User-Agent"); ua != "" {
		if res := matchString(ua, "HEADER_USER_AGENT"); res != nil {
			logMatch(res)
			return res
		}
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		if res := matchString(cookie, "HEADER_COOKIE"); res != nil {
			logMatch(res)
			return res
		}
	}
	if sigHeader := r.Header.Get("X-Threat-Signature"); sigHeader != "" {
		if res := matchString(sigHeader, "HEADER_THREAT_SIMULATION"); res != nil {
			logMatch(res)
			return res
		}
	}

	// 4. Inspect Request Body (Non-destructively)
	if r.Body != nil && r.ContentLength > 0 {
		// Read up to 1MB of body
		limit := int64(1024 * 1024)
		if r.ContentLength < limit {
			limit = r.ContentLength
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, limit))
		if err == nil && len(bodyBytes) > 0 {
			// Rewind request body so upstream server can read it
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if res := matchString(string(bodyBytes), "REQUEST_BODY"); res != nil {
				logMatch(res)
				return res
			}
		}
	}

	return &DetectionResult{Matched: false}
}

func logMatch(res *DetectionResult) {
	log.Printf("[MOD 3 - L7 IDS] ATTACK DETECTED: Rule %d [%s: %s] found in %s (Match sample: '%s')",
		res.RuleID, res.Category, res.Description, res.Location, res.Sample)
}

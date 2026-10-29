package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type HygieneRules struct {
	CookieRedaction  []string `json:"cookie_redaction" yaml:"cookie_redaction"`
	PIIPatterns      []string `json:"pii_patterns" yaml:"pii_patterns"`
	SensitiveHeaders []string `json:"sensitive_headers" yaml:"sensitive_headers"`
	NeverCaptureText []string `json:"never_capture_text" yaml:"never_capture_text"`
	HarFilters       []string `json:"har_filters" yaml:"har_filters"`
}

var DefaultHygieneRules = HygieneRules{
	CookieRedaction: []string{
		"session", "token", "auth", "jwt", "bearer", "access_token", "refresh_token",
		"id_token", "csrf", "xsrf", "sid", "connect.sid", "PHPSESSID", "JSESSIONID",
		"_csrf", "_xsrf", "__Host-", "__Secure-", "Authorization",
	},
	PIIPatterns: []string{
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
		`\b\d{3}[-.]?\d{2}[-.]?\d{4}\b`,
		`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`,
		`\b[A-Z]{2}\d{6,}\b`,
		`\b\d{15,16}\b`,
		`\b[A-Z][a-z]+ [A-Z][a-z]+\b`,
	},
	SensitiveHeaders: []string{
		"cookie", "set-cookie", "authorization", "x-auth-token",
		"x-api-key", "x-csrf-token", "proxy-authorization",
	},
	NeverCaptureText: []string{
		"password", "passwd", "secret", "private_key", "-----BEGIN",
	},
	HarFilters: []string{
		`del(.log.entries[].request.cookies)`,
		`del(.log.entries[].response.cookies)`,
		`del(.log.entries[].request.headers[] | select(.name | test("cookie|authorization|x-auth"; "i")))`,
		`del(.log.entries[].response.headers[] | select(.name | test("set-cookie"; "i")))`,
	},
}

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(key))
	switch key {
	case "cookie", "setcookie", "authorization", "proxyauthorization", "apikey", "xapikey", "password", "passwd", "secret", "raw", "rawv2", "match", "redacted", "extradata", "privatekey", "clientsecret", "token", "accesstoken", "refreshtoken", "idtoken", "session", "sessionid", "jwt":
		return true
	}
	return strings.HasPrefix(key, "x") && (strings.Contains(key, "auth") || strings.Contains(key, "token") || strings.Contains(key, "csrf"))
}

func (h HygieneRules) RedactCookies(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if sensitiveKey(k) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = h.SanitizeText(v)
		}
	}
	return out
}

var credentialAssignment = regexp.MustCompile(`(?i)(\b(?:password|passwd|secret|private_key|client_secret|api[_-]?key|access_token|refresh_token|id_token|token|authorization|cookie|set-cookie)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&]+)`)
var authorizationLine = regexp.MustCompile(`(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+`)
var bearerToken = regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
var privateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
var textURL = regexp.MustCompile(`https?://[^\s<>"']+`)

// SanitizeURL preserves URL syntax while removing credentials and sensitive query values.
func SanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	changed := false
	if u.User != nil {
		u.User = nil
		changed = true
	}
	q := u.Query()
	for key := range q {
		if sensitiveKey(key) {
			q.Set(key, "REDACTED")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	if u.Fragment != "" {
		fragment := credentialAssignment.ReplaceAllString(u.Fragment, "${1}REDACTED")
		if fragment != u.Fragment {
			u.Fragment = fragment
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return u.String()
}

func sanitizeSecrets(text string) string {
	text = privateKeyBlock.ReplaceAllString(text, "[REDACTED PRIVATE KEY]")
	text = authorizationLine.ReplaceAllString(text, "${1}[REDACTED]")
	text = bearerToken.ReplaceAllString(text, "[REDACTED AUTHORIZATION]")
	text = credentialAssignment.ReplaceAllString(text, "${1}[REDACTED]")
	return textURL.ReplaceAllStringFunc(text, SanitizeURL)
}

func (h HygieneRules) SanitizeText(text string) string {
	text = sanitizeSecrets(text)
	for _, pattern := range h.PIIPatterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			text = re.ReplaceAllString(text, "[REDACTED]")
		}
	}
	return text
}

func (h HygieneRules) SanitizeHeaders(data []byte) ([]byte, error) {
	return h.SanitizeJSON(data)
}
func (h HygieneRules) SanitizeHAR(data []byte) ([]byte, error) {
	return h.SanitizeJSON(data)
}

// SanitizeJSON handles nested headers, HAR name/value pairs and secret fields.
// Body text is removed because its format may be binary, encoded, or application-specific.
func (h HygieneRules) SanitizeJSON(data []byte) ([]byte, error) {
	var v any
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid JSON evidence")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&v); err != nil {
		return nil, err
	}
	if text, ok := v.(string); ok {
		v = sanitizeSecrets(text)
	} else {
		sanitizeValue(v)
	}
	return json.Marshal(v)
}

func sanitizeValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		name, _ := x["name"].(string)
		if name == "" {
			name, _ = x["key"].(string)
		}
		if sensitiveKey(name) {
			if _, ok := x["value"]; ok {
				x["value"] = "[REDACTED]"
			}
		}
		for k, child := range x {
			lower := strings.ToLower(k)
			switch {
			case lower == "cookies":
				x[k] = []any{}
			case sensitiveKey(k):
				x[k] = "[REDACTED]"
			case lower == "postdata" || lower == "content":
				if m, ok := child.(map[string]any); ok {
					if _, ok := m["text"]; ok {
						m["text"] = "[REDACTED]"
					}
				}
				sanitizeValue(child)
			default:
				if text, ok := child.(string); ok {
					x[k] = sanitizeSecrets(text)
				} else {
					sanitizeValue(child)
				}
			}
		}
	case []any:
		for i, child := range x {
			if text, ok := child.(string); ok {
				x[i] = sanitizeSecrets(text)
			} else {
				sanitizeValue(child)
			}
		}
	}
}

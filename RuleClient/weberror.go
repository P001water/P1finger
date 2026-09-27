package RuleClient

import "strings"

// RequestErrorText converts a request error into a compact, categorized
// reason that can be shown directly in the scan output. The classification
// prefixes make it obvious whether the failure is a timeout, a refused
// connection or a TLS mismatch on the target port.
func RequestErrorText(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	msg = strings.TrimPrefix(msg, "request fail, ")
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "i/o timeout"):
		return "connect timeout: " + msg
	case strings.Contains(lower, "context deadline exceeded"):
		return "request timeout: " + msg
	case strings.Contains(lower, "connection refused"):
		return "connection refused: " + msg
	case strings.Contains(lower, "no route to host"):
		return "no route to host: " + msg
	case strings.Contains(lower, "connection reset"):
		return "connection reset: " + msg
	case strings.Contains(lower, "tls: handshake") ||
		strings.Contains(lower, "first record does not look like a tls handshake"):
		return "TLS handshake failed, the port may not be HTTPS: " + msg
	case strings.Contains(lower, "http response to https client"):
		return "the port is not an HTTPS service: " + msg
	case strings.Contains(lower, "unsupported protocol scheme"):
		return "bad url scheme: " + msg
	case strings.Contains(lower, "proxy"):
		return "proxy error: " + msg
	case strings.Contains(lower, "eof"):
		return "connection closed unexpectedly: " + msg
	default:
		return msg
	}
}

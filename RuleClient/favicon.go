package RuleClient

import (
	"io"
	"net/http"
	"strings"
	"time"
)

const maxFaviconSize = 200 << 10 // 200KB

// faviconHash fetches /favicon.ico once per target and returns the fofa-style
// hash used by the fingerprint library's "favicon" matchers.
func (r *RuleClient) faviconHash(baseURL string) (uint32, bool) {
	iconURL := strings.TrimRight(baseURL, "/") + "/favicon.ico"
	client := r.ProxyNoRedirectCilent
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, iconURL, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFaviconSize))
	if err != nil || len(body) == 0 {
		return 0, false
	}
	return faviconFofaHash(body), true
}

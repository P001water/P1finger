package RuleClient

import (
	"embed"
	"fmt"
	"github.com/P001water/p1finger/p1httputils"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

//go:embed testdata
var testFingerprintFS embed.FS

//go:embed testdata-active
var testActiveFS embed.FS

//go:embed testdata-prefilter
var testPrefilterFS embed.FS

// TestMMH3Vector checks the MurmurHash3 implementation against the documented
// test vector: mmh3("foo") == -156908512 (0xF6A5C420 as uint32).
func TestMMH3Vector(t *testing.T) {
	got := mmh3([]byte("foo"))
	if got != 0xF6A5C420 {
		t.Fatalf("mmh3(foo) = %d (0x%X), want 0xF6A5C420", got, got)
	}
}

// TestAhoCorasick verifies the multi-pattern matcher with the classic example
// (dictionary: he, she, his, hers; text: "ushers").
func TestAhoCorasick(t *testing.T) {
	ac := newAhoCorasick([]string{"he", "she", "his", "hers"})
	found := ac.find("ushers")
	for _, want := range []string{"he", "she", "hers"} {
		if !found[want] {
			t.Errorf("ac.find(ushers) missing %q: %v", want, found)
		}
	}
	if found["his"] {
		t.Error("ac.find(ushers) should not contain his")
	}
}

// TestFaviconMatch verifies the favicon matcher end-to-end: fetch /favicon.ico,
// compute the fofa-style hash and match it against a fingerprint rule.
func TestFaviconMatch(t *testing.T) {
	icon := []byte{0x00, 0x01, 0x02, 0x03, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFE, 0xFD}
	hash := int64(int32(faviconFofaHash(icon)))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			w.Write(icon)
		default:
			w.Write([]byte("<html><title>test page</title></html>"))
		}
	}))
	defer srv.Close()

	exeDir := filepath.Dir(os.Args[0])
	fpFile := filepath.Join(exeDir, "test-favicon-fingerprint.yaml")
	content := fmt.Sprintf("- id: test-fav\n  name: TestFavicon\n  author: test\n  description: test\n  tags:\n    - test\n  matchers:\n    - location: favicon\n      hash:\n        - %d\n", hash)
	if err := os.WriteFile(fpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fpFile)

	r, err := NewRuleClientBuilder().
		WithDefaultFingerFiles(false).
		WithCustomizeFingerFile([]string{"test-favicon-fingerprint.yaml"}).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rst, err := r.Detect(srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(rst.HitRules) == 0 {
		t.Fatal("expected hit rules for favicon match")
	}
	for _, tag := range rst.FingerTag {
		if tag == "TestFavicon" {
			return
		}
	}
	t.Fatalf("favicon fingerprint not matched, FingerTag=%v", rst.FingerTag)
}

// TestBodyHitRule verifies a body-word match reports the matched rule detail
// and the injected library is used for detection.
func TestBodyHitRule(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>injected-marker page</body></html>"))
	}))
	defer srv.Close()

	r, err := NewRuleClientBuilder().
		WithFingerprintFS(testFingerprintFS).
		WithFingerprintDir("testdata/P1fingersYaml").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rst, err := r.Detect(srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	foundTag := false
	for _, tag := range rst.FingerTag {
		if tag == "InjectedFingerprint" {
			foundTag = true
			break
		}
	}
	if !foundTag {
		t.Fatalf("injected fingerprint not matched: %v", rst.FingerTag)
	}
	if len(rst.HitRules) == 0 || !strings.Contains(rst.HitRules[0], "body") {
		t.Fatalf("expected body hit rule, got %v", rst.HitRules)
	}
}

// TestActivePathProbe verifies the two-phase flow: passive root request misses,
// then the active probe requests the fingerprint's declared paths and matches.
func TestActivePathProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/special" {
			w.Write([]byte("<html><body>active-marker page</body></html>"))
			return
		}
		if r.URL.Path == "/special2" {
			w.Write([]byte("<html><body>probe-marker page</body></html>"))
			return
		}
		w.Write([]byte("<html><body>plain landing page</body></html>"))
	}))
	defer srv.Close()

	build := func(mode string) (*RuleClient, error) {
		return NewRuleClientBuilder().
			WithFingerprintFS(testActiveFS).
			WithFingerprintDir("testdata-active/P1fingersYaml").
			WithProbeMode(mode).
			Build()
	}

	// auto 模式：被动未命中 → 主动探测 /special 命中
	r, err := build("auto")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rst, err := r.Detect(srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !containsTag(rst.FingerTag, "ActiveFingerprint") {
		t.Fatalf("active probe should hit, FingerTag=%v HitRules=%v", rst.FingerTag, rst.HitRules)
	}
	if !containsTag(rst.FingerTag, "ProbeFingerprint") {
		t.Fatalf("probe matchers should hit, FingerTag=%v HitRules=%v", rst.FingerTag, rst.HitRules)
	}

	// passive 模式：不做主动探测，不应命中
	rp, err := build("passive")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rstP, err := rp.Detect(srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if containsTag(rstP.FingerTag, "ActiveFingerprint") {
		t.Fatalf("passive mode should not run active probe, got %v", rstP.FingerTag)
	}
	if containsTag(rstP.FingerTag, "ProbeFingerprint") {
		t.Fatalf("passive mode should not run probe matchers, got %v", rstP.FingerTag)
	}
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// TestFailureCache verifies failed active probes are cached per host+path and
// skipped on subsequent Detect calls until ResetFailureCache is called.
func TestFailureCache(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/special" {
			mu.Lock()
			hits++
			mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte("<html><body>plain</body></html>"))
	}))
	defer srv.Close()

	r, err := NewRuleClientBuilder().
		WithFingerprintFS(testActiveFS).
		WithFingerprintDir("testdata-active/P1fingersYaml").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	r.Detect(srv.URL)
	r.Detect(srv.URL)
	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 1 {
		t.Fatalf("expected 1 request to /special (404 cached), got %d", got)
	}

	r.ResetFailureCache()
	r.Detect(srv.URL)
	mu.Lock()
	got = hits
	mu.Unlock()
	if got != 2 {
		t.Fatalf("expected 2 requests after reset, got %d", got)
	}
}

// TestActivePrefilter verifies the title/header keyword pre-filter: fingerprints
// whose title/header markers are absent from the root page are skipped entirely
// (their paths are never requested), while marker-hit, body-only and explicitly
// prefilter:none fingerprints still get probed.
func TestActivePrefilter(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/sig":
			w.Write([]byte("<html><body>sig-marker page</body></html>"))
		case "/nope":
			w.Write([]byte("<html><body>nope-marker page</body></html>"))
		case "/bodyonly":
			w.Write([]byte("<html><body>bodyonly-marker page</body></html>"))
		case "/subonly":
			w.Write([]byte("<html><head><title>SubOnlyTitle</title></head><body>subonly-marker page</body></html>"))
		default:
			w.Write([]byte("<html><head><title>SignalApp</title></head><body>plain landing page</body></html>"))
		}
	}))
	defer srv.Close()

	r, err := NewRuleClientBuilder().
		WithFingerprintFS(testPrefilterFS).
		WithFingerprintDir("testdata-prefilter/P1fingersYaml").
		WithProbeMode("active").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rst, err := r.Detect(srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	// 根页无标记的指纹整组跳过：/nope 不应被请求
	if containsTag(rst.FingerTag, "PrefilterFail") {
		t.Fatalf("prefilter should drop PrefilterFail, got %v", rst.FingerTag)
	}
	if n := hits["/nope"]; n != 0 {
		t.Fatalf("prefilter should skip /nope, got %d requests", n)
	}
	// 根页有标记、纯 body、显式 none 的指纹路径都应被请求一次
	for _, path := range []string{"/sig", "/bodyonly", "/subonly"} {
		if n := hits[path]; n != 1 {
			t.Fatalf("expected exactly 1 request to %s, got %d", path, n)
		}
	}
	for _, name := range []string{"PrefilterPass", "PrefilterBodyOnly", "PrefilterNone"} {
		if !containsTag(rst.FingerTag, name) {
			t.Fatalf("expected %s in FingerTag, got %v", name, rst.FingerTag)
		}
	}
}

// TestWithFingerprintFS verifies a caller can inject its own embedded
// fingerprint library instead of the built-in full P1fingersYaml.
func TestWithFingerprintFS(t *testing.T) {
	r, err := NewRuleClientBuilder().
		WithFingerprintFS(testFingerprintFS).
		WithFingerprintDir("testdata/P1fingersYaml").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	fps := r.P1FingerPrints.GetElements()
	if len(fps) != 1 {
		t.Fatalf("expected 1 fingerprint from injected FS, got %d", len(fps))
	}
	if fps[0].Name != "InjectedFingerprint" {
		t.Fatalf("unexpected fingerprint %q", fps[0].Name)
	}
}

// TestNoDuplicateFingerTag 验证同一指纹多个 matcher 命中时 FingerTag 只追加
// 一次（HitRules 保留全部命中规则）。
func TestNoDuplicateFingerTag(t *testing.T) {
	dir := t.TempDir()
	content := `
- id: multi-matcher
  name: MultiMatcher
  author: test
  tags:
    - multi
  matchers:
    - location: body
      words:
        - alpha
    - location: body
      words:
        - beta
`
	fpFile := filepath.Join(dir, "multi.yaml")
	if err := os.WriteFile(fpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &RuleClient{}
	r.ProxyClient = p1httputils.NewHttpClientBuilder().Build()
	r.ProxyNoRedirectCilent = p1httputils.NewHttpClientBuilder().NoRedirect().Build()
	if err := r.LoadFingersFromFile(dir, []string{"multi.yaml"}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>alpha and beta markers</body></html>"))
	}))
	defer srv.Close()

	rst, err := r.Detect(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, tag := range rst.FingerTag {
		if tag == "MultiMatcher" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("FingerTag should contain name once, got %d: %v", count, rst.FingerTag)
	}
	if len(rst.HitRules) != 2 {
		t.Fatalf("HitRules should keep both matcher hits, got %d: %v", len(rst.HitRules), rst.HitRules)
	}
}

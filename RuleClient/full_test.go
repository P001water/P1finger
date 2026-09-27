//go:build !nofull

package RuleClient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLoadEmbeddedFingerprints guards the integrity of the embedded full
// fingerprint library (only present when built without -tags nofull).
// 指纹库已统一为 nuclei 风格命名（英文 id/name/tags），断言按联动 tag
// 存在性验证，而不是旧的中文展示名。
func TestLoadEmbeddedFingerprints(t *testing.T) {
	r, err := NewRuleClientBuilder().Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	count := len(r.P1FingerPrints.GetElements())
	if count < 6000 {
		t.Fatalf("expected >=6000 fingerprints, got %d", count)
	}

	// 关键产品的 POC 联动 tag 必须存在
	tagChecks := []string{
		"weaver", "ecology", "seeyon", "yonyou", "landray", "jinhe",
		"wanhu", "topsec", "sangfor", "qax", "hikvision", "dahua",
		"ruijie", "venustech", "fortinet", "vmware", "citrix", "exchange",
	}
	for _, tc := range tagChecks {
		found := false
		for _, f := range r.P1FingerPrints.GetElements() {
			for _, tag := range f.Tags {
				if tag == tc {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			t.Errorf("no fingerprint with POC linkage tag %q", tc)
		}
	}
}

// TestSharedClient verifies the process-wide RuleClient is built once and
// reused by every caller.
func TestSharedClient(t *testing.T) {
	c1, err := Shared()
	if err != nil {
		t.Fatalf("Shared: %v", err)
	}
	c2, err := Shared()
	if err != nil {
		t.Fatalf("Shared: %v", err)
	}
	if c1 != c2 {
		t.Fatal("Shared() returned different instances")
	}
	if n := len(c1.P1FingerPrints.GetElements()); n < 5000 {
		t.Fatalf("expected >=5000 fingerprints, got %d", n)
	}
}

// TestProductPathsInjected verifies built-in active probe paths are injected
// for fingerprints that do not declare paths explicitly.
func TestProductPathsInjected(t *testing.T) {
	r, err := NewRuleClientBuilder().Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	found := false
	for _, f := range r.P1FingerPrints.GetElements() {
		if f.FingerFile == "weaver.yaml" && len(f.Paths) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("weaver fingerprints should have injected probe paths")
	}
	foundProbe := false
	for _, f := range r.P1FingerPrints.GetElements() {
		if f.FingerFile == "springboot.yaml" && len(f.Probes) > 0 {
			foundProbe = true
			break
		}
	}
	if !foundProbe {
		t.Fatal("springboot fingerprints should have injected probes")
	}
}

// BenchmarkDetect measures end-to-end fingerprint matching throughput against a
// realistic ~100KB page using the full embedded fingerprint library.
func BenchmarkDetect(b *testing.B) {
	page := "<html><head><title>Benchmark Page</title></head><body>" +
		strings.Repeat("padding-content-for-large-page-", 4000) +
		"<script>window.location='/wui/theme/ecology/';</script></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(page))
	}))
	defer srv.Close()

	r, err := Shared()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Detect(srv.URL); err != nil {
			b.Fatal(err)
		}
	}
}

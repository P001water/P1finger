package RuleClient

import (
	"crypto/tls"
	"embed"
	"fmt"
	"github.com/P001water/p1finger/p1httputils"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type RuleClient struct {
	DefaultFingerPath     string                 // 默认指纹库路径
	P1FingerPrints        FingerPrintsTdSafeType // P1finger指纹库
	CustomizeFingerFiles  []string               // 可选 自定义指纹文件
	UseDefaultFingerFiles bool                   // 可选 自定义指纹文件后是否启用默认指纹库

	ProxyUrl              string       // 可选 代理地址
	ProxyClient           *http.Client // http客户端 默认跟随重定向
	ProxyNoRedirectCilent *http.Client // http客户端 默认禁止跟随重定向
	ProbeMode             string       // passive / active / auto（默认 auto）
	failCache             map[string]time.Time
	failCacheMu           sync.RWMutex
	failCacheTTL          time.Duration // 0 = 本次扫描生命周期内有效
	activeSem             chan struct{} // 全局主动探测并发上限
	hostLimit             *hostLimiter  // 每目标并发上限

	OutputFormat string // 可选 输出格式

	DetectRstTdSafe DetectResultTdSafeType
	RstShoot        DetectResultTdSafeType
	RstMiss         DetectResultTdSafeType
	RstReqFail      DetectResultTdSafeType

	ac *ahoCorasick // 指纹词自动机（加载时构建，匹配时只读）
}

type RuleClientBuilder struct {
	defaultFingerPath     string
	useDefaultFingerFiles bool
	customizeFingerFiles  []string
	outputFormat          string
	timeout               time.Duration
	proxyURL              string
	fingerprintFS         *embed.FS
	fingerprintDir        string
	fingerprintDiskDir    string // 从磁盘目录加载指纹库（CLI 的 -fpdir）
	probeMode             string
	failCacheTTL          time.Duration
	activeConcurrency     int
	perHostLimit          int
}

func NewRuleClientBuilder() *RuleClientBuilder {
	return &RuleClientBuilder{
		customizeFingerFiles:  []string{},
		useDefaultFingerFiles: true,   // 默认值
		outputFormat:          "json", // 默认值
		timeout:               5 * time.Second,
		probeMode:             "auto",
		activeConcurrency:     10,
		perHostLimit:          3,
	}
}

func (b *RuleClientBuilder) Build() (_ *RuleClient, err error) {
	r := &RuleClient{
		DefaultFingerPath:     "P1fingersYaml",
		UseDefaultFingerFiles: b.useDefaultFingerFiles,
		CustomizeFingerFiles:  b.customizeFingerFiles,
		OutputFormat:          b.outputFormat,
		ProxyUrl:              b.proxyURL,
		ProbeMode:             b.probeMode,
		failCache:             map[string]time.Time{},
		failCacheTTL:          b.failCacheTTL,
		activeSem:             make(chan struct{}, b.activeConcurrency),
		hostLimit:             newHostLimiter(b.perHostLimit),
	}

	// 加载自定义指纹（如果有）
	if len(r.CustomizeFingerFiles) > 0 {
		err = r.LoadFingersFromFile(filepath.Dir(os.Args[0]), r.CustomizeFingerFiles)
		if err != nil {
			return nil, err
		}
	}

	// 指纹库目录：默认 P1fingersYaml，可通过 WithFingerprintDir 覆盖
	if b.fingerprintDir != "" {
		r.DefaultFingerPath = b.fingerprintDir
	}

	// 指纹库来源优先级：磁盘目录 > 注入的嵌入 FS > 模块内嵌全量库
	switch {
	case b.fingerprintDiskDir != "":
		files, werr := listYamlFiles(b.fingerprintDiskDir)
		if werr != nil {
			return nil, werr
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("❌ 指纹目录 %s 下没有 .yaml 文件", b.fingerprintDiskDir)
		}
		if err = r.LoadFingersFromFile(b.fingerprintDiskDir, files); err != nil {
			return nil, err
		}
	case r.UseDefaultFingerFiles || len(r.CustomizeFingerFiles) == 0:
		if b.fingerprintFS != nil {
			err = r.LoadFingersFromFS(*b.fingerprintFS, r.DefaultFingerPath)
		} else {
			err = r.LoadFingersFromExEfs()
		}
		if err != nil {
			return nil, err
		}
	}
	// 未显式声明 paths 的产品，注入内置主动探测路径
	for i := range r.P1FingerPrints.FingerSlice {
		fp := &r.P1FingerPrints.FingerSlice[i]
		if len(fp.Paths) == 0 {
			if ps, ok := productPaths[fp.FingerFile]; ok {
				fp.Paths = ps
			}
		}
		if len(fp.Probes) == 0 {
			if ps, ok := productProbes[fp.FingerFile]; ok {
				fp.Probes = ps
			}
		}
	}
	// 注入的 probes 需要预编译（words 小写/正则）
	prepareFingerprints(r.P1FingerPrints.FingerSlice)
	r.ac = buildFingerprintAC(r.P1FingerPrints.FingerSlice)

	r.ProxyClient = p1httputils.NewHttpClientBuilder().
		WithTimeout(b.timeout).
		WithProxy(b.proxyURL).
		Build()

	r.ProxyNoRedirectCilent = p1httputils.NewHttpClientBuilder().
		WithTimeout(b.timeout).
		WithProxy(b.proxyURL).
		NoRedirect().
		Build()

	return r, nil
}

func (r *RuleClient) newProxyClientWithTimeout(timeout time.Duration) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	transCfg := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	r.ProxyClient = &http.Client{
		Timeout:   timeout,
		Transport: transCfg,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (b *RuleClientBuilder) WithDefaultFingerFiles(val bool) *RuleClientBuilder {
	b.useDefaultFingerFiles = val
	return b
}

func (b *RuleClientBuilder) WithCustomizeFingerFile(files []string) *RuleClientBuilder {
	b.customizeFingerFiles = files
	return b
}

func (b *RuleClientBuilder) WithOutputFormat(format string) *RuleClientBuilder {
	b.outputFormat = format
	return b
}

func (b *RuleClientBuilder) WithTimeout(t time.Duration) *RuleClientBuilder {
	b.timeout = t
	return b
}

func (b *RuleClientBuilder) WithProxyURL(url string) *RuleClientBuilder {
	b.proxyURL = url
	return b
}

// WithFingerprintFS 注入自定义指纹库（嵌入文件系统）。不调用时使用模块
// 自带的 P1fingersYaml 全量库。
func (b *RuleClientBuilder) WithFingerprintFS(fs embed.FS) *RuleClientBuilder {
	b.fingerprintFS = &fs
	return b
}

// WithFingerprintDir 设置注入指纹库所在的目录（FS 内的路径，默认
// "P1fingersYaml"；扁平目录传 "."）。
func (b *RuleClientBuilder) WithFingerprintDir(dir string) *RuleClientBuilder {
	b.fingerprintDir = dir
	return b
}

// WithFingerprintDiskDir 从磁盘目录加载指纹库（递归读取目录内 *.yaml），
// 用于 CLI 场景：指定自己的指纹库目录时会替代内嵌全量库。
func (b *RuleClientBuilder) WithFingerprintDiskDir(dir string) *RuleClientBuilder {
	b.fingerprintDiskDir = dir
	return b
}

// WithProbeMode 设置探测模式：passive（只请求根路径）、active（总是主动探测
// 特殊路径）、auto（默认：被动未命中才主动）。
func (b *RuleClientBuilder) WithProbeMode(mode string) *RuleClientBuilder {
	if mode == "" {
		mode = "auto"
	}
	b.probeMode = mode
	return b
}

// WithFailureCacheTTL 设置失败缓存过期时间；0（默认）表示本次扫描生命周期内
// 有效，不自动过期。
func (b *RuleClientBuilder) WithFailureCacheTTL(ttl time.Duration) *RuleClientBuilder {
	b.failCacheTTL = ttl
	return b
}

// WithActiveConcurrency 设置全局主动探测并发上限（默认 10）。
func (b *RuleClientBuilder) WithActiveConcurrency(n int) *RuleClientBuilder {
	if n > 0 {
		b.activeConcurrency = n
	}
	return b
}

// WithPerHostLimit 设置同一目标主机的并发探测上限（默认 3）。
func (b *RuleClientBuilder) WithPerHostLimit(n int) *RuleClientBuilder {
	if n > 0 {
		b.perHostLimit = n
	}
	return b
}

// ResetFailureCache 清空主动探测失败缓存（用于长驻进程开启新一轮扫描）。
func (r *RuleClient) ResetFailureCache() {
	r.failCacheMu.Lock()
	defer r.failCacheMu.Unlock()
	r.failCache = map[string]time.Time{}
}

func (r *RuleClient) cacheFailure(key string) {
	r.failCacheMu.Lock()
	defer r.failCacheMu.Unlock()
	r.failCache[key] = time.Now()
}

func (r *RuleClient) failureCached(key string) bool {
	r.failCacheMu.RLock()
	ts, ok := r.failCache[key]
	r.failCacheMu.RUnlock()
	if !ok {
		return false
	}
	if r.failCacheTTL > 0 && time.Since(ts) > r.failCacheTTL {
		r.failCacheMu.Lock()
		delete(r.failCache, key)
		r.failCacheMu.Unlock()
		return false
	}
	return true
}

var (
	sharedOnce   sync.Once
	sharedClient *RuleClient
	sharedErr    error
)

// Shared returns a process-wide RuleClient whose embedded fingerprints and
// HTTP clients are loaded exactly once and reused across all targets. Detect
// is safe for concurrent use because the shared state is read-only.
func Shared() (*RuleClient, error) {
	sharedOnce.Do(func() {
		sharedClient, sharedErr = NewRuleClientBuilder().Build()
	})
	return sharedClient, sharedErr
}

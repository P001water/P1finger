package RuleClient

import (
	"regexp"
	"sync"
)

type FingerprintsType struct {
	ID          string        `yaml:"id"`
	Name        string        `yaml:"name"`
	FingerFile  string        `yaml:"fingerFile"` //所属指纹文件
	Author      string        `yaml:"author"`
	Tags        []string      `yaml:"tags"`
	Description string        `yaml:"description"`
	Matchers    []MatcherType `yaml:"matchers"`
	// Paths 是主动探测路径：引擎在被动（根路径）未命中或 active 模式下，
	// 请求这些特殊路径并复用 matchers 判断，确认产品。
	Paths []string `yaml:"paths,omitempty"`
	// Probes 是特定路径的独立匹配器：与 paths 配合使用，声明了 probes 的
	// 路径使用其 matchers 判断（覆盖 paths 的默认复用逻辑）。
	Probes []Probe `yaml:"probes,omitempty"`
	// Prefilter 预筛开关：默认启用 title/header 关键词预筛；声明为 "none"
	// 的指纹（产品标记只出现在子页面，根页无迹可寻）绕过预筛，始终参与主动探测。
	Prefilter string `yaml:"prefilter,omitempty"`
}

// Probe 声明一个主动探测路径及其独立 matchers。
type Probe struct {
	Path     string        `yaml:"path"`
	Matchers []MatcherType `yaml:"matchers"`
}

type MatcherType struct {
	Location        string   `yaml:"location,omitempty"`
	Path            string   `yaml:"path"`
	Type            string   `yaml:"type,omitempty"`
	Words           []string `yaml:"words,omitempty"`
	FaviconHash     []string `yaml:"hash,omitempty"`
	BodyHash        string   `yaml:"bodyHash,omitempty"`
	Accuracy        string   `yaml:"accuracy"`
	Condition       string   `yaml:"condition,omitempty"`
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`

	// 预编译缓存：指纹加载时生成一次，匹配时只读，避免每个目标重复编译。
	wordsLower []string
	reCompiled *regexp.Regexp
}

type FingerPrintsTdSafeType struct {
	mu          sync.Mutex
	FingerSlice []FingerprintsType
}

func (s *FingerPrintsTdSafeType) AddElement(elem FingerprintsType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FingerSlice = append(s.FingerSlice, elem)
}

func (s *FingerPrintsTdSafeType) GetElements() []FingerprintsType {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.FingerSlice
}

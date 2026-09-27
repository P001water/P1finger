package RuleClient

import "sync"

type CertInfo struct {
	CN string // Common Name (证书拥有者)
	OU string // Organizational Unit (组织单位名称)
	O  string // Organization (组织名称)
}

type DetectResult struct {
	Host                  string    `json:"host"`
	OriginUrl             string    `json:"origin_target"`
	RedirectUrl           string    `json:"redirect_url"`
	OriginUrlStatusCode   int       `json:"origin_url_status_code"`
	RedirectUrlStatusCode int       `json:"redirect_url_status_code"`
	WebTitle              string    `json:"web_title"` //Important
	ContentLength         string    `json:"content_length"`
	SiteUp                string    `json:"site_up"`
	FingerTag             []string  `json:"finger_tag"`     //Important
	LastUpdateTime        string    `json:"lastupdatetime"` //Important
	CertInfo              *CertInfo `json:"cert_info,omitempty"`
	FailReason            string    `json:"fail_reason,omitempty"`
	HitRules              []string  `json:"hit_rules,omitempty"` // 命中的指纹规则明细（调试用）
}

type DetectResultTdSafeType struct {
	mu sync.Mutex
	t  []DetectResult
}

func (s *DetectResultTdSafeType) AddElement(elem DetectResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.t = append(s.t, elem)
}

func (s *DetectResultTdSafeType) GetElements() []DetectResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.t
}

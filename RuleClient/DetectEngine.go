package RuleClient

import (
	"github.com/P001water/p1finger/p1httputils"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

const (
	Up   = "up"
	Down = "down"
)

// p1RespLower holds per-response text pre-lowercased once so the matcher loop
// never repeats the expensive strings.ToLower(body) per fingerprint.
type p1RespLower struct {
	bodyFound, headerFound, titleFound map[string]bool
}

func (r *RuleClient) Detect(target string) (DetectRst DetectResult, err error) {
	var P1fingerResps []p1httputils.P1fingerHttpResp
	DetectRst = DetectResult{}

	fixedUrl, err := CheckHttpPrefix(target)
	if err != nil {
		DetectRst.OriginUrl = target
		DetectRst.WebTitle = "无法访问"
		DetectRst.SiteUp = Down
		DetectRst.FingerTag = []string{"unknown proto http/https, try manually"}
		DetectRst.FailReason = RequestErrorText(err)
		return
	}

	// 首次访问禁止重定向，手动解析重定向
	resp, p1fingerResp, err := p1httputils.HttpGet(fixedUrl, r.ProxyNoRedirectCilent)
	if err != nil {
		DetectRst.OriginUrl = target
		DetectRst.OriginUrlStatusCode = p1fingerResp.StatusCode
		DetectRst.ContentLength = p1fingerResp.ContentLength
		DetectRst.WebTitle = p1fingerResp.WebTitle
		DetectRst.SiteUp = Down
		DetectRst.FingerTag = []string{"WebSite down"}
		DetectRst.FailReason = RequestErrorText(err)
		return
	}
	P1fingerResps = append(P1fingerResps, p1fingerResp)

	// HTTPS 证书信息直接取自本次握手，省掉一次独立的 TLS 连接
	if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		ci := &CertInfo{CN: cert.Subject.CommonName}
		if len(cert.Subject.OrganizationalUnit) > 0 {
			ci.OU = cert.Subject.OrganizationalUnit[0]
		}
		if len(cert.Subject.Organization) > 0 {
			ci.O = cert.Subject.Organization[0]
		}
		DetectRst.CertInfo = ci
	}

	var p1fingerRedirectResp p1httputils.P1fingerHttpResp
	var m *http.Response
	redirectType, _, isRedirect := p1httputils.CheckPageRedirect(resp, p1fingerResp)
	if isRedirect {
		switch redirectType {
		case "Location":
			m, p1fingerRedirectResp, err = p1httputils.HttpGet(fixedUrl, r.ProxyClient)
			if err != nil {
				DetectRst.OriginUrl = target
				DetectRst.OriginUrlStatusCode = p1fingerResp.StatusCode
				DetectRst.ContentLength = p1fingerResp.ContentLength
				DetectRst.WebTitle = p1fingerResp.WebTitle
				DetectRst.SiteUp = Down
				DetectRst.FingerTag = []string{"WebSite down"}
				DetectRst.FailReason = RequestErrorText(err)
				return
			}
			DetectRst.RedirectUrl = m.Request.URL.String()
			P1fingerResps = append(P1fingerResps, p1fingerRedirectResp)
		case "jsRedirect":
			// todo
		case "VueRoute":
			// todo
		}
	}

	// 每个响应只小写一次，供全部指纹复用
	ac := r.ac
	if ac == nil {
		ac = buildFingerprintAC(r.P1FingerPrints.GetElements())
	}
	lowered := make([]p1RespLower, len(P1fingerResps))
	headerStrs := make([]string, len(P1fingerResps))
	for i, ti := range P1fingerResps {
		bodyLower := strings.ToLower(ti.BodyStr)
		headerLower := strings.ToLower(ti.HeaderStr)
		titleLower := strings.ToLower(ti.WebTitle)
		headerStrs[i] = ti.HeaderStr
		lowered[i] = p1RespLower{
			bodyFound:   ac.find(bodyLower),
			headerFound: ac.find(headerLower),
			titleFound:  ac.find(titleLower),
		}
	}

	var faviconHash uint32
	var faviconOK bool
	for _, finger := range r.P1FingerPrints.GetElements() {
		fingerHit := false
		for _, matcher := range finger.Matchers {
			matchFlag := false
			for i, targetInfo := range P1fingerResps {
				low := lowered[i]
				if matcher.Location == "favicon" {
					// 每个目标只取一次 favicon
					if !faviconOK {
						faviconHash, faviconOK = r.faviconHash(fixedUrl)
					}
					if faviconOK && faviconHashMatch(faviconHash, matcher.FaviconHash) {
						matchFlag = true
					}
				} else {
					matchFlag = matchOneMatcher(&matcher, &low, targetInfo.HeaderStr)
				}
				if matchFlag {
					// 同一指纹只追加一次 FingerTag（多 matcher 命中时避免重复），
					// HitRules 保留全部命中规则供排障
					if !fingerHit {
						appendHit(&DetectRst, finger.Name, finger.Tags, formatHitRule(finger.Name, matcher))
						fingerHit = true
					} else {
						DetectRst.HitRules = append(DetectRst.HitRules, formatHitRule(finger.Name, matcher))
					}
					break
				}
			}
		}
	}

	// 主动探测：active 模式总是探测；auto 模式被动未命中才探测
	switch r.ProbeMode {
	case "passive":
		// 只做被动
	case "active":
		r.activePathProbe(fixedUrl, &DetectRst, lowered, headerStrs)
	default: // auto
		if len(DetectRst.FingerTag) <= 0 {
			r.activePathProbe(fixedUrl, &DetectRst, lowered, headerStrs)
		}
	}

	if len(DetectRst.FingerTag) <= 0 {
		DetectRst.OriginUrl = p1fingerResp.Url
		DetectRst.OriginUrlStatusCode = p1fingerResp.StatusCode
		DetectRst.ContentLength = p1fingerResp.ContentLength
		DetectRst.WebTitle = p1fingerResp.WebTitle
		DetectRst.SiteUp = Up

		// 规则匹配未匹配到，尝试主动路径匹配
		webPathMatch, DetectRstTmp := r.matchWithWebPath(fixedUrl)
		if webPathMatch {
			DetectRst = DetectRstTmp
		}
	}

	DetectRst.OriginUrl = p1fingerResp.Url
	DetectRst.OriginUrlStatusCode = p1fingerResp.StatusCode
	DetectRst.ContentLength = p1fingerResp.ContentLength
	DetectRst.WebTitle = p1fingerResp.WebTitle
	DetectRst.SiteUp = Up

	if isRedirect {
		DetectRst.WebTitle = p1fingerRedirectResp.WebTitle
	}
	return
}

// activePathProbe 请求指纹声明的特殊路径（paths）并复用其 matchers 判断：
// 路径全局去重、只请求一次，命中即追加指纹结果。
// rootLows/rootHeaders 是被动阶段根页（含重定向后）的预计算命中结果，
// 用于 title/header 关键词预筛：根页无产品标记的指纹整组跳过。
func (r *RuleClient) activePathProbe(baseURL string, rst *DetectResult, rootLows []p1RespLower, rootHeaders []string) {
	ac := r.ac
	if ac == nil {
		ac = buildFingerprintAC(r.P1FingerPrints.GetElements())
	}

	type pathCand struct {
		idx      int
		matchers []MatcherType // nil => 复用指纹默认 matchers
	}
	pathCands := map[string][]pathCand{}
	var fingers []FingerprintsType
	for _, f := range r.P1FingerPrints.GetElements() {
		if !prefilterKeep(f, rootLows, rootHeaders) {
			continue
		}
		has := false
		for _, p := range f.Paths {
			if normalizePath(p) != "" {
				has = true
				break
			}
		}
		if !has {
			for _, pr := range f.Probes {
				if normalizePath(pr.Path) != "" {
					has = true
					break
				}
			}
		}
		if !has {
			continue
		}
		idx := len(fingers)
		fingers = append(fingers, f)
		for _, p := range f.Paths {
			if p = normalizePath(p); p != "" {
				pathCands[p] = append(pathCands[p], pathCand{idx: idx})
			}
		}
		for _, pr := range f.Probes {
			if p := normalizePath(pr.Path); p != "" {
				pathCands[p] = append(pathCands[p], pathCand{idx: idx, matchers: pr.Matchers})
			}
		}
	}
	if len(fingers) == 0 {
		return
	}

	paths := make([]string, 0, len(pathCands))
	for p := range pathCands {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	host := ""
	if u, err := url.Parse(baseURL); err == nil {
		host = u.Host
	}
	// 并发工作池：全局 activeSem 控制总并发，hostLimit 限制同一目标的并发，
	// 失败缓存减少重复请求；命中结果通过 hitMu 串行追加。
	var wg sync.WaitGroup
	var hitMu sync.Mutex
	fingerSeen := make(map[int]bool) // 跨路径按指纹去重 FingerTag
	type pathHit struct {
		idx  int
		rule string
	}
	for _, p := range paths {
		key := host + "|" + p
		if r.failureCached(key) {
			continue
		}
		url := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(p, "/")
		cands := pathCands[p]
		wg.Add(1)
		go func(p, key, url string, cands []pathCand) {
			defer wg.Done()
			// 先取全局信号量再取主机信号量，所有 goroutine 按同一顺序获取，避免死锁
			r.activeSem <- struct{}{}
			defer func() { <-r.activeSem }()
			r.hostLimit.acquire(host)
			defer r.hostLimit.release(host)
			// 排队等待期间可能已被并发探测缓存，二次检查
			if r.failureCached(key) {
				return
			}
			_, resp, err := p1httputils.HttpGet(url, r.ProxyNoRedirectCilent)
			if err != nil {
				r.cacheFailure(key)
				return // 失败路径本次扫描内跳过
			}
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
				r.cacheFailure(key)
				return
			}
			low := p1RespLower{
				bodyFound:   ac.find(strings.ToLower(resp.BodyStr)),
				headerFound: ac.find(strings.ToLower(resp.HeaderStr)),
				titleFound:  ac.find(strings.ToLower(resp.WebTitle)),
			}
			// 先本地收集命中，再一次性加锁追加，避免在锁内做匹配
			var hits []pathHit
			for _, c := range cands {
				f := fingers[c.idx]
				matchers := c.matchers
				if matchers == nil {
					matchers = f.Matchers
				}
				for _, m := range matchers {
					if matchOneMatcher(&m, &low, resp.HeaderStr) {
						hits = append(hits, pathHit{idx: c.idx, rule: formatPathHit(f.Name, p, m)})
						break
					}
				}
			}
			if len(hits) > 0 {
				hitMu.Lock()
				for _, h := range hits {
					if !fingerSeen[h.idx] {
						fingerSeen[h.idx] = true
						f := fingers[h.idx]
						rst.FingerTag = append(rst.FingerTag, f.Name)
						rst.FingerTag = append(rst.FingerTag, f.Tags...)
					}
					rst.HitRules = append(rst.HitRules, h.rule)
				}
				hitMu.Unlock()
			}
		}(p, key, url, cands)
	}
	wg.Wait()
}

// prefilterKeep 判断指纹是否通过主动探测预筛。
//
// 原理：被动阶段已经免费拿到根页 title/header 的关键词命中结果。产品指纹的
// 标题/响应头标记通常在落地页即可见（如 X-Powered-By、title 里的产品名），
// 若根页一个都匹配不到，则该产品大概率未运行，其特殊路径无需请求。
//
// 规则（保守方向，避免误杀）：
//   - prefilter 显式声明为 none 的指纹不参与预筛，始终保留；
//   - 没有 title/header matcher 的指纹（纯 body/favicon）无法用根页信息判断，保留；
//   - 有 title/header matcher 的指纹，任一 matcher 命中任一根页响应才保留，
//     语义与被动匹配完全一致（condition and/or 照常生效）；header 正则 matcher
//     直接对根页 header 求值，命中即保留。
func prefilterKeep(f FingerprintsType, rootLows []p1RespLower, rootHeaders []string) bool {
	if f.Prefilter == "none" {
		return true
	}
	hasSignal := false
	for i := range f.Matchers {
		switch f.Matchers[i].Location {
		case "title", "header":
			hasSignal = true
		}
	}
	if !hasSignal {
		return true
	}
	for i := range f.Matchers {
		m := &f.Matchers[i]
		if m.Location != "title" && m.Location != "header" {
			continue
		}
		for j := range rootLows {
			low := &rootLows[j]
			if m.Type == "regex" && m.Location == "header" {
				if m.reCompiled != nil && m.reCompiled.MatchString(rootHeaders[j]) {
					return true
				}
				continue
			}
			var ok bool
			if m.Location == "title" {
				ok = matchConditionFound(low.titleFound, m.wordsLower, m.Condition)
			} else {
				ok = matchConditionFound(low.headerFound, m.wordsLower, m.Condition)
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// matchOneMatcher 用 AC 预计算结果判断单个 matcher 是否命中一次响应
// （favicon/webPath 由被动阶段处理，这里不参与）。
func matchOneMatcher(m *MatcherType, low *p1RespLower, headerStr string) bool {
	switch m.Location {
	case "title":
		return matchConditionFound(low.titleFound, m.wordsLower, m.Condition)
	case "header":
		if m.Type == "regex" {
			return m.reCompiled != nil && m.reCompiled.MatchString(headerStr)
		}
		return matchConditionFound(low.headerFound, m.wordsLower, m.Condition)
	case "body":
		return matchConditionFound(low.bodyFound, m.wordsLower, m.Condition)
	}
	return false
}

func appendHit(rst *DetectResult, name string, tags []string, rule string) {
	rst.FingerTag = append(rst.FingerTag, name)
	// 指纹自带的 tags 是对齐 nuclei 的联动键：识别出指纹后，
	// 用 tags 精确命中 POC，而不是依赖展示名的大小写。
	rst.FingerTag = append(rst.FingerTag, tags...)
	rst.HitRules = append(rst.HitRules, rule)
}

func formatPathHit(name, path string, m MatcherType) string {
	detail := m.Location
	if len(m.Words) > 0 {
		detail += ":" + strings.Join(m.Words, ",")
	}
	if len(detail) > 80 {
		detail = detail[:80] + "..."
	}
	return name + " [path:" + path + " " + detail + "]"
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func (r *RuleClient) matchWithWebPath(fixedUrl string) (matchFlag bool, DetectRst DetectResult) {
	var P1fingerResps []p1httputils.P1fingerHttpResp

	for _, finger := range r.P1FingerPrints.GetElements() {
		for _, matcher := range finger.Matchers {
			if matcher.Location == "webPath" {
				fixWebPathUrl := fixedUrl + matcher.Path
				// 首次访问禁止重定向，手动解析重定向
				resp, p1fingerResp, err := p1httputils.HttpGet(fixWebPathUrl, r.ProxyNoRedirectCilent)
				if err != nil {
					DetectRst = DetectResult{
						OriginUrl:           p1fingerResp.Url,
						OriginUrlStatusCode: p1fingerResp.StatusCode,
						WebTitle:            p1fingerResp.WebTitle,
						SiteUp:              Down,
						FingerTag:           []string{"WebSite down"},
						FailReason:          RequestErrorText(err),
					}
					return
				}
				P1fingerResps = append(P1fingerResps, p1fingerResp)

				var P1fingerRedirectResp p1httputils.P1fingerHttpResp
				redirectType, _, isRedirect := p1httputils.CheckPageRedirect(resp, p1fingerResp)
				if isRedirect {
					switch redirectType {
					case "Location":
						_, P1fingerRedirectResp, err = p1httputils.HttpGet(fixWebPathUrl, r.ProxyClient)
						if err != nil {
							DetectRst = DetectResult{
								OriginUrl:           p1fingerResp.Url,
								OriginUrlStatusCode: p1fingerResp.StatusCode,
								WebTitle:            p1fingerResp.WebTitle,
								SiteUp:              Down,
								FingerTag:           []string{"WebSite down"},
								FailReason:          RequestErrorText(err),
							}
							return
						}
						P1fingerResps = append(P1fingerResps, P1fingerRedirectResp)
					case "jsRedirect":
						// todo
					case "VueRoute":
						// todo
					}
				}

				for _, fingerResp := range P1fingerResps {
					if matchConditionFound(r.ac.find(strings.ToLower(fingerResp.BodyStr)), matcher.wordsLower, matcher.Condition) {
						DetectRst = DetectResult{
							OriginUrl:           p1fingerResp.Url,
							OriginUrlStatusCode: p1fingerResp.StatusCode,
							WebTitle:            p1fingerResp.WebTitle,
							SiteUp:              Up,
							FingerTag:           append([]string{finger.Name}, finger.Tags...),
							HitRules:            []string{formatHitRule(finger.Name, matcher)},
						}
						matchFlag = true
						return
					}
				}
			}
		}
	}
	return
}

// matchConditionFound checks the pre-computed set of words present in a
// response (produced by the Aho-Corasick pass) against a matcher's words.
func matchConditionFound(found map[string]bool, words []string, condition string) bool {
	shooted := 0
	for _, word := range words {
		if found[word] {
			shooted++
			if condition == "or" || condition == "" {
				return true
			}
		} else if condition == "and" {
			return false
		}
	}
	return condition == "and" && shooted == len(words)
}

// formatHitRule 生成命中的指纹规则描述，用于 -dbg 输出与排障。
func formatHitRule(name string, m MatcherType) string {
	var detail string
	switch m.Location {
	case "favicon":
		detail = "favicon:" + strings.Join(m.FaviconHash, ",")
	default:
		detail = m.Location
		if len(m.Words) > 0 {
			detail += ":" + strings.Join(m.Words, ",")
		}
	}
	const maxDetail = 100
	if len(detail) > maxDetail {
		detail = detail[:maxDetail] + "..."
	}
	return name + " [" + detail + "]"
}

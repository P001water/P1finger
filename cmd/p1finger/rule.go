package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/P001water/p1finger/RuleClient"
)

type ruleOptions struct {
	urls        stringList
	urlFile     string
	proxy       string
	output      string
	debug       bool
	rate        int
	perHost     int
	mode        string
	timeout     time.Duration
	fpDir       string
	silent      bool
	jsonOut     bool
	showVersion bool
}

// newRuleFlagSet 注册 rule 命令的全部参数（长/短名共用同一变量）。
func newRuleFlagSet(o *ruleOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("p1finger rule", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.Var(&o.urls, "u", "target URL (repeatable / comma separated)")
	fs.Var(&o.urls, "url", "target URL (repeatable / comma separated)")
	fs.StringVar(&o.urlFile, "f", "", "target file, one URL per line; '-' reads stdin")
	fs.StringVar(&o.urlFile, "file", "", "target file, one URL per line; '-' reads stdin")
	fs.StringVar(&o.proxy, "p", "", "proxy URL, e.g. socks5://127.0.0.1:1080")
	fs.StringVar(&o.proxy, "proxy", "", "proxy URL, e.g. socks5://127.0.0.1:1080")
	fs.StringVar(&o.output, "o", "", "output file: .csv / .json(.jsonl); default stdout text")
	fs.StringVar(&o.output, "output", "", "output file: .csv / .json(.jsonl); default stdout text")
	fs.BoolVar(&o.debug, "debug", false, "print matched rules and request errors")
	fs.BoolVar(&o.debug, "dbg", false, "alias of --debug")
	fs.IntVar(&o.rate, "rate", 100, "concurrent targets")
	fs.IntVar(&o.rate, "threads", 100, "alias of --rate")
	fs.IntVar(&o.perHost, "per-host", 3, "concurrent probes per host")
	fs.StringVar(&o.mode, "mode", "auto", "probe mode: auto | passive | active")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.StringVar(&o.fpDir, "fpdir", "", "fingerprint directory (*.yaml, recursive); default embedded library")
	fs.BoolVar(&o.silent, "silent", false, "only print matched targets")
	fs.BoolVar(&o.jsonOut, "json", false, "output JSON lines to stdout")
	fs.BoolVar(&o.showVersion, "version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage:\n")
		fmt.Fprint(fs.Output(), "  p1finger rule -u <url> [flags]\n")
		fmt.Fprint(fs.Output(), "  p1finger rule -f <file> [flags]\n\n")
		fmt.Fprint(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}
	return fs
}

func printRuleFlags(w io.Writer) {
	o := &ruleOptions{}
	fs := newRuleFlagSet(o)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func runRule(args []string) int {
	o := &ruleOptions{}
	fs := newRuleFlagSet(o)
	flags, positional := splitArgs(fs, args)
	if err := fs.Parse(flags); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1 // flag 已打印错误
	}
	o.urls = append(o.urls, positional...)

	if o.showVersion {
		fmt.Printf("p1finger %s\n", effectiveVersion())
		return 0
	}

	if !o.silent {
		printBanner(os.Stderr)
	}

	targets, err := collectTargets(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: no targets, use -u / -f / positional args, or '-' to read stdin")
		return 1
	}

	client, err := buildClient(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	out, closeOut, err := openOutput(o.output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer closeOut()

	writer, err := newResultWriter(o, out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// 扫描前的运行参数提示，输出到 stderr，避免污染 stdout 的检测结果。
	if !o.silent {
		fmt.Fprintf(os.Stderr, "targets=%d mode=%s rate=%d per-host=%d timeout=%s\n",
			len(targets), o.mode, o.rate, o.perHost, o.timeout)
		if o.proxy != "" {
			fmt.Fprintf(os.Stderr, "proxy=%s\n", o.proxy)
		}
	}

	start := time.Now()
	st := detectAll(client, targets, o, writer)
	if err := writer.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "error: flush output:", err)
	}

	fmt.Fprintf(os.Stderr, "targets=%d hit=%d miss=%d fail=%d elapsed=%s\n",
		len(targets), st.hit, st.miss, st.fail, time.Since(start).Round(time.Millisecond))
	if o.output != "" {
		fmt.Fprintf(os.Stderr, "results written to %s\n", o.output)
	}
	return 0
}

// collectTargets 汇总 -u、位置参数与目标文件中的目标并去重。
// 标准输入必须显式声明：目标或 -f 传 "-" 时才读取（如 `cat urls.txt | p1finger rule -f -`），
// 避免没有目标时程序等待 stdin（IDE 里 stdin 常是保持打开的管道）而看起来卡死。
func collectTargets(o *ruleOptions) ([]string, error) {
	useStdin := false
	var targets []string
	for _, t := range o.urls {
		if t == "-" {
			useStdin = true
			continue
		}
		targets = append(targets, t)
	}

	if o.urlFile != "" {
		if o.urlFile == "-" {
			useStdin = true
		} else {
			f, err := os.Open(o.urlFile)
			if err != nil {
				return nil, fmt.Errorf("open target file: %w", err)
			}
			defer f.Close()
			lines, err := readTargets(f)
			if err != nil {
				return nil, err
			}
			targets = append(targets, lines...)
		}
	}

	if useStdin {
		lines, err := readTargets(os.Stdin)
		if err != nil {
			return nil, err
		}
		targets = append(targets, lines...)
	}

	return dedupTargets(targets), nil
}

func readTargets(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func dedupTargets(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func buildClient(o *ruleOptions) (*RuleClient.RuleClient, error) {
	b := RuleClient.NewRuleClientBuilder().
		WithProbeMode(o.mode).
		WithTimeout(o.timeout).
		WithProxyURL(o.proxy).
		WithActiveConcurrency(o.rate).
		WithPerHostLimit(o.perHost)
	if o.fpDir != "" {
		b = b.WithFingerprintDiskDir(o.fpDir)
	}
	return b.Build()
}

// openOutput 按 -o 打开输出文件；未指定时写 stdout。
// 返回的 close 函数在 stdout 场景下为空操作。
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("create output dir: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

type stats struct{ hit, miss, fail int }

type detectOutcome struct {
	target string
	rst    RuleClient.DetectResult
	err    error
}

// failed 判定目标是否请求失败：引擎在失败时返回 SiteUp=down + FailReason，
// 个别分支会附带 error。
func (r detectOutcome) failed() bool {
	return r.err != nil || r.rst.SiteUp == RuleClient.Down
}

// detectAll 用固定数量的 worker 并发探测，由结果循环串行写出。
func detectAll(client *RuleClient.RuleClient, targets []string, o *ruleOptions, w resultWriter) stats {
	workers := o.rate
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string)
	results := make(chan detectOutcome)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				rst, err := client.Detect(t)
				results <- detectOutcome{target: t, rst: rst, err: err}
			}
		}()
	}
	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var st stats
	for r := range results {
		hit := !r.failed() && len(r.rst.FingerTag) > 0
		switch {
		case r.failed():
			st.fail++
		case hit:
			st.hit++
		default:
			st.miss++
		}

		if o.silent && !hit {
			if o.debug && r.err != nil {
				fmt.Fprintf(os.Stderr, "[debug] %s: %v\n", r.target, r.err)
			}
			continue
		}
		if err := w.Write(r); err != nil {
			fmt.Fprintf(os.Stderr, "error: write result: %v\n", err)
		}
	}
	return st
}

// resultWriter 是三种输出格式（文本 / JSON Lines / CSV）的统一接口。
type resultWriter interface {
	Write(r detectOutcome) error
	Flush() error
}

// newResultWriter 依据 -o 扩展名与 --json 选择输出格式。
func newResultWriter(o *ruleOptions, out io.Writer) (resultWriter, error) {
	bw := bufio.NewWriter(out)
	switch ext := strings.ToLower(filepath.Ext(o.output)); {
	case ext == ".csv":
		return newCSVWriter(bw, o), nil
	case ext == ".json" || ext == ".jsonl":
		return newJSONWriter(bw, o), nil
	case o.jsonOut:
		return newJSONWriter(bw, o), nil
	default:
		return &textWriter{w: bw, debug: o.debug}, nil
	}
}

type textWriter struct {
	w     *bufio.Writer
	debug bool
}

func (t *textWriter) Write(r detectOutcome) error {
	switch {
	case r.failed():
		reason := r.rst.FailReason
		if reason == "" && r.err != nil {
			reason = r.err.Error()
		}
		_, err := fmt.Fprintf(t.w, "[fail] %s %s\n", r.target, reason)
		return err
	case len(r.rst.FingerTag) > 0:
		if _, err := fmt.Fprintf(t.w, "[hit]  %s code=%d len=%s title=%q finger=%s\n",
			r.target, r.rst.OriginUrlStatusCode, r.rst.ContentLength, r.rst.WebTitle,
			strings.Join(RuleClient.SliceRmDuplication(r.rst.FingerTag), ",")); err != nil {
			return err
		}
	default:
		if _, err := fmt.Fprintf(t.w, "[miss] %s code=%d len=%s title=%q\n",
			r.target, r.rst.OriginUrlStatusCode, r.rst.ContentLength, r.rst.WebTitle); err != nil {
			return err
		}
	}

	if t.debug {
		for _, rule := range r.rst.HitRules {
			fmt.Fprintf(os.Stderr, "[rule] %s: %s\n", r.target, rule)
		}
	}
	return nil
}

func (t *textWriter) Flush() error { return t.w.Flush() }

type jsonWriter struct {
	w     *bufio.Writer
	debug bool
}

func newJSONWriter(w *bufio.Writer, o *ruleOptions) *jsonWriter {
	return &jsonWriter{w: w, debug: o.debug}
}

func (j *jsonWriter) Write(r detectOutcome) error {
	rst := r.rst
	if rst.OriginUrl == "" {
		rst.OriginUrl = r.target
	}
	data, err := json.Marshal(rst)
	if err != nil {
		return err
	}
	if _, err := j.w.Write(data); err != nil {
		return err
	}
	return j.w.WriteByte('\n')
}

func (j *jsonWriter) Flush() error { return j.w.Flush() }

type csvWriter struct {
	w     *bufio.Writer
	cw    *csv.Writer
	debug bool
}

func newCSVWriter(w *bufio.Writer, o *ruleOptions) *csvWriter {
	c := &csvWriter{w: w, cw: csv.NewWriter(w), debug: o.debug}
	_ = c.cw.Write([]string{
		"url", "host", "status", "length", "title", "fingerprints",
		"redirect_url", "site_up", "cert_cn", "cert_ou", "cert_o", "fail_reason",
	})
	return c
}

func (c *csvWriter) Write(r detectOutcome) error {
	rst := r.rst
	if rst.OriginUrl == "" {
		rst.OriginUrl = r.target
	}
	certCN, certOU, certO := "", "", ""
	if rst.CertInfo != nil {
		certCN, certOU, certO = rst.CertInfo.CN, rst.CertInfo.OU, rst.CertInfo.O
	}
	return c.cw.Write([]string{
		rst.OriginUrl,
		rst.Host,
		fmt.Sprintf("%d", rst.OriginUrlStatusCode),
		rst.ContentLength,
		rst.WebTitle,
		strings.Join(RuleClient.SliceRmDuplication(rst.FingerTag), ","),
		rst.RedirectUrl,
		rst.SiteUp,
		certCN, certOU, certO,
		rst.FailReason,
	})
}

func (c *csvWriter) Flush() error {
	c.cw.Flush()
	if err := c.cw.Error(); err != nil {
		return err
	}
	return c.w.Flush()
}

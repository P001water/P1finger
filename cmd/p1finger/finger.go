package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/P001water/p1finger/RuleClient"
	"gopkg.in/yaml.v3"
)

type fingerOptions struct {
	list   bool
	detail bool
	query  string
	fpDir  string
	output string
}

func newFingerFlagSet(o *fingerOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("p1finger finger", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&o.list, "list", false, "list all fingerprints (id / name / tags)")
	fs.BoolVar(&o.detail, "detail", false, "show details of one fingerprint")
	fs.StringVar(&o.query, "id", "", "fingerprint id or name (used with -detail)")
	fs.StringVar(&o.fpDir, "fpdir", "", "fingerprint directory (*.yaml, recursive); default embedded library")
	fs.StringVar(&o.output, "o", "", "write output to file (default stdout)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage:\n")
		fmt.Fprint(fs.Output(), "  p1finger finger -list\n")
		fmt.Fprint(fs.Output(), "  p1finger finger -detail -id <id|name>\n\n")
		fmt.Fprint(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}
	return fs
}

func runFinger(args []string) int {
	o := &fingerOptions{}
	fs := newFingerFlagSet(o)
	flags, positional := splitArgs(fs, args)
	if err := fs.Parse(flags); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}
	// 允许 `p1finger finger <id>` 直接查详情
	if len(positional) > 0 && o.query == "" {
		o.query = positional[0]
		o.detail = true
	}

	if !o.list && !o.detail {
		fs.Usage()
		return 1
	}

	b := RuleClient.NewRuleClientBuilder()
	if o.fpDir != "" {
		b = b.WithFingerprintDiskDir(o.fpDir)
	}
	client, err := b.Build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fingers := client.P1FingerPrints.GetElements()

	var out io.Writer = os.Stdout
	if o.output != "" {
		f, ferr := os.Create(o.output)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, "error:", ferr)
			return 1
		}
		defer f.Close()
		out = f
	}

	if o.list {
		printFingerList(out, fingers)
		fmt.Fprintf(os.Stderr, "total fingerprints: %d\n", len(fingers))
		return 0
	}
	return printFingerDetail(out, fingers, o.query)
}

// printFingerList 按「指纹文件 → id」排序输出，便于核对指纹库结构。
func printFingerList(w io.Writer, fingers []RuleClient.FingerprintsType) {
	sort.Slice(fingers, func(i, j int) bool {
		if fingers[i].FingerFile != fingers[j].FingerFile {
			return fingers[i].FingerFile < fingers[j].FingerFile
		}
		return fingers[i].ID < fingers[j].ID
	})
	for _, fp := range fingers {
		fmt.Fprintf(w, "%-44s %-40s %s\n", fp.ID, fp.Name, strings.Join(fp.Tags, ","))
	}
}

// printFingerDetail 按 id/name 精确匹配，未命中再退化为包含匹配，输出指纹 YAML。
func printFingerDetail(w io.Writer, fingers []RuleClient.FingerprintsType, query string) int {
	if query == "" {
		fmt.Fprintln(os.Stderr, "error: -detail requires -id <id|name>")
		return 1
	}

	q := strings.ToLower(query)
	var exact, fuzzy []RuleClient.FingerprintsType
	for _, fp := range fingers {
		switch {
		case strings.ToLower(fp.ID) == q, strings.ToLower(fp.Name) == q:
			exact = append(exact, fp)
		case strings.Contains(strings.ToLower(fp.ID), q), strings.Contains(strings.ToLower(fp.Name), q):
			fuzzy = append(fuzzy, fp)
		}
	}
	matched := exact
	if len(matched) == 0 {
		matched = fuzzy
	}
	if len(matched) == 0 {
		fmt.Fprintf(os.Stderr, "no fingerprint matched %q\n", query)
		return 1
	}

	for i, fp := range matched {
		if i > 0 {
			fmt.Fprintln(w, "---")
		}
		data, err := yaml.Marshal(fp)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Fprint(w, string(data))
	}
	if len(matched) > 1 {
		fmt.Fprintf(os.Stderr, "matched %d fingerprints\n", len(matched))
	}
	return 0
}

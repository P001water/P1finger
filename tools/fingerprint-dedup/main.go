// Command fingerprint-dedup merges duplicate fingerprint entries (same id)
// across the P1fingersYaml library: matchers and tags are unioned, metadata of
// the first occurrence is kept, and entries left without any matcher are
// dropped. Run it from the repository root:
//
//	go run ./tools/fingerprint-dedup
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type finger struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	FingerFile  string    `yaml:"fingerFile,omitempty"`
	Author      string    `yaml:"author,omitempty"`
	Tags        []string  `yaml:"tags,omitempty"`
	Description string    `yaml:"description,omitempty"`
	Matchers    []matcher `yaml:"matchers,omitempty"`
}

type matcher struct {
	Location        string   `yaml:"location,omitempty"`
	Path            string   `yaml:"path,omitempty"`
	Type            string   `yaml:"type,omitempty"`
	Words           []string `yaml:"words,omitempty"`
	FaviconHash     []string `yaml:"hash,omitempty"`
	BodyHash        string   `yaml:"bodyHash,omitempty"`
	Accuracy        string   `yaml:"accuracy,omitempty"`
	Condition       string   `yaml:"condition,omitempty"`
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`
}

func matcherSig(m matcher) string {
	return fmt.Sprintf("%s|%s|%s|%v|%v|%s|%s|%s|%v",
		m.Location, m.Path, m.Type, m.Words, m.FaviconHash,
		m.BodyHash, m.Accuracy, m.Condition, m.CaseInsensitive)
}

func main() {
	dir := "P1fingersYaml"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		fmt.Println("no fingerprint yaml files found, run from repo root")
		os.Exit(1)
	}
	sort.Strings(files)

	type src struct {
		file string
		f    finger
	}
	var all []src
	crlf := map[string]bool{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		crlf[f] = strings.Contains(string(raw), "\r\n")
		var list []finger
		if err := yaml.Unmarshal(raw, &list); err != nil {
			fmt.Printf("parse error %s: %v\n", f, err)
			os.Exit(1)
		}
		for _, x := range list {
			all = append(all, src{file: f, f: x})
		}
	}
	total := len(all)

	merged := map[string]*finger{}
	var order []string
	firstFile := map[string]string{}
	for _, s := range all {
		id := s.f.ID
		if id == "" {
			id = s.f.Name
		}
		if _, ok := merged[id]; !ok {
			cp := s.f
			cp.Tags = append([]string{}, s.f.Tags...)
			cp.Matchers = append([]matcher{}, s.f.Matchers...)
			merged[id] = &cp
			order = append(order, id)
			firstFile[id] = s.file
			continue
		}
		m := merged[id]
		for _, t := range s.f.Tags {
			dup := false
			for _, ex := range m.Tags {
				if ex == t {
					dup = true
					break
				}
			}
			if !dup {
				m.Tags = append(m.Tags, t)
			}
		}
		seen := map[string]bool{}
		for _, mm := range m.Matchers {
			seen[matcherSig(mm)] = true
		}
		for _, mm := range s.f.Matchers {
			if !seen[matcherSig(mm)] {
				seen[matcherSig(mm)] = true
				m.Matchers = append(m.Matchers, mm)
			}
		}
	}

	var kept []string
	droppedEmpty := 0
	for _, id := range order {
		if len(merged[id].Matchers) == 0 {
			droppedEmpty++
			delete(merged, id)
			continue
		}
		kept = append(kept, id)
	}

	byFile := map[string][]finger{}
	for _, id := range kept {
		byFile[firstFile[id]] = append(byFile[firstFile[id]], *merged[id])
	}

	for _, f := range files {
		list := byFile[f]
		if len(list) == 0 {
			if err := os.Remove(f); err == nil {
				fmt.Printf("%s: removed (empty)\n", filepath.Base(f))
			}
			continue
		}
		raw, err := yaml.Marshal(list)
		if err != nil {
			panic(err)
		}
		content := string(raw)
		if crlf[f] {
			content = strings.ReplaceAll(content, "\n", "\r\n")
		}
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("%s: %d entries\n", filepath.Base(f), len(list))
	}
	fmt.Printf("entries: %d -> %d (removed %d, empty-matcher dropped %d)\n",
		total, len(kept), total-len(kept), droppedEmpty)
}

package RuleClient

import (
	"embed"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	p1finger "github.com/P001water/p1finger"
)

func (r *RuleClient) LoadFingersFromFile(exeDir string, fingerFiles []string) (err error) {

	for _, file := range fingerFiles {
		filePath := filepath.Join(exeDir, file)
		fileInf, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("❌ File %s not existing:", file)
		}

		if filepath.Ext(file) == ".yaml" {
			fileBytes, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("❌ 无法读取文件 %s: %w", fileInf.Name(), err)
			}

			var newFingerprints []FingerprintsType
			err = yaml.Unmarshal(fileBytes, &newFingerprints)
			if err != nil {
				return fmt.Errorf("❌ 解析 YAML 失败 %s: %w", fileInf.Name(), err)
			}

			// 注意：必须按下标写回，range 的值拷贝会导致 FingerFile 丢失，
			// 进而使内置主动探测路径（productPaths/productProbes）注入失效。
			for i := range newFingerprints {
				newFingerprints[i].FingerFile = filepath.Base(fileInf.Name())
			}
			prepareFingerprints(newFingerprints)

			r.P1FingerPrints.FingerSlice = append(r.P1FingerPrints.FingerSlice, newFingerprints...)
		}
	}

	return nil
}

// listYamlFiles 递归收集 dir 下的 *.yaml，返回相对 dir 的路径，
// 供 LoadFingersFromFile 使用。
func listYamlFiles(dir string) ([]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("❌ 指纹目录不可读 %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("❌ %s 不是目录", dir)
	}

	var files []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || strings.ToLower(filepath.Ext(p)) != ".yaml" {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("❌ 遍历指纹目录失败 %s: %w", dir, err)
	}
	sort.Strings(files)
	return files, nil
}

func (r *RuleClient) LoadFingersFromExEfs() (err error) {
	return r.LoadFingersFromFS(p1finger.FingerprintFS, r.DefaultFingerPath)
}

// LoadFingersFromFS 从给定的嵌入文件系统加载指纹库（目录内 *.yaml）。
// 默认使用模块根目录的 P1fingersYaml；P1soda 等使用者可以注入自己的
// 精选指纹库。
// LoadFingersFromFS 从给定的嵌入文件系统加载指纹库（dir 目录内的 *.yaml）。
// 默认使用模块根目录的 P1fingersYaml；P1soda 等使用者可以注入自己的
// 精选指纹库。
func (r *RuleClient) LoadFingersFromFS(fs embed.FS, dir string) (err error) {

	ExeFsFingerFiles, err := fs.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("❌ 无法打开嵌入文件夹 %s: %w（未嵌入全量库时请使用 WithFingerprintFS 注入指纹库）", dir, err)
	}

	for _, file := range ExeFsFingerFiles {
		if filepath.Ext(file.Name()) == ".yaml" {
			fileBytes, err := fs.ReadFile(path.Join(dir, file.Name()))
			if err != nil {
				return fmt.Errorf("❌ 无法读取文件 %s: %w", file.Name(), err)
			}

			var newFingerprints []FingerprintsType
			err = yaml.Unmarshal(fileBytes, &newFingerprints)
			if err != nil {
				return fmt.Errorf("❌ 解析 YAML 失败 %s: %w", file.Name(), err)
			}

			for i := range newFingerprints {
				newFingerprints[i].FingerFile = file.Name()
			}
			prepareFingerprints(newFingerprints)

			r.P1FingerPrints.FingerSlice = append(r.P1FingerPrints.FingerSlice, newFingerprints...)
		}
	}
	return nil
}

// prepareFingerprints precomputes per-matcher matching data that never changes
// across targets: lowercased words and compiled header regexes.
func prepareFingerprints(fps []FingerprintsType) {
	for i := range fps {
		prepareMatchers(fps[i].Matchers)
		for j := range fps[i].Probes {
			prepareMatchers(fps[i].Probes[j].Matchers)
		}
	}
}

func prepareMatchers(matchers []MatcherType) {
	for j := range matchers {
		m := &matchers[j]
		m.wordsLower = make([]string, len(m.Words))
		for k, w := range m.Words {
			m.wordsLower[k] = strings.ToLower(w)
		}
		if m.Type == "regex" && m.Location == "header" && len(m.Words) > 0 {
			if re, err := regexp.Compile(strings.Join(m.Words, "|")); err == nil {
				m.reCompiled = re
			}
		}
	}
}

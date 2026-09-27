// Command p1finger 是 P1finger 指纹识别引擎的独立命令行工具。
//
// 命令结构与 P1finger v0.1.x 保持一致（rule / finger / version / help），
// 默认命令为 rule，因此 `p1finger -u http://x` 等价于 `p1finger rule -u http://x`。
//
// 示例：
//
//	p1finger rule -u https://example.com
//	p1finger rule -f urls.txt --rate 500 -o result.csv
//	p1finger finger -list
//	cat urls.txt | p1finger rule -f -
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

// version 可在构建时注入：go build -ldflags "-X main.version=v0.2.0" ./cmd/p1finger
var version = "v0.1.5"

const banner = `
	██████╗  ██╗███████╗██╗███╗   ██╗ ██████╗ ███████╗██████╗
	██╔══██╗███║██╔════╝██║████╗  ██║██╔════╝ ██╔════╝██╔══██╗
	██████╔╝╚██║█████╗  ██║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
	██╔═══╝  ██║██╔══╝  ██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
	██║      ██║██║     ██║██║ ╚████║╚██████╔╝███████╗██║  ██║
	╚═╝      ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═
	一款红队行动下的重点资产指纹识别工具, Powered by P001water
`

func main() {
	args := os.Args[1:]
	command := "rule"
	// 第一个非 flag 参数视为子命令
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}

	switch command {
	case "rule":
		os.Exit(runRule(args))
	case "finger":
		os.Exit(runFinger(args))
	case "version", "ver":
		printBanner(os.Stdout)
	case "help", "h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		printHelp()
		os.Exit(1)
	}
}

// effectiveVersion 优先使用构建注入的版本号，其次读取模块构建信息
// （go install github.com/P001water/p1finger/cmd/p1finger@vX.Y.Z 场景），
// 最后回退 "dev"。
func effectiveVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	if version == "" {
		return "dev"
	}
	return version
}

func printHelp() {
	w := os.Stdout
	fmt.Fprintf(w, "%s\n", banner)
	fmt.Fprintf(w, "P1finger - web fingerprint engine CLI (%s)\n\n", effectiveVersion())
	fmt.Fprint(w, "Usage:\n")
	fmt.Fprint(w, "  p1finger [command] [flags]\n\n")
	fmt.Fprint(w, "Available Commands:\n")
	fmt.Fprint(w, "  rule       基于本地指纹库的指纹识别（默认命令，可省略）\n")
	fmt.Fprint(w, "  finger     指纹库操作：-list 列出指纹 / -detail -id <id|name> 查看详情\n")
	fmt.Fprint(w, "  version    打印版本\n")
	fmt.Fprint(w, "  help       显示本帮助\n\n")
	fmt.Fprint(w, "Examples:\n")
	fmt.Fprint(w, "  p1finger rule -u https://example.com\n")
	fmt.Fprint(w, "  p1finger rule -f urls.txt --rate 500 -o result.csv\n")
	fmt.Fprint(w, "  p1finger rule -u https://example.com -p socks5://127.0.0.1:1080 --debug\n")
	fmt.Fprint(w, "  p1finger -u https://example.com -silent          # 省略 rule\n")
	fmt.Fprint(w, "  p1finger finger -list\n")
	fmt.Fprint(w, "  cat urls.txt | p1finger rule -f - -o result.json\n\n")
	fmt.Fprint(w, "Flags (rule):\n")
	printRuleFlags(w)
}

// printBanner 把 banner 与版本号写入 w，格式与 version 命令保持一致。
func printBanner(w io.Writer) {
	fmt.Fprintf(w, "%s\n%s\n", banner, effectiveVersion())
}

// stringList 支持重复传参（-u a -u b）与逗号分隔（-u a,b）。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

// splitArgs 把命令行拆成 flag 参数与位置参数，使位置参数可以写在 flag 前后
// （Go 标准 flag 在遇到第一个非 flag 参数后会停止解析）。
func splitArgs(fs *flag.FlagSet, args []string) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		// 单个 "-" 是 stdin 标记，属于位置参数
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}

		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			flags = append(flags, a)
			continue
		}

		flags = append(flags, a)
		f := fs.Lookup(name)
		if f == nil {
			continue // 未知 flag 交给 flag.Parse 报错
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		// 非布尔 flag 需要把下一个参数作为取值
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return flags, positional
}

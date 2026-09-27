<img src="./img/image-20240811182803001.png" alt="image-20240811182803001" style="zoom: 67%;" />

<h3 align="center">P1finger 一款红队行动下的重点资产指纹识别工具</h3>

可独立调用的 P1finger 指纹识别引擎（Go 库），从 P1soda 扫描器中抽离并优化。

## 特性

- 内置 6750+ 条指纹规则（Web 指纹：body / header / title / **favicon** / webPath），随包嵌入，零外部文件依赖
- Aho-Corasick 多模式匹配：8661 条规则全量匹配约 10ms/目标
- 指纹 tags 与 nuclei 风格对齐，识别结果可直接用于 POC 联动
- 进程级单例 `Shared()`：指纹库只加载一次，多协程安全
- 支持注入自定义指纹库（`WithFingerprintFS`），可用 `-tags nofull` 构建去除内置全量库（P1soda 只带精选库时使用）
- 支持主动/被动两阶段探测：被动请求根路径匹配；主动探测指纹声明的特殊路径（`paths`），可对特定路径声明独立匹配器（`probes`）
- 依赖极少：`golang.org/x/net`、`golang.org/x/text`、`gopkg.in/yaml.v3`

## 使用

```go
package main

import (
	"fmt"

	"github.com/P001water/p1finger/RuleClient"
)

func main() {
	client, err := RuleClient.Shared() // 或 NewRuleClientBuilder().Build()
	if err != nil {
		panic(err)
	}

	rst, err := client.Detect("https://example.com")
	if err != nil {
		fmt.Println("detect error:", err)
		return
	}
	fmt.Printf("url=%s code=%d title=%q fingers=%v fail=%q\n",
		rst.OriginUrl, rst.OriginUrlStatusCode, rst.WebTitle, rst.FingerTag, rst.FailReason)
}
```

只加载自定义指纹库（不携带内置全量库时，配合 `-tags nofull` 构建）：

```go
import (
	"embed"
	"github.com/P001water/p1finger/RuleClient"
)

//go:embed fingerprints
var myFingerprints embed.FS

client, _ := RuleClient.NewRuleClientBuilder().
	WithFingerprintFS(myFingerprints).
	WithFingerprintDir("fingerprints").
	Build()
```

`DetectResult` 关键字段：`OriginUrl`、`OriginUrlStatusCode`、`WebTitle`、`ContentLength`、`FingerTag`（指纹名 + tags）、`CertInfo`、`SiteUp`、`FailReason`。

## CLI 使用

编译独立命令行工具（内置全量指纹库）：

```sh
make cli          # 产出 ./p1finger[.exe]
# 或
go build -o p1finger ./cmd/p1finger

make cli-nofull   # 不含内置库的精简版，需用 -fpdir 指定指纹目录
```

命令结构与 v0.1.x 保持一致，`rule` 为默认命令（可省略）：

```sh
p1finger rule -u https://example.com                     # 单目标
p1finger rule -f urls.txt --rate 500 -o result.csv       # 目标文件 → csv
p1finger rule -f urls.txt -o result.json                 # → JSON Lines
p1finger -u https://example.com -silent                  # 省略 rule，只输出命中
cat urls.txt | p1finger rule -f - -o result.json         # 从 stdin 读目标
p1finger rule -u https://example.com -p socks5://127.0.0.1:1080 --debug
p1finger rule -u https://example.com --fpdir ./myfingers # 使用自定义指纹目录

p1finger finger -list                                    # 列出指纹库（id / name / tags）
p1finger finger -detail -id Spring Boot                  # 查看某个指纹详情（YAML）
p1finger version                                         # 版本
```

`rule` 参数：

| 参数 | 说明 |
|---|---|
| `-u`, `--url` | 目标 URL，可重复或逗号分隔；也支持位置参数 |
| `-f`, `--file` | 目标文件，每行一个 URL，`#` 开头的行忽略；`-f -` 从 stdin 读取 |
| `-p`, `--proxy` | HTTP / SOCKS5 代理，如 `socks5://127.0.0.1:1080` |
| `-o`, `--output` | 输出文件，按扩展名决定格式：`.csv` / `.json`(`.jsonl`)；默认输出到 stdout |
| `--rate` | 并发目标数（默认 100，可调大，如 `--rate 500`） |
| `--mode` | 探测模式：`auto` / `passive` / `active`（默认 auto） |
| `--timeout` | 单请求超时（默认 10s） |
| `--per-host` | 同一目标的并发探测上限（默认 3） |
| `--fpdir` | 自定义指纹目录（递归读取 `*.yaml`），默认使用内嵌全量库 |
| `--silent` | 仅输出命中指纹的目标 |
| `--debug` | 输出命中规则明细与请求错误 |
| `--json` | 以 JSON Lines 输出到 stdout |
| `--version` | 打印版本 |

输出示例（统计信息输出到 stderr，便于管道使用）：

```text
[hit]  https://example.com code=200 len=1256 title="Example Domain" finger=nginx
[miss] https://other.com code=404 len=548 title=""
[fail] https://down.com dial tcp 10.0.0.1:80: i/o timeout
targets=3 hit=1 miss=1 fail=1 elapsed=1.2s
```

> 与 v0.1.x 的差异：不再包含 `fofa` 模式与 `upgrade` 子命令（对应依赖已从引擎中移除）；默认输出到 stdout 而不是 `p1finger.csv`（需要文件时用 `-o`）；`--rate` 默认 100 而非 500。

## 主动探测

指纹可声明主动探测路径（复用自身 matchers 判断），或对特定路径声明独立匹配器：

```yaml
- id: weaver-ecology
  name: 泛微 e-cology
  tags: [weaver]
  paths:
    - /wui/index.html
  matchers:
    - location: body
      words: [ecology]

- id: springboot
  name: Spring Boot
  tags: [springboot]
  probes:
    - path: /actuator/env
      matchers:
        - type: word
          location: body
          words: [activeProfiles, applicationConfig]
```

探测模式通过 `WithProbeMode` 设置：`passive`（只请求根路径）、`active`（总是主动探测）、`auto`（默认：被动未命中才主动）。常用产品的内置路径/匹配器在 `productpaths.go`，指纹 YAML 里显式声明即覆盖。

## 维护

指纹库去重：

```sh
go run ./tools/fingerprint-dedup
```

测试与基准：

```sh
go test ./RuleClient/...
go test ./RuleClient/ -run '^$' -bench BenchmarkDetect -benchmem
```

> 默认构建内置全量指纹库；`go build -tags nofull ./...` 不嵌入全量库（此时需通过
> `WithFingerprintFS` 注入指纹库），依赖全量库的测试会自动跳过。

## 在 P1soda 中使用

P1soda 通过 `replace` 使用本模块（见 P1soda 的 go.mod）。



## 指纹库规则和如何贡献指纹

详情参考：[指纹库规范 - 安全漫道.team Wiki](https://securapath.github.io/SecuraPathWiki/P1finger/fingersRepo/)



# 致谢

感谢社区已有的指纹库和整合指纹库做出努力的作者们，P1finger的指纹库在这些巨人的肩膀上建立

- [0x727/FingerprintHub](https://github.com/0x727/FingerprintHub)
- [chainreactors/spray](https://github.com/chainreactors/spray)

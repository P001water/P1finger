//go:build !nofull

// Package p1finger 提供随模块嵌入的指纹库数据访问。
package p1finger

import "embed"

// FingerprintFS 是嵌入的 P1finger 全量指纹库（模块根目录 P1fingersYaml/）。
// 构建时加 -tags nofull 会移除该嵌入（P1soda 只带精选库时使用），此时请通过
// RuleClient.WithFingerprintFS 注入自定义指纹库。
//
//go:embed P1fingersYaml
var FingerprintFS embed.FS

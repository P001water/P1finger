//go:build nofull

// Package p1finger 提供随模块嵌入的指纹库数据访问。
package p1finger

import "embed"

// FingerprintFS 在 -tags nofull 构建下为空（不嵌入全量库）。使用者应通过
// RuleClient.WithFingerprintFS 注入自己的指纹库（如 P1soda 的精选库）。
var FingerprintFS embed.FS

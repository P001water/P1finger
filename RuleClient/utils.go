package RuleClient

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func CheckHttpPrefix(check string) (checked string, err error) {
	if strings.Contains(check, "http") {
		// eg: check = https://101.10.10.1
		checked = check
	} else {
		if strings.Contains(check, ":") {
			// eg: check = 101.10.10.1:9090
			host, port := strings.Split(check, ":")[0], strings.Split(check, ":")[1]
			proto, err := CheckProtocol(host, port)
			if err != nil {
				return checked, err
			}
			checked = fmt.Sprintf("%v://%s:%v", proto, host, port)
		} else {
			// eg: check = 101.10.10.1
			proto := CheckProtocolByIp(check)
			checked = fmt.Sprintf("%v://%s", proto, check)
		}
	}

	return
}

// CheckProtocol 检查给定主机和端口的协议类型（HTTP或HTTPS）
func CheckProtocol(host string, port string) (string, error) {
	protocol := "http" // 默认协议为HTTP
	timeout := 3 * time.Second
	target := fmt.Sprintf("%s:%s", host, port)

	switch port {
	case "80":
		return protocol, nil
	case "443":
		return "https", nil
	}

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return protocol, fmt.Errorf("failed to establish TCP connection: %v", err)
	}
	defer conn.Close()

	// 创建TLS连接并尝试握手
	tlsConn := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true, // 忽略证书验证
	})
	tlsConn.SetDeadline(time.Now().Add(timeout))
	err = tlsConn.Handshake()
	if err == nil {
		protocol = "https"
	}

	return protocol, nil
}

func CheckProtocolByIp(ip string) string {

	//timeout := 3 * time.Second
	// 尝试 HTTPS (443 端口)
	httpsTarget := fmt.Sprintf("%s:443", ip)
	connHttps, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 3 * time.Second,
	}, "tcp", httpsTarget, &tls.Config{
		InsecureSkipVerify: true, // 忽略证书验证
	})
	if err == nil {
		defer connHttps.Close()
		return "https"
	} else {
		return "http"
	}

	//// 如果 HTTPS 失败，检查错误类型，继续尝试 HTTP
	//if _, ok := err.(net.Error); ok && err.Error() == "i/o timeout" {
	//	// 这里可以做更精确的超时判断，避免直接认为是无法访问
	//} else {
	//	// 输出 HTTPS 错误信息
	//	return "http", nil
	//}
	//
	//// 尝试 HTTP (80 端口)
	//httpTarget := fmt.Sprintf("%s:80", ip)
	//connHttp, err := net.DialTimeout("tcp", httpTarget, timeout)
	//if err == nil {
	//	defer connHttp.Close()
	//	return "http", nil
	//}

	// 如果两者都失败，返回错误
	//return "", fmt.Errorf("failed to detect protocol (both HTTP and HTTPS failed): %v", err)
}

// parseHostPort 从URL中解析host和port
func parseHostPort(rawUrl string) (host string, port string) {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return "", ""
	}
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return
}

// GetCertInfo 通过TLS连接获取目标证书信息
func GetCertInfo(host string, port string) *CertInfo {
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 3 * time.Second,
	}, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	subject := certs[0].Subject
	info := &CertInfo{
		CN: subject.CommonName,
	}

	if len(subject.OrganizationalUnit) > 0 {
		info.OU = subject.OrganizationalUnit[0]
	}
	if len(subject.Organization) > 0 {
		info.O = subject.Organization[0]
	}

	return info
}

// 切片去重 使用泛型来去除切片中的重复元素 go > 1.18
func SliceRmDuplication[T comparable](old []T) []T {
	r := make([]T, 0, len(old))
	checkMap := make(map[T]struct{})

	for _, item := range old {
		if _, ok := checkMap[item]; !ok {
			checkMap[item] = struct{}{}
			r = append(r, item)
		}
	}
	return r
}

package p1httputils

import (
	"context"
	"crypto/tls"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HttpClientOption defines the type for setting optional parameters
type HttpClientOption func(*http.Transport)

// WithSocks5Proxy sets the SOCKS5 proxy
func WithSocks5Proxy(socks5Proxy string) HttpClientOption {
	return func(transCfg *http.Transport) {
		if socks5Proxy != "" {
			dialer, err := proxy.SOCKS5("tcp", socks5Proxy, nil, proxy.Direct)
			if err == nil {
				transCfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			}
		}
	}
}

// WithHttpProxy sets the HTTP proxy
func WithHttpProxy(httpProxy string) HttpClientOption {
	return func(transCfg *http.Transport) {
		if httpProxy != "" {
			transCfg.Proxy = func(_ *http.Request) (*url.URL, error) {
				return url.Parse(httpProxy)
			}
		}
	}
}

// NewHttpClient creates a new HTTP client with optional settings
func NewHttpClient(options ...HttpClientOption) *http.Client {
	transCfg := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // disable verify
		DisableKeepAlives: true,
	}

	for _, opt := range options {
		opt(transCfg)
	}

	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transCfg,
	}

	return httpClient
}

type HttpClientBuilder struct {
	transport      *http.Transport
	timeout        time.Duration
	followRedirect bool
}

func NewHttpClientBuilder() *HttpClientBuilder {
	return &HttpClientBuilder{
		transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		timeout:        5 * time.Second,
		followRedirect: true,
	}
}

func (b *HttpClientBuilder) WithTimeout(timeout time.Duration) *HttpClientBuilder {
	b.timeout = timeout
	return b
}

func (b *HttpClientBuilder) WithProxy(proxyAddr string) *HttpClientBuilder {
	if proxyAddr == "" {
		return b
	}

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return b
	}

	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err == nil {
			b.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	default: // assumes HTTP/HTTPS proxy
		b.transport.Proxy = http.ProxyURL(proxyURL)
	}

	return b
}

func (b *HttpClientBuilder) NoRedirect() *HttpClientBuilder {
	b.followRedirect = false
	return b
}

func (b *HttpClientBuilder) Build() *http.Client {
	client := &http.Client{
		Timeout:   b.timeout,
		Transport: b.transport,
	}

	if !b.followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

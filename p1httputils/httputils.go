package p1httputils

import (
	"errors"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	readTimeout   = "read response timeout"
	readBodyError = "read response body error"
	// MaxFingerprintBody caps response body reads for fingerprint matching;
	// far beyond any fingerprint word, but bounds memory on huge pages.
	MaxFingerprintBody = 2 << 20
)

var (
	errorsReadTimeout   = errors.New(readTimeout)
	errorsReadBodyError = errors.New(readBodyError)
)

type P1fingerHttpResp struct {
	Url           string
	StatusCode    int
	ContentLength string
	WebTitle      string `json:"webTitle,omitempty"`
	HeaderRaw     []byte
	HeaderStr     string
	BodyRaw       []byte
	BodyStr string
}

func HttpGet(URL string, customClient *http.Client) (resp *http.Response, CusResp P1fingerHttpResp, err error) {
	// to check if use proxy
	httpClient := customClient

	CusResp.Url = URL
	req, err := NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return resp, CusResp, err
	}

	// to let go/http lib auto decode http request
	if _, ok := req.Header["Accept-Encoding"]; !ok {
		req.Header.Del("Accept-Encoding")
	}

	response, err := httpClient.Do(req)
	if err != nil {
		return resp, CusResp, fmt.Errorf("request fail, %v\n", err)
	}
	defer response.Body.Close() // 在这里关闭 Body

	err = HandleResp2P1fingerResp(response, &CusResp)
	if err != nil {
		return
	}

	return response, CusResp, nil
}

func NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	req.Header.Set("User-Agent", GetRandomUA())
	return req, nil
}

func HandleResp2P1fingerResp(response *http.Response, CusResp *P1fingerHttpResp) (err error) {

	CusResp.StatusCode = response.StatusCode

	CusResp.HeaderStr = GetHeaderStr(response)
	CusResp.HeaderRaw = []byte(CusResp.HeaderStr)

	bodyraw, err := ReadBodyTimeout(response.Body, time.Second*3)
	if err != nil {
		return errorsReadBodyError
	}
	CusResp.BodyRaw = bodyraw

	// if resp is gbk
	if !utf8.Valid(CusResp.BodyRaw) {
		bodyraw, _ = simplifiedchinese.GBK.NewDecoder().Bytes(bodyraw)
		CusResp.BodyRaw = bodyraw
		CusResp.BodyStr = string(bodyraw)
	} else {
		CusResp.BodyStr = string(bodyraw)
	}

	length := response.Header.Get("Content-Length")
	if length == "" {
		length = fmt.Sprintf("%v", len(CusResp.BodyStr))
	}
	CusResp.ContentLength = length
	CusResp.StatusCode = response.StatusCode

	title := ExtractTitle(CusResp)
	CusResp.WebTitle = title
	if CusResp.WebTitle == "" {
		CusResp.WebTitle = "TitleNone"
	}

	return
}

func CheckPageRedirect(resp *http.Response, p1fingerResp P1fingerHttpResp) (string, string, bool) {

	var redirectType string
	loc := resp.Header.Get("Location")
	if loc != "" {
		// While most 3xx responses include a Location, it is not
		// required and 3xx responses without a Location have been
		// observed in the wild. See issues #17773 and #49281.
		redirectType = "Location"
		return redirectType, loc, true
	}

	// 检测HTML中的 <meta http-equiv="Refresh" content="..."> 标签
	metaRegex := regexp.MustCompile(`<meta\s+http-equiv=["']?Refresh["']?\s+content=["']?[^"']*URL=([^\s"']+)["']?`)
	if metaMatch := metaRegex.FindStringSubmatch(p1fingerResp.BodyStr); metaMatch != nil {
		redirectType = "jsRedirect"
		return redirectType, metaMatch[1], true
	}

	// 检测JavaScript中的 window.location.href 或 window.location.replace()
	jsRegex := regexp.MustCompile(`window\.location\.(href|replace)\s*\(\s*["']([^"']+)["']`)
	if jsMatch := jsRegex.FindStringSubmatch(p1fingerResp.BodyStr); jsMatch != nil {
		redirectType = "jsRedirect"
		return redirectType, jsMatch[2], true
	}

	return "", "", false
}

func ReadBodyTimeout(reader io.Reader, duration time.Duration) (buf []byte, err error) {
	// The HTTP client enforces a total request timeout, so a plain bounded
	// read replaces the per-read goroutine and channel.
	return io.ReadAll(io.LimitReader(reader, MaxFingerprintBody))
}

func GetHeaderStr(response *http.Response) string {
	headerString := fmt.Sprintf("%s %s\r\n", response.Proto, response.Status)
	for key, value := range response.Header {
		headerString += fmt.Sprintf("%s: %s\r\n", key, strings.Join(value, ";"))
	}
	return headerString
}

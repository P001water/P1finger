package p1httputils

import (
	"bytes"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"regexp"
	"strings"
)

var (
	cutset  = "\n\t\v\f\r"
	reTitle = regexp.MustCompile(`(?im)<\s*title.*>(.*?)<\s*/\s*title>`)
)

func ExtractTitle(r *P1fingerHttpResp) (title string) {
	// Try to parse the DOM
	titleDom, err := getTitleWithDom(r)
	// In case of error fallback to regex
	if err != nil {
		for _, match := range reTitle.FindAllString(r.BodyStr, -1) {
			title = match
			break
		}
	} else {
		title = renderNode(titleDom)
	}

	title = html.UnescapeString(trimTitleTags(title))

	// remove unwanted chars
	title = strings.TrimSpace(strings.Trim(title, cutset))
	title = ReplaceAll(title, "", "\n", "\t", "\v", "\f", "\r")

	return title
}

func getTitleWithDom(r *P1fingerHttpResp) (*html.Node, error) {
	var title *html.Node
	var crawler func(*html.Node)
	crawler = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "title" {
			title = node
			return
		}
		for child := node.FirstChild; child != nil && title == nil; child = child.NextSibling {
			crawler(child)
		}
	}
	htmlDoc, err := html.Parse(bytes.NewReader(r.BodyRaw))
	if err != nil {
		return nil, err
	}
	crawler(htmlDoc)
	if title != nil {
		return title, nil
	}
	return nil, fmt.Errorf("title not found")
}

func renderNode(n *html.Node) string {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	html.Render(w, n) //nolint
	return buf.String()
}

func trimTitleTags(title string) string {
	// trim <title>*</title>
	titleBegin := strings.Index(title, ">")
	titleEnd := strings.Index(title, "</")
	if titleEnd < 0 || titleBegin < 0 {
		return title
	}
	return title[titleBegin+1 : titleEnd]
}

func ReplaceAll(s, new string, olds ...string) string {
	for _, old := range olds {
		s = strings.ReplaceAll(s, old, new)
	}
	return s
}

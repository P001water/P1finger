package RuleClient

// ahoCorasick is a multi-pattern string matcher (Aho-Corasick). All fingerprint
// words are indexed once at load time; each response is scanned once and every
// dictionary word present in it is returned, replacing thousands of
// strings.Contains calls per target.
type acNode struct {
	next   map[byte]*acNode
	fail   *acNode
	output string // 单词终点：该节点处结束的词
}

type ahoCorasick struct {
	root *acNode
}

func newAhoCorasick(words []string) *ahoCorasick {
	root := &acNode{next: make(map[byte]*acNode)}
	seen := make(map[string]bool)
	for _, w := range words {
		if w == "" || seen[w] {
			continue
		}
		seen[w] = true
		node := root
		for i := 0; i < len(w); i++ {
			c := w[i]
			if node.next[c] == nil {
				node.next[c] = &acNode{next: make(map[byte]*acNode)}
			}
			node = node.next[c]
		}
		node.output = w
	}

	queue := make([]*acNode, 0, 64)
	for _, child := range root.next {
		child.fail = root
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for c, child := range cur.next {
			fail := cur.fail
			for fail != nil && fail.next[c] == nil {
				fail = fail.fail
			}
			if fail == nil {
				child.fail = root
			} else {
				child.fail = fail.next[c]
			}
			queue = append(queue, child)
		}
	}
	return &ahoCorasick{root: root}
}

// find returns the set of dictionary words present anywhere in text.
func (ac *ahoCorasick) find(text string) map[string]bool {
	found := make(map[string]bool)
	node := ac.root
	for i := 0; i < len(text); i++ {
		c := text[i]
		for node.next[c] == nil && node != ac.root {
			node = node.fail
		}
		if n := node.next[c]; n != nil {
			node = n
		}
		for n := node; n != ac.root; n = n.fail {
			if n.output != "" {
				found[n.output] = true
			}
		}
	}
	return found
}

// buildFingerprintAC indexes every word used by body/header/title matchers.
func buildFingerprintAC(fps []FingerprintsType) *ahoCorasick {
	var words []string
	for _, fp := range fps {
		for _, m := range fp.Matchers {
			switch m.Location {
			case "body", "header", "title":
				words = append(words, m.wordsLower...)
			}
		}
		for _, p := range fp.Probes {
			for _, m := range p.Matchers {
				switch m.Location {
				case "body", "header", "title":
					words = append(words, m.wordsLower...)
				}
			}
		}
	}
	return newAhoCorasick(words)
}

package RuleClient

import "sync"

// hostLimiter 是按键（主机）的计数信号量，限制同一目标的并发请求数。
type hostLimiter struct {
	mu   sync.Mutex
	cap  int
	sems map[string]chan struct{}
}

func newHostLimiter(cap int) *hostLimiter {
	if cap <= 0 {
		cap = 1
	}
	return &hostLimiter{cap: cap, sems: map[string]chan struct{}{}}
}

func (h *hostLimiter) acquire(host string) {
	h.mu.Lock()
	sem, ok := h.sems[host]
	if !ok {
		sem = make(chan struct{}, h.cap)
		h.sems[host] = sem
	}
	h.mu.Unlock()
	sem <- struct{}{}
}

func (h *hostLimiter) release(host string) {
	h.mu.Lock()
	sem := h.sems[host]
	h.mu.Unlock()
	<-sem
}

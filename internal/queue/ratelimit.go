package queue

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter объединяет глобальный лимит и лимит на каждую цель,
// чтобы не поймать бан на программе bug bounty.
type RateLimiter struct {
	global    *rate.Limiter
	perTarget map[string]*rate.Limiter
	perRPS    int
	mu        sync.Mutex
}

// NewRateLimiter создаёт лимитер с заданными RPS.
func NewRateLimiter(globalRPS, perTargetRPS int) *RateLimiter {
	return &RateLimiter{
		global:    rate.NewLimiter(rate.Limit(globalRPS), globalRPS),
		perTarget: make(map[string]*rate.Limiter),
		perRPS:    perTargetRPS,
	}
}

// Wait блокируется, пока и глобальный, и целевой лимиты не разрешат действие.
func (r *RateLimiter) Wait(ctx context.Context, target string) error {
	if err := r.global.Wait(ctx); err != nil {
		return err
	}
	return r.targetLimiter(target).Wait(ctx)
}

func (r *RateLimiter) targetLimiter(target string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.perTarget[target]
	if !ok {
		l = rate.NewLimiter(rate.Limit(r.perRPS), r.perRPS)
		r.perTarget[target] = l
	}
	return l
}

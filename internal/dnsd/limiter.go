package dnsd

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// limiter bounds how many queries one source address may make per second.
//
// It is a token bucket per source, refilled continuously. The bucket is what
// makes a normal resolver — which bursts a handful of queries and then goes
// quiet — indistinguishable from unlimited, while a flood is cut off within a
// second.
type limiter struct {
	perSecond float64
	burst     float64

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// sweepInterval is how often idle buckets are collected. Without it the map
// grows once per distinct source address ever seen, which on a public
// nameserver is unbounded — the memory leak being prevented is itself a
// denial-of-service vector.
const sweepInterval = time.Minute

// idleBucketAge is how long a bucket survives with no queries.
const idleBucketAge = 5 * time.Minute

func newLimiter(perSecond int) *limiter {
	return &limiter{
		perSecond: float64(perSecond),
		// A burst of one second's worth lets a resolver ask for A and AAAA
		// back to back without being throttled on a cold cache.
		burst:   float64(perSecond),
		buckets: make(map[netip.Addr]*bucket),
	}
}

// allow reports whether a query from src may be answered.
func (l *limiter) allow(src netip.Addr) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[src]
	if !ok {
		l.buckets[src] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}

	b.tokens += now.Sub(b.last).Seconds() * l.perSecond
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops idle buckets until ctx is done.
func (l *limiter) sweep(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-idleBucketAge)
			l.mu.Lock()
			for addr, b := range l.buckets {
				if b.last.Before(cutoff) {
					delete(l.buckets, addr)
				}
			}
			l.mu.Unlock()
		}
	}
}

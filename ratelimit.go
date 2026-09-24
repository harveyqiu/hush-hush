package main

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	defaultRateLimitPerMinute       = 60
	defaultUnauthRateLimitPerMinute = 10

	// maxBuckets bounds limiter memory. Token-name keys are bounded by the
	// tokens table; this cap exists for the per-IP limiter, whose keys an
	// attacker chooses.
	maxBuckets = 10000
	// pruneInterval is how often idle (fully refilled) buckets are dropped.
	// A full bucket carries no state, so forgetting it changes nothing.
	pruneInterval = time.Minute
	// pruneWhenFullEvery throttles pruning while the map sits at maxBuckets
	// so a flood of new keys can't turn every request into an O(n) sweep.
	pruneWhenFullEvery = time.Second
)

// rateLimiter is an in-memory token-bucket limiter keyed by string.
// Each key gets `capacity` requests of burst, refilled at capacity per
// minute. State is lost on restart, which is acceptable for a limiter.
type rateLimiter struct {
	mu        sync.Mutex
	capacity  float64
	perSecond float64
	buckets   map[string]*bucket
	lastPrune time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{
		capacity:  float64(perMinute),
		perSecond: float64(perMinute) / 60,
		buckets:   map[string]*bucket{},
	}
}

// allow consumes one request for key at time now. When the bucket is
// empty it reports how long until the next request would be allowed.
// now is passed in rather than read from a clock so tests can drive it
// through server.now without sleeping.
func (l *rateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Prune before the lookup: pruning afterwards could delete the bucket
	// we are about to decrement and silently refund the request.
	l.maybePrune(now)
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			// Fail closed: under a key-spraying flood, new keys are
			// limited rather than growing memory without bound. Only the
			// per-IP limiter for failed-auth requests can get here, and
			// for those a 429 instead of a 401 costs nothing.
			return false, pruneInterval
		}
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	} else {
		l.refill(b, now)
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.perSecond * float64(time.Second))
	return false, wait
}

func (l *rateLimiter) refill(b *bucket, now time.Time) {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.capacity, b.tokens+elapsed*l.perSecond)
	}
	// A clock that steps backwards must not mint tokens later; pin last
	// to the newest time seen.
	if now.After(b.last) {
		b.last = now
	}
}

// maybePrune drops buckets that have fully refilled. Caller holds l.mu.
func (l *rateLimiter) maybePrune(now time.Time) {
	since := now.Sub(l.lastPrune)
	if since < pruneInterval && !(len(l.buckets) >= maxBuckets && since >= pruneWhenFullEvery) {
		return
	}
	l.lastPrune = now
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSecond >= l.capacity {
			delete(l.buckets, k)
		}
	}
}

func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// writeRateLimited emits the 429. Retry-After is whole seconds rounded up
// and never 0, so a client honouring it can't retry into the same wall.
func writeRateLimited(w http.ResponseWriter, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, "rate_limited")
}

// ipBucketKey groups IPv6 clients by /64: a single host typically controls
// a whole /64, so per-address buckets would be trivially evaded. IPv4 (and
// "unknown") are used as-is.
func ipBucketKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

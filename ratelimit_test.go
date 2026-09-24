package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeClock drives server.now so bucket refill is tested without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newLimitedServer(t *testing.T, perToken, unauth int) (*server, http.Handler, *fakeClock) {
	t.Helper()
	s, h := newTestServer(t)
	clock := &fakeClock{t: time.Now()}
	s.now = clock.now
	s.tokenLimiter = newRateLimiter(perToken)
	s.ipLimiter = newRateLimiter(unauth)
	return s, h, clock
}

func auditCountWhere(t *testing.T, s *server, where string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	return n
}

// secretCount reads the table directly; going through the API would
// spend the rate limit under test.
func secretCount(t *testing.T, s *server) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&n); err != nil {
		t.Fatalf("count secrets: %v", err)
	}
	return n
}

func assertRateLimited(t *testing.T, rr *httptest.ResponseRecorder, wantRetry string) {
	t.Helper()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body=%s)", rr.Code, rr.Body.String())
	}
	if got := decodeErrBody(t, rr); got != "rate_limited" {
		t.Errorf("error = %q, want rate_limited", got)
	}
	if got := rr.Header().Get("Retry-After"); got != wantRetry {
		t.Errorf("Retry-After = %q, want %q", got, wantRetry)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestRateLimit_PerToken(t *testing.T) {
	s, h, clock := newLimitedServer(t, 3, 10)
	mustInsertToken(t, s, tokenSpec{name: "agent", role: roleAgent, prefixes: []string{"llm."}}, agentToken)

	for i := 0; i < 3; i++ {
		if rr := do(h, authReq("GET", "/v1/secrets", nil)); rr.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i, rr.Code)
		}
	}
	// 3/min refills one request every 20s.
	assertRateLimited(t, do(h, authReq("GET", "/v1/secrets", nil)), "20")

	// The handler must not run: a limited PUT stores nothing.
	assertRateLimited(t, do(h, authReq("PUT", "/v1/secrets/llm.key", []byte(`{"value":"v"}`))), "20")
	if n := secretCount(t, s); n != 0 {
		t.Errorf("rate-limited PUT reached the handler: %d secrets stored", n)
	}

	// Buckets are per token: another token is unaffected.
	if rr := do(h, reqWithToken("GET", "/v1/secrets", agentToken, nil)); rr.Code != http.StatusOK {
		t.Errorf("other token: status %d, want 200", rr.Code)
	}

	if n := auditCountWhere(t, s, `token_name = ? AND result = ?`, "test-admin", resultRateLimited); n != 2 {
		t.Errorf("rate_limited audit rows = %d, want 2", n)
	}
	if n := auditCountWhere(t, s, `action = ? AND secret_name = ? AND result = ?`, actionPut, "llm.key", resultRateLimited); n != 1 {
		t.Errorf("rate-limited PUT audit rows = %d, want 1", n)
	}

	// Partial refill: 10s is half a request, still limited, shorter wait.
	clock.advance(10 * time.Second)
	assertRateLimited(t, do(h, authReq("GET", "/v1/secrets", nil)), "10")

	clock.advance(10 * time.Second)
	if rr := do(h, authReq("GET", "/v1/secrets", nil)); rr.Code != http.StatusOK {
		t.Fatalf("after refill: status %d, want 200", rr.Code)
	}
	assertRateLimited(t, do(h, authReq("GET", "/v1/secrets", nil)), "20")

	// A full minute restores the whole burst, and no more.
	clock.advance(time.Hour)
	for i := 0; i < 3; i++ {
		if rr := do(h, authReq("GET", "/v1/secrets", nil)); rr.Code != http.StatusOK {
			t.Fatalf("after full refill, request %d: status %d", i, rr.Code)
		}
	}
	assertRateLimited(t, do(h, authReq("GET", "/v1/secrets", nil)), "20")
}

func TestRateLimit_UnauthenticatedPerIP(t *testing.T) {
	s, h, clock := newLimitedServer(t, 60, 2)
	badFrom := func(ip string) *http.Request {
		r := reqWithToken("GET", "/v1/secrets/llm.key", "hush_wrong", nil)
		r.RemoteAddr = ip + ":40000"
		return r
	}

	// Successful requests never touch the IP bucket.
	for i := 0; i < 5; i++ {
		r := authReq("GET", "/v1/secrets", nil)
		r.RemoteAddr = "203.0.113.9:1"
		if rr := do(h, r); rr.Code != http.StatusOK {
			t.Fatalf("valid request %d: status %d", i, rr.Code)
		}
	}

	for i := 0; i < 2; i++ {
		if rr := do(h, badFrom("203.0.113.9")); rr.Code != http.StatusUnauthorized {
			t.Fatalf("bad token %d: status %d, want 401", i, rr.Code)
		}
	}
	// 2/min refills one every 30s.
	assertRateLimited(t, do(h, badFrom("203.0.113.9")), "30")

	// A different IP has its own bucket.
	if rr := do(h, badFrom("198.51.100.7")); rr.Code != http.StatusUnauthorized {
		t.Errorf("other IP: status %d, want 401", rr.Code)
	}
	// A valid token from the limited IP still works: the IP limit only
	// applies to failed authentication.
	r := authReq("GET", "/v1/secrets", nil)
	r.RemoteAddr = "203.0.113.9:1"
	if rr := do(h, r); rr.Code != http.StatusOK {
		t.Errorf("valid token from limited IP: status %d, want 200", rr.Code)
	}

	if n := auditCountWhere(t, s, `token_name = '' AND remote_addr = ? AND result = ? AND secret_name = ?`,
		"203.0.113.9", resultRateLimited, "llm.key"); n != 1 {
		t.Errorf("rate_limited audit rows = %d, want 1", n)
	}

	clock.advance(30 * time.Second)
	if rr := do(h, badFrom("203.0.113.9")); rr.Code != http.StatusUnauthorized {
		t.Errorf("after refill: status %d, want 401", rr.Code)
	}
}

// With TRUSTED_PROXIES covering the proxy, each real client gets
// its own unauthenticated bucket rather than all sharing the proxy's.
func TestRateLimit_UnauthBehindProxy(t *testing.T) {
	s, h, _ := newLimitedServer(t, 60, 1)
	s.trustedProxies = loopbackNets
	viaProxy := func(client string) *http.Request {
		r := reqWithToken("GET", "/v1/secrets", "hush_wrong", nil)
		r.RemoteAddr = "127.0.0.1:55555"
		r.Header.Set("X-Forwarded-For", client)
		return r
	}
	if rr := do(h, viaProxy("203.0.113.1")); rr.Code != http.StatusUnauthorized {
		t.Fatalf("client 1: status %d, want 401", rr.Code)
	}
	assertRateLimited(t, do(h, viaProxy("203.0.113.1")), "60")
	if rr := do(h, viaProxy("203.0.113.2")); rr.Code != http.StatusUnauthorized {
		t.Errorf("client 2: status %d, want 401", rr.Code)
	}
	if n := auditCountWhere(t, s, `remote_addr = ?`, "203.0.113.2"); n != 1 {
		t.Errorf("audit rows for forwarded client = %d, want 1", n)
	}
}

// The defaults newServer installs must cover the existing test suite's
// bursts; this pins the documented 60 / 10 figures.
func TestNewServer_DefaultLimits(t *testing.T) {
	s, _ := newTestServer(t)
	if s.tokenLimiter.capacity != 60 || s.ipLimiter.capacity != 10 {
		t.Errorf("defaults = %v / %v, want 60 / 10", s.tokenLimiter.capacity, s.ipLimiter.capacity)
	}
	if len(s.trustedProxies) != 0 {
		t.Error("newServer should trust no proxies by default")
	}
}

func TestRateLimiter_PrunesFullBuckets(t *testing.T) {
	l := newRateLimiter(2)
	t0 := time.Now()
	for i := 0; i < 100; i++ {
		l.allow(fmt.Sprintf("k%d", i), t0)
	}
	l.allow("busy", t0)
	l.allow("busy", t0)
	// Keep "busy" partially drained: at 55s it has refilled 1.83, spend 1.
	if ok, _ := l.allow("busy", t0.Add(55*time.Second)); !ok {
		t.Fatal("busy should have refilled one request")
	}
	if got := l.size(); got != 101 {
		t.Fatalf("size = %d, want 101", got)
	}
	// Past the prune interval every k* bucket (1 used, refills in 30s) is
	// full, but "busy" (about 1.03 of 2) is not and must survive.
	at := t0.Add(61 * time.Second)
	l.allow("probe", at)
	if got := l.size(); got != 2 {
		t.Errorf("after prune size = %d, want 2 (busy + probe)", got)
	}
	if ok, _ := l.allow("busy", at); !ok {
		t.Error("busy should have one request available")
	}
	if ok, _ := l.allow("busy", at); ok {
		t.Error("busy bucket was pruned while partially drained (limit reset)")
	}
}

// Memory is bounded: when the map is full of active buckets, new keys are
// refused rather than stored.
func TestRateLimiter_BoundedMemory(t *testing.T) {
	l := newRateLimiter(1)
	t0 := time.Now()
	for i := 0; i < maxBuckets; i++ {
		l.allow(fmt.Sprintf("k%d", i), t0)
	}
	ok, wait := l.allow("new", t0.Add(2*time.Second))
	if ok || wait <= 0 {
		t.Errorf("new key at capacity: ok=%v wait=%v, want refused", ok, wait)
	}
	if got := l.size(); got != maxBuckets {
		t.Errorf("size = %d, want %d", got, maxBuckets)
	}
	// Once the old buckets refill they are pruned and new keys fit again.
	if ok, _ := l.allow("new", t0.Add(2*time.Minute)); !ok {
		t.Error("new key refused after old buckets refilled")
	}
	if got := l.size(); got != 1 {
		t.Errorf("size after prune = %d, want 1", got)
	}
}

// A clock stepping backwards must not refill or mint tokens.
func TestRateLimiter_ClockGoesBackwards(t *testing.T) {
	l := newRateLimiter(1)
	t0 := time.Now()
	l.allow("k", t0)
	if ok, _ := l.allow("k", t0.Add(-time.Hour)); ok {
		t.Error("backwards clock refilled the bucket")
	}
	if ok, _ := l.allow("k", t0.Add(30*time.Second)); ok {
		t.Error("refilled after only 30s at 1/min")
	}
}

func TestWriteRateLimited_RetryAfterAtLeastOne(t *testing.T) {
	for _, tt := range []struct {
		wait time.Duration
		want string
	}{
		{0, "1"},
		{time.Millisecond, "1"},
		{time.Second, "1"},
		{1500 * time.Millisecond, "2"},
		{20 * time.Second, "20"},
	} {
		rr := httptest.NewRecorder()
		writeRateLimited(rr, tt.wait)
		if got := rr.Header().Get("Retry-After"); got != tt.want {
			t.Errorf("wait %v: Retry-After = %q, want %q", tt.wait, got, tt.want)
		}
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		trust      bool
		remoteAddr string
		xff        []string
		want       string
	}{
		{name: "peer only", remoteAddr: "203.0.113.5:1234", want: "203.0.113.5"},
		{name: "XFF ignored when not trusted", remoteAddr: "127.0.0.1:1", xff: []string{"198.51.100.1"}, want: "127.0.0.1"},
		{name: "trusted loopback uses XFF", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"198.51.100.1"}, want: "198.51.100.1"},
		{name: "IPv6 loopback peer", trust: true, remoteAddr: "[::1]:1", xff: []string{"198.51.100.1"}, want: "198.51.100.1"},
		{name: "rightmost entry wins", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"6.6.6.6, 198.51.100.1"}, want: "198.51.100.1"},
		{name: "rightmost across header lines", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"6.6.6.6", "7.7.7.7, 198.51.100.1"}, want: "198.51.100.1"},
		{name: "IPv6 client normalised", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"2001:DB8::0001"}, want: "2001:db8::1"},
		{name: "spoofed XFF from untrusted peer ignored", trust: true, remoteAddr: "203.0.113.5:1234", xff: []string{"127.0.0.1"}, want: "203.0.113.5"},
		{name: "garbage XFF falls back", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"<script>"}, want: "127.0.0.1"},
		{name: "garbage rightmost does not scan left", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"6.6.6.6, bogus"}, want: "127.0.0.1"},
		{name: "trailing comma falls back", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"6.6.6.6,"}, want: "127.0.0.1"},
		{name: "XFF with port rejected", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{"198.51.100.1:80"}, want: "127.0.0.1"},
		{name: "empty XFF falls back", trust: true, remoteAddr: "127.0.0.1:1", xff: []string{""}, want: "127.0.0.1"},
		{name: "unparseable peer", remoteAddr: "not-an-addr", want: "unknown"},
		{name: "unparseable peer with XFF", trust: true, remoteAddr: "garbage", xff: []string{"198.51.100.1"}, want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			var nets []*net.IPNet
			if tt.trust {
				nets = loopbackNets
			}
			if got := clientIP(r, nets); got != tt.want {
				t.Errorf("clientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIPBucketKey(t *testing.T) {
	if a, b := ipBucketKey("2001:db8:1:2::1"), ipBucketKey("2001:db8:1:2:ffff::9"); a != b {
		t.Errorf("same /64 got different keys %q and %q", a, b)
	}
	if a, b := ipBucketKey("2001:db8:1:2::1"), ipBucketKey("2001:db8:1:3::1"); a == b {
		t.Errorf("different /64s share key %q", a)
	}
	for _, ip := range []string{"203.0.113.5", "unknown"} {
		if got := ipBucketKey(ip); got != ip {
			t.Errorf("ipBucketKey(%q) = %q, want unchanged", ip, got)
		}
	}
}

var loopbackNets = mustNets("127.0.0.0/8,::1")

func mustNets(v string) []*net.IPNet {
	n, err := parseTrustedProxies(v)
	if err != nil {
		panic(err)
	}
	return n
}

// Behind Docker the proxy's address is the bridge gateway, not loopback;
// TRUSTED_PROXIES must cover that case and nothing wider.
func TestClientIP_DockerBridgeProxy(t *testing.T) {
	nets := mustNets("172.17.0.1")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.17.0.1:40000"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := clientIP(r, nets); got != "198.51.100.7" {
		t.Errorf("via bridge proxy = %q, want forwarded client", got)
	}
	r.RemoteAddr = "172.17.0.2:40000" // another container, not the proxy
	if got := clientIP(r, nets); got != "172.17.0.2" {
		t.Errorf("from untrusted neighbour = %q, want its own address", got)
	}
}

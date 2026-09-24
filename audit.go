package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// Audit actions and results. The spec lists allowed / denied / not_found /
// unauthenticated; rate_limited, bad_request and error are added so that
// every request maps to a row instead of being squeezed into a wrong bucket.
const (
	actionGet    = "get"
	actionList   = "list"
	actionPut    = "put"
	actionDelete = "delete"

	resultAllowed         = "allowed"
	resultDenied          = "denied"
	resultNotFound        = "not_found"
	resultUnauthenticated = "unauthenticated"
	resultRateLimited     = "rate_limited"
	resultBadRequest      = "bad_request"
	resultError           = "error"
)

// auditEntry is one audit_log row. It never holds a secret value or a
// token: only names, outcome and correlation data.
type auditEntry struct {
	TokenName  string
	Action     string
	SecretName string
	Result     string
	RequestID  string
	RemoteAddr string
}

func resultForStatus(status int) string {
	switch {
	case status < 400:
		return resultAllowed
	case status == http.StatusUnauthorized:
		return resultUnauthenticated
	case status == http.StatusForbidden:
		return resultDenied
	case status == http.StatusNotFound:
		return resultNotFound
	case status == http.StatusTooManyRequests:
		return resultRateLimited
	case status < 500:
		return resultBadRequest
	default:
		return resultError
	}
}

func (s *server) writeAudit(ctx context.Context, e auditEntry) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (ts, token_name, action, secret_name, result, request_id, remote_addr)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		s.now().Unix(), e.TokenName, e.Action, e.SecretName, e.Result, e.RequestID, e.RemoteAddr)
	return err
}

// bufferedResponse holds a handler's response until the audit row is
// written, so the value of a secret is never sent for a read that could
// not be recorded.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}
func (b *bufferedResponse) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}

func (b *bufferedResponse) flushTo(w http.ResponseWriter) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

// secretsRoute is the single entry point for every /v1/secrets request:
// authentication, then the handler, then exactly one audit row.
func (s *server) secretsRoute(action string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		e := auditEntry{
			Action:     action,
			RequestID:  requestIDFrom(ctx),
			RemoteAddr: clientIP(r, s.trustProxy),
		}
		// Only well-formed names are recorded; anything else is logged as
		// empty so arbitrary client bytes never land in the audit table.
		if name := r.PathValue("name"); nameRe.MatchString(name) {
			e.SecretName = name
		}

		buf := &bufferedResponse{header: http.Header{}}
		p, err := s.authenticate(ctx, r)
		switch {
		case errors.Is(err, errUnauthenticated):
			// Only failed authentications spend the per-IP budget, so a
			// shared NAT or proxy can't lock out valid tokens behind it.
			if ok, wait := s.ipLimiter.allow(ipBucketKey(e.RemoteAddr), s.now()); !ok {
				writeRateLimited(buf, wait)
			} else {
				writeErr(buf, http.StatusUnauthorized, "unauthorized")
			}
		case err != nil:
			slog.ErrorContext(ctx, "token lookup failed", "error", err)
			writeErr(buf, http.StatusInternalServerError, "db error")
		default:
			e.TokenName = p.name
			if ok, wait := s.tokenLimiter.allow(p.name, s.now()); !ok {
				writeRateLimited(buf, wait)
			} else {
				h(buf, r.WithContext(context.WithValue(ctx, principalKey{}, p)))
			}
		}
		if buf.status == 0 {
			buf.status = http.StatusOK
		}
		e.Result = resultForStatus(buf.status)

		if err := s.writeAudit(ctx, e); err != nil {
			slog.ErrorContext(ctx, "audit write failed", "error", err,
				"token_name", e.TokenName, "action", e.Action, "secret_name", e.SecretName, "result", e.Result)
			// Fail closed for reads: don't hand out data we couldn't
			// record. A write has already happened by now, so report it
			// truthfully rather than claim it failed.
			if e.Result == resultAllowed && (action == actionGet || action == actionList) {
				writeErr(w, http.StatusInternalServerError, "audit failed")
				return
			}
		}
		slog.InfoContext(ctx, "secret access",
			"token_name", e.TokenName, "action", e.Action, "secret_name", e.SecretName,
			"result", e.Result, "status", buf.status, "remote_addr", e.RemoteAddr)
		buf.flushTo(w)
	}
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// clientIP returns the caller's IP without the port, or "unknown". It is
// the audit remote_addr and the key for the unauthenticated rate limit.
//
// With trustProxy, X-Forwarded-For is honoured only when the direct peer is
// loopback, i.e. the co-located reverse proxy; from anyone else the header
// is attacker-controlled and ignored. Only the rightmost entry is used:
// Caddy appends the address it saw, and everything to its left came from
// the client. If that entry is not a valid IP we fall back to the peer
// rather than scanning further left into client-supplied values.
func clientIP(r *http.Request, trustProxy bool) string {
	peer := parseIP(r.RemoteAddr)
	if trustProxy && peer != nil && peer.IsLoopback() {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			last := xff[len(xff)-1]
			if i := strings.LastIndexByte(last, ','); i >= 0 {
				last = last[i+1:]
			}
			if ip := net.ParseIP(strings.TrimSpace(last)); ip != nil {
				return ip.String()
			}
		}
	}
	if peer == nil {
		return "unknown"
	}
	return peer.String()
}

// parseIP accepts "host:port" or a bare IP. RemoteAddr is always set by
// net/http; the bare form keeps odd test or proxy values well-formed.
func parseIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

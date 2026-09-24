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
			RemoteAddr: clientIP(r),
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
			writeErr(buf, http.StatusUnauthorized, "unauthorized")
		case err != nil:
			slog.ErrorContext(ctx, "token lookup failed", "error", err)
			writeErr(buf, http.StatusInternalServerError, "db error")
		default:
			e.TokenName = p.name
			h(buf, r.WithContext(context.WithValue(ctx, principalKey{}, p)))
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

// clientIP returns the caller's IP without the port. RemoteAddr is always
// set by net/http; the fallback keeps the column well-formed regardless.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		return ip.String()
	}
	return "unknown"
}

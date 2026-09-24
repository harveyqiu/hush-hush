package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Admin HTTP API behind the web UI. Every route runs through secretsRoute
// (authentication, rate limit, exactly one audit row) and requireAdmin, so
// agent tokens get 403 before any parsing. Mutations commit together with
// their audit row via commitWithAudit. Disabled entirely by ADMIN_API=false.

// Admin audit actions. secret_name holds the target token name for the
// token actions and is empty for list/audit reads.
const (
	actionTokenList   = "token_list"
	actionTokenCreate = "token_create"
	actionTokenUpdate = "token_update"
	actionTokenRevoke = "token_revoke"
	actionAuditRead   = "audit_read"
)

// maxAdminBody bounds admin request bodies; they carry names and prefix
// lists only.
const maxAdminBody = 16 * 1024

func (s *server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/tokens", s.secretsRoute(actionTokenList, requireAdmin(s.adminListTokens)))
	mux.HandleFunc("POST /v1/admin/tokens", s.secretsRoute(actionTokenCreate, requireAdmin(s.adminCreateToken)))
	mux.HandleFunc("PATCH /v1/admin/tokens/{name}", s.secretsRoute(actionTokenUpdate, requireAdmin(s.adminUpdateToken)))
	mux.HandleFunc("DELETE /v1/admin/tokens/{name}", s.secretsRoute(actionTokenRevoke, requireAdmin(s.adminRevokeToken)))
	mux.HandleFunc("GET /v1/admin/audit", s.secretsRoute(actionAuditRead, requireAdmin(s.adminAudit)))
	// Anything else under /v1/admin is still authenticated and audited.
	mux.HandleFunc("/v1/admin/", s.secretsRoute(actionOther, requireAdmin(func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotFound, "not found")
	})))
}

// decodeAdminJSON applies the same strictness as PUT /v1/secrets: JSON
// content type, bounded size, no unknown fields, no trailing data.
func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAdminBody+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return false
	}
	if len(body) > maxAdminBody {
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return false
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "trailing data after json")
		return false
	}
	return true
}

// tokenErrStatus maps shared-layer errors to HTTP. Anything unrecognised
// is an internal error and is not echoed to the client.
func tokenErrStatus(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errTokenExists), errors.Is(err, errTokenRevoked), errors.Is(err, errNotAgentToken):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, errTokenNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	default:
		slog.ErrorContext(r.Context(), "admin token operation failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
	}
}

func (s *server) adminListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := listTokens(r.Context(), s.db, s.now())
	if err != nil {
		tokenErrStatus(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

type createTokenRequest struct {
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	Prefixes      []string `json:"prefixes"`
	WritePrefixes []string `json:"write_prefixes"`
	// Expires is a lifetime such as "90d" or "12h"; empty means never.
	Expires string `json:"expires"`
	// ConfirmAll must be true to grant the "*" read prefix, mirroring the
	// CLI's retype-the-name prompt.
	ConfirmAll bool `json:"confirm_all"`
}

func (s *server) adminCreateToken(w http.ResponseWriter, r *http.Request) {
	var in createTokenRequest
	if !decodeAdminJSON(w, r, &in) {
		return
	}
	setAuditTarget(r.Context(), in.Name)
	now := s.now()
	spec := tokenSpec{name: in.Name, role: in.Role, prefixes: in.Prefixes, writePrefixes: in.WritePrefixes}
	if in.Expires != "" {
		d, err := parseExpiry(in.Expires)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid expires (use e.g. 90d or 12h)")
			return
		}
		t := now.Add(d)
		spec.expiresAt = &t
	}
	if err := validateTokenSpec(spec); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if grantsAll(in.Prefixes) && !in.ConfirmAll {
		writeErr(w, http.StatusBadRequest, `prefix "*" grants every secret; resend with "confirm_all": true`)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		tokenErrStatus(w, r, err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	plaintext, warnings, err := createToken(r.Context(), tx, spec, now)
	if err != nil {
		// Validation already passed, so this is a name clash or internal.
		tokenErrStatus(w, r, err)
		return
	}
	if err := s.commitWithAudit(r.Context(), tx); err != nil {
		slog.ErrorContext(r.Context(), "token create commit failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "audit failed")
		return
	}
	if warnings == nil {
		warnings = []string{}
	}
	// The only time the plaintext exists outside the caller. The response
	// is no-store and is never logged.
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":     in.Name,
		"token":    plaintext,
		"warnings": warnings,
	})
}

type updateTokenRequest struct {
	// A missing field keeps the current list; [] clears it.
	Prefixes      *[]string `json:"prefixes"`
	WritePrefixes *[]string `json:"write_prefixes"`
	ConfirmAll    bool      `json:"confirm_all"`
}

func (s *server) adminUpdateToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !tokenNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	var in updateTokenRequest
	if !decodeAdminJSON(w, r, &in) {
		return
	}
	if in.Prefixes == nil && in.WritePrefixes == nil {
		writeErr(w, http.StatusBadRequest, "give prefixes and/or write_prefixes")
		return
	}
	if in.Prefixes != nil && grantsAll(*in.Prefixes) && !in.ConfirmAll {
		writeErr(w, http.StatusBadRequest, `prefix "*" grants every secret; resend with "confirm_all": true`)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		tokenErrStatus(w, r, err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	read, write, warnings, err := updateTokenGrants(r.Context(), tx, name,
		grantUpdate{prefixes: in.Prefixes, writePrefixes: in.WritePrefixes})
	if err != nil {
		var ge grantError
		if errors.As(err, &ge) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		tokenErrStatus(w, r, err)
		return
	}
	if err := s.commitWithAudit(r.Context(), tx); err != nil {
		slog.ErrorContext(r.Context(), "token update commit failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "audit failed")
		return
	}
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "prefixes": read, "write_prefixes": write, "warnings": warnings,
	})
}

func (s *server) adminRevokeToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !tokenNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	// Revoking the token making this request is refused: it would lock the
	// operator out of the UI mid-session. Use another admin token or the CLI.
	if principalFrom(r.Context()).name == name {
		writeErr(w, http.StatusConflict, "refusing to revoke the token used for this request")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		tokenErrStatus(w, r, err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	already, err := revokeToken(r.Context(), tx, name, s.now())
	if err != nil {
		tokenErrStatus(w, r, err)
		return
	}
	if err := s.commitWithAudit(r.Context(), tx); err != nil {
		slog.ErrorContext(r.Context(), "token revoke commit failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "audit failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "revoked": true, "already_revoked": already})
}

// adminAudit serves GET /v1/admin/audit?token=&secret=&action=&result=
// &since=&until=&limit=. since/until take unix seconds, RFC3339, or an age
// such as 24h / 7d.
func (s *server) adminAudit(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	f := auditFilter{
		Token:  qs.Get("token"),
		Secret: qs.Get("secret"),
		Action: qs.Get("action"),
		Result: qs.Get("result"),
		Limit:  auditDefaultLimit,
	}
	if v := qs.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "limit must be an integer")
			return
		}
		f.Limit = n
	}
	now := s.now()
	for _, t := range []struct {
		key string
		dst **int64
	}{{"since", &f.Since}, {"until", &f.Until}} {
		ts, ok, err := parseQueryTime(qs, t.key, now)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid "+t.key)
			return
		}
		if ok {
			*t.dst = &ts
		}
	}
	if err := f.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	records, err := queryAudit(r.Context(), s.db, f)
	if err != nil {
		slog.ErrorContext(r.Context(), "audit query failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func parseQueryTime(qs url.Values, key string, now time.Time) (int64, bool, error) {
	v := qs.Get(key)
	if v == "" {
		return 0, false, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n, true, nil
	}
	ts, err := parseAuditTime(key, v, now)
	return ts, err == nil, err
}

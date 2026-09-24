package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	auditDefaultLimit = 100
	// auditMaxLimit bounds a single query's output; narrow with --since /
	// --until to see further back.
	auditMaxLimit = 10000
)

var (
	auditActions = []string{actionGet, actionList, actionPut, actionDelete, actionOther,
		actionTokenList, actionTokenCreate, actionTokenUpdate, actionTokenRevoke, actionAuditRead, actionWhoami}
	auditResults = []string{resultAllowed, resultDenied, resultNotFound, resultUnauthenticated,
		resultRateLimited, resultBadRequest, resultConflict, resultError}
)

// parseAuditTime accepts an RFC3339 timestamp or a duration meaning "that
// long before now" (e.g. 24h, 7d), and returns Unix seconds.
func parseAuditTime(flagName, s string, now time.Time) (int64, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Unix(), nil
	}
	d, err := parseExpiry(s)
	if err != nil {
		return 0, usageErr("audit: invalid --%s %q (use RFC3339 like 2026-09-01T00:00:00Z, or a duration ago like 24h or 7d)", flagName, s)
	}
	return now.Add(-d).Unix(), nil
}

// auditFilter selects audit_log rows. Zero values mean "no filter".
type auditFilter struct {
	Token, Secret, Action, Result string
	Since, Until                  *int64 // unix seconds; since inclusive, until exclusive
	Limit                         int
}

// auditRecord is one audit_log row as returned to admins.
type auditRecord struct {
	TS         int64  `json:"ts"`
	TokenName  string `json:"token_name"`
	Action     string `json:"action"`
	SecretName string `json:"secret_name"`
	Result     string `json:"result"`
	RemoteAddr string `json:"remote_addr"`
	RequestID  string `json:"request_id"`
}

// validate checks the enumerated fields and bounds. Errors are plain
// messages suitable for both a usage error and a 400.
func (f auditFilter) validate() error {
	if f.Limit <= 0 || f.Limit > auditMaxLimit {
		return fmt.Errorf("limit must be between 1 and %d, got %d", auditMaxLimit, f.Limit)
	}
	if f.Action != "" && !slices.Contains(auditActions, f.Action) {
		return fmt.Errorf("action must be one of %s", strings.Join(auditActions, ", "))
	}
	if f.Result != "" && !slices.Contains(auditResults, f.Result) {
		return fmt.Errorf("result must be one of %s", strings.Join(auditResults, ", "))
	}
	if f.Since != nil && f.Until != nil && *f.Since >= *f.Until {
		return errors.New("since must be earlier than until")
	}
	return nil
}

// queryAudit returns matching rows, newest first. The WHERE clause is
// assembled from constant fragments only; every value is a bound argument.
func queryAudit(ctx context.Context, q dbtx, f auditFilter) ([]auditRecord, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	var conds []string
	var args []any
	for _, c := range []struct{ col, val string }{
		{"token_name = ?", f.Token},
		{"secret_name = ?", f.Secret},
		{"action = ?", f.Action},
		{"result = ?", f.Result},
	} {
		if c.val != "" {
			conds = append(conds, c.col)
			args = append(args, c.val)
		}
	}
	if f.Since != nil {
		conds = append(conds, "ts >= ?")
		args = append(args, *f.Since)
	}
	if f.Until != nil {
		conds = append(conds, "ts < ?")
		args = append(args, *f.Until)
	}
	query := `SELECT ts, token_name, action, secret_name, result, remote_addr, request_id FROM audit_log`
	if len(conds) > 0 {
		query += ` WHERE ` + strings.Join(conds, ` AND `) // #nosec G202 -- constant fragments only; values are bound
	}
	query += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, f.Limit)

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auditRecord{}
	for rows.Next() {
		var r auditRecord
		if err := rows.Scan(&r.TS, &r.TokenName, &r.Action, &r.SecretName, &r.Result, &r.RemoteAddr, &r.RequestID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// cmdAudit prints audit_log rows, newest first. It reads the database file
// directly, like the token subcommands, so it works with the server down.
func cmdAudit(args []string, stdout io.Writer) error {
	fs, dbPath := newFlagSet("audit")
	f := auditFilter{}
	fs.StringVar(&f.Token, "token", "", "only rows for this token name")
	fs.StringVar(&f.Secret, "secret", "", "only rows for this secret name")
	fs.StringVar(&f.Action, "action", "", "only this action: "+strings.Join(auditActions, ", "))
	fs.StringVar(&f.Result, "result", "", "only this result: "+strings.Join(auditResults, ", "))
	since := fs.String("since", "", "only rows at or after this time (RFC3339, or e.g. 24h / 7d ago)")
	until := fs.String("until", "", "only rows before this time (RFC3339, or e.g. 24h / 7d ago)")
	fs.IntVar(&f.Limit, "limit", auditDefaultLimit, "maximum rows to print")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	now := time.Now()
	for _, t := range []struct {
		flag, val string
		dst       **int64
	}{{"since", *since, &f.Since}, {"until", *until, &f.Until}} {
		if t.val == "" {
			continue
		}
		ts, err := parseAuditTime(t.flag, t.val, now)
		if err != nil {
			return err
		}
		*t.dst = &ts
	}
	if err := f.validate(); err != nil {
		return usageErr("audit: %v", err)
	}

	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	records, err := queryAudit(context.Background(), db, f)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tTOKEN\tACTION\tSECRET\tRESULT\tREMOTE\tREQUEST_ID")
	for _, r := range records {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			time.Unix(r.TS, 0).UTC().Format(time.RFC3339),
			orDash(r.TokenName), r.Action, orDash(r.SecretName), r.Result, orDash(r.RemoteAddr), orDash(r.RequestID))
	}
	return tw.Flush()
}

// orDash keeps columns aligned and greppable when a field is empty (e.g.
// no token on an unauthenticated request, no secret on a list).
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

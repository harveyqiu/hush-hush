package main

import (
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
	auditActions = []string{actionGet, actionList, actionPut, actionDelete, actionOther}
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

// cmdAudit prints audit_log rows, newest first. It reads the database file
// directly, like the token subcommands, so it works with the server down.
func cmdAudit(args []string, stdout io.Writer) error {
	fs, dbPath := newFlagSet("audit")
	token := fs.String("token", "", "only rows for this token name")
	secret := fs.String("secret", "", "only rows for this secret name")
	action := fs.String("action", "", "only this action: "+strings.Join(auditActions, ", "))
	result := fs.String("result", "", "only this result: "+strings.Join(auditResults, ", "))
	since := fs.String("since", "", "only rows at or after this time (RFC3339, or e.g. 24h / 7d ago)")
	until := fs.String("until", "", "only rows before this time (RFC3339, or e.g. 24h / 7d ago)")
	limit := fs.Int("limit", auditDefaultLimit, "maximum rows to print")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *limit <= 0 || *limit > auditMaxLimit {
		return usageErr("audit: --limit must be between 1 and %d, got %d", auditMaxLimit, *limit)
	}
	if *action != "" && !slices.Contains(auditActions, *action) {
		return usageErr("audit: --action must be one of %s", strings.Join(auditActions, ", "))
	}
	if *result != "" && !slices.Contains(auditResults, *result) {
		return usageErr("audit: --result must be one of %s", strings.Join(auditResults, ", "))
	}

	// WHERE is assembled from constant fragments only; every user-supplied
	// value is a bound argument.
	var conds []string
	var qargs []any
	for _, f := range []struct {
		col, val string
	}{
		{"token_name = ?", *token},
		{"secret_name = ?", *secret},
		{"action = ?", *action},
		{"result = ?", *result},
	} {
		if f.val != "" {
			conds = append(conds, f.col)
			qargs = append(qargs, f.val)
		}
	}
	now := time.Now()
	var sinceTS, untilTS *int64
	if *since != "" {
		ts, err := parseAuditTime("since", *since, now)
		if err != nil {
			return err
		}
		sinceTS = &ts
		conds = append(conds, "ts >= ?")
		qargs = append(qargs, ts)
	}
	if *until != "" {
		ts, err := parseAuditTime("until", *until, now)
		if err != nil {
			return err
		}
		untilTS = &ts
		conds = append(conds, "ts < ?")
		qargs = append(qargs, ts)
	}
	if sinceTS != nil && untilTS != nil && *sinceTS >= *untilTS {
		return usageErr("audit: --since must be earlier than --until")
	}

	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	query := `SELECT ts, token_name, action, secret_name, result, remote_addr, request_id FROM audit_log`
	if len(conds) > 0 {
		query += ` WHERE ` + strings.Join(conds, ` AND `) // #nosec G202 -- constant fragments only; values are bound
	}
	query += ` ORDER BY ts DESC, id DESC LIMIT ?`
	qargs = append(qargs, *limit)

	rows, err := db.Query(query, qargs...)
	if err != nil {
		return err
	}
	defer rows.Close()

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tTOKEN\tACTION\tSECRET\tRESULT\tREMOTE\tREQUEST_ID")
	for rows.Next() {
		var ts int64
		var tok, act, sec, res, remote, reqID string
		if err := rows.Scan(&ts, &tok, &act, &sec, &res, &remote, &reqID); err != nil {
			return err
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			time.Unix(ts, 0).UTC().Format(time.RFC3339),
			orDash(tok), act, orDash(sec), res, orDash(remote), orDash(reqID))
	}
	if err := rows.Err(); err != nil {
		return err
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

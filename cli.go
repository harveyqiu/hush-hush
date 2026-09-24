package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const cliUsage = `hush-hush — self-hosted secret store (server + admin CLI).

Usage:
  hush-hush [serve]                 Start the HTTP API (default with no subcommand)
  hush-hush token create --name N --role agent --prefix llm. [--prefix github.] [--expires 90d]
  hush-hush token create --name N --role admin [--expires 90d]
  hush-hush token create --name N --role agent --write-prefix crawler. [--prefix crawler.]
  hush-hush token list
  hush-hush token revoke --name N
  hush-hush token update --name N [--prefix llm. ...] [--write-prefix crawler. ... | --no-write]
  hush-hush audit [--token N] [--secret N] [--action get|list|put|delete|other] [--result R]
                  [--since T] [--until T] [--limit 100]
                                    T is RFC3339 (2026-09-01T00:00:00Z) or an age (24h, 7d)
  hush-hush help

Admin subcommands operate directly on the database file, not over HTTP.
Run them as the user that owns the database (e.g. sudo -u hush ...).
Every admin subcommand accepts --db PATH (default: $DB_PATH, else ./hush.db).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run dispatches one invocation. Split from main so tests can drive the
// admin subcommands with arbitrary args and I/O.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "serve" {
		if len(args) > 1 {
			fmt.Fprintf(stderr, "serve takes no arguments; configure it with environment variables\n")
			return 2
		}
		serve()
		return 0
	}
	// Admin commands: human-readable warnings to stderr, never stdout
	// (stdout carries the new token for `token create`).
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	var err error
	switch args[0] {
	case "token":
		err = cmdToken(args[1:], stdin, stdout, stderr)
	case "audit":
		err = cmdAudit(args[1:], stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, cliUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[0], cliUsage)
		return 2
	}
	if errors.Is(err, errUsage) {
		fmt.Fprintf(stderr, "error: %v\n\n%s", err, cliUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

var errUsage = errors.New("usage")

func usageErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, a...))
}

// multiFlag collects a repeatable string flag (--prefix a --prefix b).
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func newFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", getenv("DB_PATH", "./hush.db"), "database path")
	return fs, db
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usageErr("%s: %v", fs.Name(), err)
	}
	if fs.NArg() > 0 {
		return usageErr("%s: unexpected argument %q", fs.Name(), fs.Arg(0))
	}
	return nil
}

// openAdminDB opens an existing database for an admin subcommand. It will
// not create one: a typo in --db should fail loudly instead of producing
// an empty database, and a root-created file would lock the service user
// out. For the same reason it refuses to run as a user other than the
// file's owner, since SQLite would create WAL/SHM files that user owns.
func openAdminDB(path string) (*sql.DB, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("database %s: %w (start the server once to create it, or check --db / DB_PATH)", path, err)
	}
	if err := checkOwner(fi); err != nil {
		return nil, err
	}
	return openDB(path)
}

func cmdToken(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageErr("token: missing subcommand (create, list, revoke, update)")
	}
	switch args[0] {
	case "create":
		return cmdTokenCreate(args[1:], stdin, stdout, stderr)
	case "list":
		return cmdTokenList(args[1:], stdout)
	case "revoke":
		return cmdTokenRevoke(args[1:], stdout)
	case "update":
		return cmdTokenUpdate(args[1:], stdin, stdout, stderr)
	default:
		return usageErr("token: unknown subcommand %q", args[0])
	}
}

// parseExpiry accepts Go durations ("12h", "90m") plus a day suffix
// ("90d"), which time.ParseDuration lacks.
func parseExpiry(s string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid --expires %q", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid --expires %q (use e.g. 90d or 12h)", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("--expires must be positive, got %q", s)
	}
	return d, nil
}

// confirmAllSecrets asks the operator to retype the token name before a
// "*" grant is written. There is deliberately no flag to skip it; scripts
// can pipe the name on stdin.
func confirmAllSecrets(name string, stdin io.Reader, stderr io.Writer) error {
	fmt.Fprintf(stderr, "WARNING: prefix \"*\" lets %q read EVERY secret, including ones added later.\n", name)
	fmt.Fprintf(stderr, "Type the token name to confirm: ")
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(line) != name {
		return errors.New("confirmation did not match; nothing changed")
	}
	return nil
}

func cmdTokenCreate(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dbPath := newFlagSet("token create")
	name := fs.String("name", "", "token name (required)")
	role := fs.String("role", "", "admin or agent (required)")
	expires := fs.String("expires", "", "lifetime, e.g. 90d or 12h (default: never)")
	var prefixes, writePrefixes multiFlag
	fs.Var(&prefixes, "prefix", "readable name prefix, repeatable (agent only)")
	fs.Var(&writePrefixes, "write-prefix", "create-only name prefix, repeatable (agent only)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !tokenNameRe.MatchString(*name) {
		return usageErr("token create: --name must match %s", tokenNameRe)
	}
	if *role == "" {
		return usageErr("token create: --role is required (admin or agent)")
	}
	now := time.Now()
	spec := tokenSpec{name: *name, role: *role, prefixes: prefixes, writePrefixes: writePrefixes}
	if *expires != "" {
		d, err := parseExpiry(*expires)
		if err != nil {
			return fmt.Errorf("token create: %w", err)
		}
		t := now.Add(d)
		spec.expiresAt = &t
	}
	// Validate before touching the database or prompting.
	if err := validateTokenSpec(spec); err != nil {
		return fmt.Errorf("token create: %w", err)
	}

	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()

	if exists, err := tokenExists(ctx, db, *name); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("token create: %w", errTokenExists)
	}
	if grantsAll(prefixes) {
		if err := confirmAllSecrets(*name, stdin, stderr); err != nil {
			return err
		}
	}
	plaintext, warnings, err := createToken(ctx, db, spec, now)
	if err != nil {
		return fmt.Errorf("token create: %w", err)
	}
	printWarnings(stderr, warnings)
	fmt.Fprintf(stderr, "created %s token %q. Store it now; it cannot be shown again:\n", *role, *name)
	fmt.Fprintln(stdout, plaintext)
	return nil
}

func printWarnings(w io.Writer, warnings []string) {
	for _, m := range warnings {
		fmt.Fprintf(w, "WARNING: %s\n", m)
	}
}

func fmtUnix(v *int64) string {
	if v == nil {
		return "-"
	}
	return time.Unix(*v, 0).UTC().Format(time.RFC3339)
}

func cmdTokenList(args []string, stdout io.Writer) error {
	fs, dbPath := newFlagSet("token list")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tokens, err := listTokens(context.Background(), db, time.Now())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tROLE\tPREFIXES\tWRITE\tSTATUS\tEXPIRES\tLAST_USED\tCREATED")
	for _, t := range tokens {
		pre, write := orDash(strings.Join(t.Prefixes, ",")), orDash(strings.Join(t.WritePrefixes, ","))
		if t.Role == roleAdmin {
			pre, write = "(all)", "(all, overwrite+delete)"
		}
		created := t.CreatedAt
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.Name, t.Role, pre, write, t.Status,
			fmtUnix(t.ExpiresAt), fmtUnix(t.LastUsedAt), fmtUnix(&created))
	}
	return tw.Flush()
}

func cmdTokenRevoke(args []string, stdout io.Writer) error {
	fs, dbPath := newFlagSet("token revoke")
	name := fs.String("name", "", "token name (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageErr("token revoke: --name is required")
	}
	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	already, err := revokeToken(context.Background(), db, *name, time.Now())
	if err != nil {
		return fmt.Errorf("token revoke: %q: %w", *name, err)
	}
	if already {
		fmt.Fprintf(stdout, "%q was already revoked\n", *name)
		return nil
	}
	fmt.Fprintf(stdout, "revoked %q; it is rejected from the next request on\n", *name)
	return nil
}

func cmdTokenUpdate(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs, dbPath := newFlagSet("token update")
	name := fs.String("name", "", "token name (required)")
	var prefixes, writePrefixes multiFlag
	fs.Var(&prefixes, "prefix", "new read prefix set, repeatable; replaces the old set")
	fs.Var(&writePrefixes, "write-prefix", "new create-only prefix set, repeatable; replaces the old set")
	noWrite := fs.Bool("no-write", false, "remove all write prefixes")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return usageErr("token update: --name is required")
	}
	if len(prefixes) == 0 && len(writePrefixes) == 0 && !*noWrite {
		return usageErr("token update: give --prefix, --write-prefix or --no-write")
	}
	if *noWrite && len(writePrefixes) > 0 {
		return usageErr("token update: --no-write and --write-prefix are mutually exclusive")
	}
	var u grantUpdate
	if len(prefixes) > 0 {
		p := []string(prefixes)
		u.prefixes = &p
	}
	if len(writePrefixes) > 0 || *noWrite {
		w := []string(writePrefixes)
		u.writePrefixes = &w
	}

	db, err := openAdminDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if grantsAll(prefixes) {
		if err := confirmAllSecrets(*name, stdin, stderr); err != nil {
			return err
		}
	}
	read, write, warnings, err := updateTokenGrants(context.Background(), db, *name, u)
	if err != nil {
		return fmt.Errorf("token update: %q: %w", *name, err)
	}
	printWarnings(stderr, warnings)
	fmt.Fprintf(stdout, "updated %q: read %s, write %s (effective from the next request)\n",
		*name, orDash(strings.Join(read, ",")), orDash(strings.Join(write, ",")))
	return nil
}

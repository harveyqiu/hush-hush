// Command hush is the CLI client for the hush-hush secret store.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

const usage = `hush — CLI for the hush-hush secret store.

Usage:
  hush <command> [flags]

Commands:
  login            Save URL + token to the local config (0600)
  health           Verify the server is reachable and the token works
  get NAME         Print the value of a secret to stdout
  put NAME [VALUE] Create/update a secret. Sources: arg | --from-file | --from-stdin | TTY prompt
  delete NAME      Remove a secret (idempotent)
  list             List all secrets (table; --json for JSON)
  help             Show this message

Global flags (accepted by network commands):
  --url    Server base URL  (overrides config / HUSH_URL)
  --token  Bearer token     (overrides config / HUSH_TOKEN)

Config resolution: flag > env (HUSH_URL/HUSH_TOKEN) > config file.
Config file: $HUSH_CONFIG_DIR/config.json, else the OS user config dir
under hush/config.json (e.g. ~/.config/hush/config.json on Linux).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run dispatches a single CLI invocation. Split out from main() so tests
// can drive it with arbitrary args, stdin, and stdout/stderr without
// process-level exec.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "login":
		err = cmdLogin(rest, stdout)
	case "health":
		err = cmdHealth(ctx, rest, stdout)
	case "get":
		err = cmdGet(ctx, rest, stdout)
	case "put":
		err = cmdPut(ctx, rest, stdin, stdout)
	case "delete":
		err = cmdDelete(ctx, rest, stdout)
	case "list":
		err = cmdList(ctx, rest, stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// newFlagSet returns a FlagSet that surfaces parse errors via the return
// value of Parse() instead of os.Exit-ing. Output is sent to io.Discard so
// run()'s error path is the single source of the user-facing message —
// without this, parse failures double-print (FlagSet auto-usage + our wrap).
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// connFlags adds the standard --url/--token flags to fs. Returned pointers
// are populated after fs.Parse.
func connFlags(fs *flag.FlagSet) (*string, *string) {
	url := fs.String("url", "", "Server base URL (overrides config / HUSH_URL)")
	token := fs.String("token", "", "Bearer token (overrides config / HUSH_TOKEN)")
	return url, token
}

// resolveClient is the standard config → client construction path shared
// by every network subcommand. Returns a wrapped error so the caller
// doesn't have to re-attribute the failure context.
func resolveClient(flagURL, flagToken string) (*client, error) {
	cfg, err := resolveConfig(flagURL, flagToken)
	if err != nil {
		return nil, err
	}
	if cfg.URL == "" {
		return nil, errors.New("no URL configured (set via --url, HUSH_URL, or 'hush login')")
	}
	if cfg.Token == "" {
		return nil, errors.New("no token configured (set via --token, HUSH_TOKEN, or 'hush login')")
	}
	return newClient(cfg.URL, cfg.Token), nil
}

// wrapErr maps context.Canceled to a friendly "interrupted" so Ctrl+C
// doesn't look like a plumbing failure, and otherwise wraps with the
// caller-supplied context tag.
func wrapErr(tag string, err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New("interrupted")
	}
	return fmt.Errorf("%s: %w", tag, err)
}

func cmdLogin(args []string, stdout io.Writer) error {
	fs := newFlagSet("login")
	url := fs.String("url", "", "Server base URL (required)")
	token := fs.String("token", "", "Bearer token (required)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if *url == "" || *token == "" {
		return errors.New("login: --url and --token are required")
	}
	if err := saveConfigFile(Config{URL: *url, Token: *token}); err != nil {
		return err
	}
	p, err := configPath()
	if err != nil {
		// saveConfigFile already succeeded so the file IS on disk; we just
		// can't report where. Surface the resolution error so the user knows
		// to look manually instead of trusting an empty path in the message.
		return fmt.Errorf("login: config written but path resolution failed: %w", err)
	}
	fmt.Fprintf(stdout, "config saved to %s (mode 0600)\n", p)
	return nil
}

func cmdHealth(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlagSet("health")
	flagURL, flagToken := connFlags(fs)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("health: %w", err)
	}

	cfg, err := resolveConfig(*flagURL, *flagToken)
	if err != nil {
		return err
	}
	if cfg.URL == "" {
		return errors.New("no URL configured (set via --url, HUSH_URL, or 'hush login')")
	}

	c := newClient(cfg.URL, cfg.Token)
	if err := c.Health(ctx); err != nil {
		return wrapErr("reachability check failed", err)
	}
	fmt.Fprintf(stdout, "%s: reachable\n", cfg.URL)

	if cfg.Token == "" {
		fmt.Fprintln(stdout, "auth: skipped (no token configured)")
		return nil
	}
	if err := c.AuthCheck(ctx); err != nil {
		return wrapErr("auth check failed", err)
	}
	fmt.Fprintln(stdout, "auth: ok")
	return nil
}

// splitNameAndRest pulls the leading positional <name> argument off the
// front of args, returning ("", rest) if the first token looks like a flag.
// Lets the user write `hush get foo --url=...` even though stdlib flag
// would normally stop at the first non-flag arg.
func splitNameAndRest(args []string) (string, []string) {
	if len(args) == 0 {
		return "", args
	}
	if strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}

func cmdGet(ctx context.Context, args []string, stdout io.Writer) error {
	name, rest := splitNameAndRest(args)
	fs := newFlagSet("get")
	flagURL, flagToken := connFlags(fs)
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if extra := fs.Args(); len(extra) > 0 {
		return fmt.Errorf("get: unexpected arguments: %s", strings.Join(extra, " "))
	}
	if name == "" {
		return errors.New("get: NAME is required")
	}
	c, err := resolveClient(*flagURL, *flagToken)
	if err != nil {
		return err
	}
	s, err := c.Get(ctx, name)
	if err != nil {
		return wrapErr("get", err)
	}
	// No trailing newline: lets `hush get FOO | clip` round-trip the value
	// exactly as stored, without surprising callers who don't want a stray
	// "\n" tacked on.
	fmt.Fprint(stdout, s.Value)
	return nil
}

func cmdPut(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	name, rest := splitNameAndRest(args)
	// A second positional, before any flags, is the value.
	var positionalValue string
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		positionalValue = rest[0]
		rest = rest[1:]
	}

	fs := newFlagSet("put")
	flagURL, flagToken := connFlags(fs)
	fromFile := fs.String("from-file", "", "Read value from this file (trailing newline stripped)")
	fromStdin := fs.Bool("from-stdin", false, "Read value from stdin (trailing newline stripped)")
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	// Promote a single trailing positional to the value if one wasn't
	// already supplied before the flags — so `hush put foo --url=X bar`
	// works the same as `hush put foo bar --url=X`. Anything beyond that
	// is a user mistake; refuse instead of silently dropping it.
	switch extra := fs.Args(); {
	case positionalValue == "" && len(extra) == 1:
		positionalValue = extra[0]
	case len(extra) > 0:
		return fmt.Errorf("put: unexpected arguments: %s", strings.Join(extra, " "))
	}
	if name == "" {
		return errors.New("put: NAME is required")
	}

	src := valueSource{
		arg:       positionalValue,
		fromFile:  *fromFile,
		fromStdin: *fromStdin,
		stdin:     stdin,
		readPass:  promptNoEcho,
		isTTY:     stdinIsTTY,
	}
	value, err := src.resolve()
	if err != nil {
		return fmt.Errorf("put: %w", err)
	}

	c, err := resolveClient(*flagURL, *flagToken)
	if err != nil {
		return err
	}
	if _, err := c.Put(ctx, name, value); err != nil {
		return wrapErr("put", err)
	}
	// "saved" instead of "created"/"updated": the server's response is
	// {name, created_at, updated_at} with second-resolution timestamps, so
	// a put-then-put within the same second is indistinguishable from a
	// fresh create. Better unambiguous than fast-and-loose.
	fmt.Fprintf(stdout, "%s: saved\n", name)
	return nil
}

func cmdDelete(ctx context.Context, args []string, stdout io.Writer) error {
	name, rest := splitNameAndRest(args)
	fs := newFlagSet("delete")
	flagURL, flagToken := connFlags(fs)
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if extra := fs.Args(); len(extra) > 0 {
		return fmt.Errorf("delete: unexpected arguments: %s", strings.Join(extra, " "))
	}
	if name == "" {
		return errors.New("delete: NAME is required")
	}
	c, err := resolveClient(*flagURL, *flagToken)
	if err != nil {
		return err
	}
	if err := c.Delete(ctx, name); err != nil {
		return wrapErr("delete", err)
	}
	fmt.Fprintf(stdout, "%s: deleted\n", name)
	return nil
}

func cmdList(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlagSet("list")
	flagURL, flagToken := connFlags(fs)
	asJSON := fs.Bool("json", false, "Output as JSON array instead of a table")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("list: %w", err)
	}
	if extra := fs.Args(); len(extra) > 0 {
		return fmt.Errorf("list: unexpected arguments: %s", strings.Join(extra, " "))
	}
	c, err := resolveClient(*flagURL, *flagToken)
	if err != nil {
		return err
	}
	secrets, err := c.List(ctx)
	if err != nil {
		return wrapErr("list", err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(secrets)
	}
	return renderListTable(stdout, secrets)
}

func renderListTable(out io.Writer, secrets []Secret) error {
	if len(secrets) == 0 {
		fmt.Fprintln(out, "(no secrets)")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCREATED\tUPDATED")
	for _, s := range secrets {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, fmtTime(s.CreatedAt), fmtTime(s.UpdatedAt))
	}
	return tw.Flush()
}

func fmtTime(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

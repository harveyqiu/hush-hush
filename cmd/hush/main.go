// Command hush is the CLI client for the hush-hush secret store.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const usage = `hush — CLI for the hush-hush secret store.

Usage:
  hush <command> [flags]

Commands:
  login    Save URL + token to the local config (0600)
  health   Verify the server is reachable and the token works
  help     Show this message

Global flags (accepted by network commands):
  --url    Server base URL  (overrides config / HUSH_URL)
  --token  Bearer token     (overrides config / HUSH_TOKEN)

Config resolution: flag > env (HUSH_URL/HUSH_TOKEN) > config file.
Config file: $HUSH_CONFIG_DIR/config.json, else the OS user config dir
under hush/config.json (e.g. ~/.config/hush/config.json on Linux).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a single CLI invocation. Split out from main() so tests
// can drive it with arbitrary args and capture stdout/stderr without
// process-level exec.
func run(args []string, stdout, stderr io.Writer) int {
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

func cmdLogin(args []string, stdout io.Writer) error {
	fs := newFlagSet("login")
	url := fs.String("url", "", "Server base URL (required)")
	token := fs.String("token", "", "Bearer token (required)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if *url == "" || *token == "" {
		return fmt.Errorf("login: --url and --token are required")
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
	flagURL := fs.String("url", "", "Server base URL (overrides config / HUSH_URL)")
	flagToken := fs.String("token", "", "Bearer token (overrides config / HUSH_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("health: %w", err)
	}

	cfg, err := resolveConfig(*flagURL, *flagToken)
	if err != nil {
		return err
	}
	if cfg.URL == "" {
		return fmt.Errorf("no URL configured (set via --url, HUSH_URL, or 'hush login')")
	}

	c := newClient(cfg.URL, cfg.Token)
	if err := c.Health(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("interrupted")
		}
		return fmt.Errorf("reachability check failed: %w", err)
	}
	fmt.Fprintf(stdout, "%s: reachable\n", cfg.URL)

	if cfg.Token == "" {
		fmt.Fprintln(stdout, "auth: skipped (no token configured)")
		return nil
	}
	if err := c.AuthCheck(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("interrupted")
		}
		return fmt.Errorf("auth check failed: %w", err)
	}
	fmt.Fprintln(stdout, "auth: ok")
	return nil
}

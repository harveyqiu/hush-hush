package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// valueSource carries the user's chosen way to supply a secret value.
// Exactly one of arg/fromFile/fromStdin should be populated; if none are
// and stdin is a TTY, we fall through to an interactive no-echo prompt.
type valueSource struct {
	arg       string
	fromFile  string
	fromStdin bool

	// Injected for testability so the resolution logic doesn't depend on
	// process-level singletons.
	stdin    io.Reader
	stderr   io.Writer
	readPass func(prompt string) (string, error)
	isTTY    func() bool
}

// errNoValueSource is returned when the user provided no value source AND
// stdin is not a TTY (so we can't safely prompt). Surfaces as a clear CLI
// usage error instead of hanging forever waiting for input.
var errNoValueSource = errors.New("no value source: pass a positional arg, --from-file PATH, --from-stdin, or run from a terminal")

// errMultipleValueSources is returned when the user picked more than one
// of the explicit value flags. Avoid silent precedence rules.
var errMultipleValueSources = errors.New("at most one of value-arg / --from-file / --from-stdin may be specified")

func (v valueSource) resolve() (string, error) {
	count := 0
	if v.arg != "" {
		count++
	}
	if v.fromFile != "" {
		count++
	}
	if v.fromStdin {
		count++
	}
	if count > 1 {
		return "", errMultipleValueSources
	}

	switch {
	case v.arg != "":
		return v.arg, nil
	case v.fromFile != "":
		return readFromFile(v.fromFile)
	case v.fromStdin:
		return readFromStream(v.stdin)
	case v.isTTY != nil && v.isTTY():
		if v.readPass == nil {
			return "", errors.New("interactive prompt not available")
		}
		return v.readPass("value: ")
	default:
		return "", errNoValueSource
	}
}

// readFromFile reads the entire file and trims a single trailing newline
// pair so editors that auto-append "\n" don't store an off-by-one secret.
// Interior and leading whitespace are preserved; multi-newline endings
// keep all but the last newline (the "intentional" ones).
func readFromFile(path string) (string, error) {
	// #nosec G304 -- path comes from a user-controlled CLI flag, which is
	// the entire point: read what the user pointed us at.
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return trimOneTrailingNewline(string(b)), nil
}

func readFromStream(r io.Reader) (string, error) {
	if r == nil {
		return "", errors.New("no stdin reader configured")
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return trimOneTrailingNewline(string(b)), nil
}

// trimOneTrailingNewline strips a single trailing newline sequence (CRLF,
// LF, or CR) and nothing more. Using strings.TrimRight with a "\r\n"
// cutset would strip ALL trailing CR/LF bytes, silently rewriting inputs
// that intentionally end with multiple newlines.
func trimOneTrailingNewline(s string) string {
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return s[:len(s)-2]
	case strings.HasSuffix(s, "\n"), strings.HasSuffix(s, "\r"):
		return s[:len(s)-1]
	}
	return s
}

// promptNoEcho reads a secret from the terminal without echoing it. Used
// when the user runs `hush put NAME` interactively with no other value
// source supplied.
func promptNoEcho(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read terminal: %w", err)
	}
	return string(b), nil
}

func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"

	"modernc.org/sqlite"
)

// A database/sql driver that wraps modernc.org/sqlite and fails chosen
// operations on demand. Error branches are exercised against the real
// code and a real database, rather than a mock.

const faultDriverName = "sqlite-fault"

var errInjected = errors.New("injected fault")

// A fault fires when op matches and the SQL contains match ("" matches
// any statement). after lets the first N matching calls through.
type fault struct {
	op, match string
	after     int
	col       int // for "nullcol": which column to replace with NULL
}

var faults struct {
	sync.Mutex
	list []*fault
}

func init() { sql.Register(faultDriverName, faultDriver{&sqlite.Driver{}}) }

// injectFault arms a fault for the rest of the test. op is one of
// "exec", "query", "begin", "commit", "next".
func injectFault(t *testing.T, op, match string, after int) {
	t.Helper()
	faults.Lock()
	faults.list = append(faults.list, &fault{op: op, match: match, after: after})
	faults.Unlock()
	t.Cleanup(func() {
		faults.Lock()
		faults.list = nil
		faults.Unlock()
	})
}

func checkFault(op, query string) error {
	if matchFault(op, query) != nil {
		return errInjected
	}
	return nil
}

func matchFault(op, query string) *fault {
	faults.Lock()
	defer faults.Unlock()
	for _, f := range faults.list {
		if f.op != op || !strings.Contains(query, f.match) {
			continue
		}
		if f.after > 0 {
			f.after--
			continue
		}
		return f
	}
	return nil
}

// injectNullColumn makes every row of matching queries return NULL in
// column col, to exercise Scan failures and defensive checks.
func injectNullColumn(t *testing.T, match string, col int) {
	t.Helper()
	injectFault(t, "nullcol", match, 0)
	faults.Lock()
	faults.list[len(faults.list)-1].col = col
	faults.Unlock()
}

type faultDriver struct{ inner driver.Driver }

func (d faultDriver) Open(name string) (driver.Conn, error) {
	c, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &faultConn{c}, nil
}

type faultConn struct{ driver.Conn }

func (c *faultConn) Prepare(q string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), q)
}

func (c *faultConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	st, err := c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	return &faultStmt{st, q}, nil
}

func (c *faultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if err := checkFault("begin", ""); err != nil {
		return nil, err
	}
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return faultTx{tx}, nil
}

type faultTx struct{ driver.Tx }

func (t faultTx) Commit() error {
	if err := checkFault("commit", ""); err != nil {
		_ = t.Tx.Rollback()
		return err
	}
	return t.Tx.Commit()
}

type faultStmt struct {
	driver.Stmt
	q string
}

func (s *faultStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if err := checkFault("exec", s.q); err != nil {
		return nil, err
	}
	return s.Stmt.(driver.StmtExecContext).ExecContext(ctx, args)
}

func (s *faultStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if err := checkFault("query", s.q); err != nil {
		return nil, err
	}
	rows, err := s.Stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
	if err != nil {
		return nil, err
	}
	return &faultRows{rows, s.q}, nil
}

type faultRows struct {
	driver.Rows
	q string
}

func (r *faultRows) Next(dest []driver.Value) error {
	if err := checkFault("next", r.q); err != nil {
		return err
	}
	if err := r.Rows.Next(dest); err != nil {
		return err
	}
	if f := matchFault("nullcol", r.q); f != nil && f.col < len(dest) {
		dest[f.col] = nil
	}
	return nil
}

// useFaultDriver makes openDB (server and CLI) use the fault driver for
// the rest of the test.
func useFaultDriver(t *testing.T) {
	t.Helper()
	prev := sqliteDriver
	sqliteDriver = faultDriverName
	t.Cleanup(func() { sqliteDriver = prev })
}

// newFaultServer is newTestServer on the fault driver.
func newFaultServer(t *testing.T) (*server, *sql.DB) {
	t.Helper()
	db, err := sql.Open(faultDriverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	s := newServer(db, testKey())
	mustInsertToken(t, s, tokenSpec{name: "test-admin", role: roleAdmin}, testToken)
	return s, db
}

// The wrapper itself must be transparent when no fault is armed.
func TestFaultDriver_Transparent(t *testing.T) {
	s, _ := newFaultServer(t)
	h := s.routes()
	seedSecrets(t, h, "llm.k")
	if v, ok := secretValue(t, s, "llm.k"); !ok || v != "v-llm.k" {
		t.Fatalf("round trip through fault driver: %q %v", v, ok)
	}
}

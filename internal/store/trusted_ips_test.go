package store

import (
	"context"
	"errors"
	"strings"
	stdsync "sync"
	"testing"
)

func trustedStore(t *testing.T) *Store {
	t.Helper()
	st, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func countTrustedIPs(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM trusted_ips").Scan(&n); err != nil {
		t.Fatalf("count trusted_ips: %v", err)
	}
	return n
}

// [A6] The whole point of the partial UNIQUE indexes: concurrent adds of the
// same address cannot both land. Before them, SELECT-then-INSERT let two
// interleaved writers each insert a row.
func TestAddTrustedIPConcurrentDuplicates(t *testing.T) {
	st := trustedStore(t)
	ctx := context.Background()

	const writers = 8
	var wg stdsync.WaitGroup
	results := make([]error, writers)
	start := make(chan struct{})

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := st.AddTrustedIP(ctx, &TrustedIP{
				IPAddress:   "203.0.113.44",
				Description: "concurrent",
				AddedBy:     "test",
			})
			results[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	won, exists := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrTrustedIPExists):
			exists++
		default:
			t.Errorf("unexpected error from a losing writer: %v", err)
		}
	}

	if won != 1 {
		t.Errorf("successful inserts = %d; want exactly 1", won)
	}
	if exists != writers-1 {
		t.Errorf("already-trusted errors = %d; want %d", exists, writers-1)
	}
	if n := countTrustedIPs(t, st); n != 1 {
		t.Errorf("rows = %d; want exactly 1 - the UNIQUE index is the guard", n)
	}
}

// The same for CIDRs, which have their own partial index.
func TestAddTrustedCIDRDuplicate(t *testing.T) {
	st := trustedStore(t)
	ctx := context.Background()

	if _, err := st.AddTrustedIP(ctx, &TrustedIP{CIDR: "198.51.100.0/24", AddedBy: "test"}); err != nil {
		t.Fatalf("first add: %v", err)
	}
	_, err := st.AddTrustedIP(ctx, &TrustedIP{CIDR: "198.51.100.0/24", AddedBy: "test"})
	if !errors.Is(err, ErrTrustedIPExists) {
		t.Fatalf("second add error = %v; want ErrTrustedIPExists", err)
	}
	// The message names the entry and carries the pinned substring.
	if !strings.Contains(err.Error(), "198.51.100.0/24") || !strings.Contains(err.Error(), "already trusted") {
		t.Errorf("error text = %q; want it to name the CIDR and say already trusted", err)
	}
	if n := countTrustedIPs(t, st); n != 1 {
		t.Errorf("rows = %d; want 1", n)
	}
}

// Several distinct CIDR rows all have ip_address NULL. A plain UNIQUE index
// would reject the second one; a partial index on non-null values must not.
func TestAddTrustedIPPartialIndexAllowsManyNulls(t *testing.T) {
	st := trustedStore(t)
	ctx := context.Background()

	for _, cidr := range []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"} {
		if _, err := st.AddTrustedIP(ctx, &TrustedIP{CIDR: cidr, AddedBy: "test"}); err != nil {
			t.Fatalf("add %s: %v", cidr, err)
		}
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if _, err := st.AddTrustedIP(ctx, &TrustedIP{IPAddress: ip, AddedBy: "test"}); err != nil {
			t.Fatalf("add %s: %v", ip, err)
		}
	}
	if n := countTrustedIPs(t, st); n != 5 {
		t.Errorf("rows = %d; want 5", n)
	}
}

// Malformed entries are a caller error, distinguishable from a failed write.
func TestAddTrustedIPValidation(t *testing.T) {
	st := trustedStore(t)
	ctx := context.Background()

	if _, err := st.AddTrustedIP(ctx, &TrustedIP{IPAddress: "pancakes"}); !errors.Is(err, ErrTrustedIPInvalid) {
		t.Errorf("invalid IP error = %v; want ErrTrustedIPInvalid", err)
	}
	if _, err := st.AddTrustedIP(ctx, &TrustedIP{CIDR: "10.0.0.0/99"}); !errors.Is(err, ErrTrustedIPInvalid) {
		t.Errorf("invalid CIDR error = %v; want ErrTrustedIPInvalid", err)
	}
}

// A delete that found nothing is reported as such, so callers can tell it
// apart from a delete that failed.
func TestRemoveTrustedIPNotFound(t *testing.T) {
	st := trustedStore(t)
	ctx := context.Background()

	id, err := st.AddTrustedIP(ctx, &TrustedIP{IPAddress: "203.0.113.7", AddedBy: "test"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := st.RemoveTrustedIP(ctx, id); err != nil {
		t.Fatalf("remove: %v", err)
	}
	err = st.RemoveTrustedIP(ctx, id)
	if !errors.Is(err, ErrTrustedIPNotFound) {
		t.Errorf("second remove error = %v; want ErrTrustedIPNotFound", err)
	}
}

// [A6] Existing databases may hold duplicates from the SELECT-then-INSERT era,
// so migration v16 has to dedupe before it can create the indexes. This
// reproduces that database: pre-v16 schema, duplicate rows, then migrate.
func TestMigrationV16DedupesExistingTrustedIPs(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(dir)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	// Roll back to the pre-A6 state: drop the indexes and the version rows,
	// then write the duplicates the old code could produce.
	for _, stmt := range []string{
		"DROP INDEX IF EXISTS idx_trusted_ips_address_unique",
		"DROP INDEX IF EXISTS idx_trusted_ips_cidr_unique",
		"DELETE FROM schema_version WHERE version >= 16",
		// Two rows for one IP, two for one CIDR, plus legacy empty strings.
		`INSERT INTO trusted_ips (ip_address, cidr, description, added_by, created_at)
		 VALUES ('203.0.113.5', NULL, 'first', 'installer', '2026-01-01T00:00:00Z')`,
		`INSERT INTO trusted_ips (ip_address, cidr, description, added_by, created_at)
		 VALUES ('203.0.113.5', NULL, 'duplicate', 'api', '2026-02-01T00:00:00Z')`,
		`INSERT INTO trusted_ips (ip_address, cidr, description, added_by, created_at)
		 VALUES (NULL, '10.0.0.0/8', 'first cidr', 'installer', '2026-01-01T00:00:00Z')`,
		`INSERT INTO trusted_ips (ip_address, cidr, description, added_by, created_at)
		 VALUES ('', '10.0.0.0/8', 'duplicate cidr with legacy empty ip', 'api', '2026-02-01T00:00:00Z')`,
	} {
		if _, err := st.DB().Exec(stmt); err != nil {
			t.Fatalf("seeding pre-migration state (%s): %v", stmt, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen: migration v16 must dedupe oldest-wins and then build the index.
	reopened, err := Init(dir)
	if err != nil {
		t.Fatalf("reopen (migration v16 failed): %v", err)
	}
	defer reopened.Close()

	ips, err := reopened.ListTrustedIPs(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("rows after dedupe = %d; want 2 (%+v)", len(ips), ips)
	}
	for _, ip := range ips {
		if ip.AddedBy != "installer" {
			t.Errorf("survivor %+v was added_by %q; oldest-wins means the installer rows survive",
				ip, ip.AddedBy)
		}
	}

	// And the index is now enforcing.
	if _, err := reopened.AddTrustedIP(context.Background(), &TrustedIP{
		IPAddress: "203.0.113.5", AddedBy: "test",
	}); !errors.Is(err, ErrTrustedIPExists) {
		t.Errorf("post-migration duplicate add error = %v; want ErrTrustedIPExists", err)
	}
}

package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Trusted-IP error contract. Callers (the dashboard API, and through it the
// hosted command channel) must be able to tell "this is already true" and
// "you asked for something invalid" - both terminal, both the caller's answer -
// apart from "the write failed", which is transient and must be retried.
// Before these sentinels every failure looked the same, so a locked database
// surfaced to the API as a 400/404.
var (
	// ErrTrustedIPExists means the address or range is already trusted.
	// [A6] Since the partial UNIQUE indexes landed this is also what a lost
	// insert race reports, instead of a second row appearing.
	ErrTrustedIPExists = errors.New("already trusted")

	// ErrTrustedIPNotFound means there is no such row to delete.
	ErrTrustedIPNotFound = errors.New("trusted IP not found")

	// ErrTrustedIPInvalid means the supplied IP or CIDR does not parse.
	ErrTrustedIPInvalid = errors.New("invalid trusted IP entry")
)

// isUniqueViolation reports whether err is SQLite refusing a duplicate.
// modernc.org/sqlite returns extended result codes; the low byte of a
// constraint failure is SQLITE_CONSTRAINT.
func isUniqueViolation(err error) bool {
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		switch serr.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY, sqlite3.SQLITE_CONSTRAINT:
			return true
		}
	}
	return false
}

// TrustedIP represents an entry in the trusted_ips table.
type TrustedIP struct {
	ID          int64     `json:"id"`
	IPAddress   string    `json:"ip_address,omitempty"` // exact IP (nullable)
	CIDR        string    `json:"cidr,omitempty"`       // CIDR range (nullable)
	Description string    `json:"description"`
	AddedBy     string    `json:"added_by"` // "installer", "api", "cli"
	CreatedAt   time.Time `json:"created_at"`
}

// IsTrustedIP checks whether a given IP is in the trusted_ips table.
// Checks exact IP match first, then CIDR ranges.
// Returns false on error (fail-closed: unknown = untrusted).
func (s *Store) IsTrustedIP(ip string) (bool, error) {
	ctx := context.Background()

	// Fast path: exact IP match
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM trusted_ips WHERE ip_address = ?", ip).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("trusted ip lookup: %w", err)
	}
	if count > 0 {
		return true, nil
	}

	// Slow path: check CIDR ranges
	rows, err := s.db.QueryContext(ctx,
		"SELECT cidr FROM trusted_ips WHERE cidr IS NOT NULL AND cidr != ''")
	if err != nil {
		return false, fmt.Errorf("trusted cidr lookup: %w", err)
	}
	defer rows.Close()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, nil // unparseable IP = untrusted
	}

	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true, nil
		}
	}

	return false, nil
}

// AddTrustedIP inserts a new trusted IP or CIDR range.
// At least one of ipAddress or cidr must be non-empty.
func (s *Store) AddTrustedIP(ctx context.Context, ip *TrustedIP) (int64, error) {
	if ip.IPAddress == "" && ip.CIDR == "" {
		return 0, fmt.Errorf("either ip_address or cidr must be provided")
	}

	// Validate CIDR if provided
	if ip.CIDR != "" {
		if _, _, err := net.ParseCIDR(ip.CIDR); err != nil {
			return 0, fmt.Errorf("%w: invalid CIDR %q: %v", ErrTrustedIPInvalid, ip.CIDR, err)
		}
	}

	// Validate IP if provided
	if ip.IPAddress != "" {
		if net.ParseIP(ip.IPAddress) == nil {
			return 0, fmt.Errorf("%w: invalid IP address %q", ErrTrustedIPInvalid, ip.IPAddress)
		}
	}

	// [A6] Duplicate rejection is the database's job, not a SELECT's.
	//
	// This used to be SELECT-then-INSERT against a table with no UNIQUE
	// constraint: two dashboard clicks (or, now, two deliveries of the same
	// hosted command) that interleaved between the SELECT and the INSERT both
	// saw "not there yet" and both inserted. The result was a duplicate row
	// that no code path could ever produce a second time, so it was invisible
	// until somebody counted. Migration v16 adds partial UNIQUE indexes and
	// the insert simply lets them speak - one writer wins, the loser gets
	// ErrTrustedIPExists, which is exactly what a serialized second attempt
	// would have got.
	result, err := s.db.ExecContext(ctx, `INSERT INTO trusted_ips
		(ip_address, cidr, description, added_by)
		VALUES (?, ?, ?, ?)`,
		nullableString(ip.IPAddress),
		nullableString(ip.CIDR),
		ip.Description,
		ip.AddedBy,
	)
	if err != nil {
		if isUniqueViolation(err) {
			what := "IP " + ip.IPAddress
			if ip.IPAddress == "" {
				what = "CIDR " + ip.CIDR
			}
			// Message shape is unchanged ("IP 1.2.3.4 already trusted") and
			// carries api.ConvergedTrustedIPExists as a substring.
			return 0, fmt.Errorf("%s %w", what, ErrTrustedIPExists)
		}
		return 0, fmt.Errorf("insert trusted ip: %w", err)
	}

	id, _ := result.LastInsertId()
	return id, nil
}

// RemoveTrustedIP deletes a trusted IP entry by ID.
func (s *Store) RemoveTrustedIP(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM trusted_ips WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete trusted ip: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("id %d: %w", id, ErrTrustedIPNotFound)
	}
	return nil
}

// ListTrustedIPs returns all entries in the trusted_ips table.
func (s *Store) ListTrustedIPs(ctx context.Context) ([]TrustedIP, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, 
		COALESCE(ip_address, ''), COALESCE(cidr, ''), 
		description, added_by, created_at 
		FROM trusted_ips ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list trusted ips: %w", err)
	}
	defer rows.Close()

	var ips []TrustedIP
	for rows.Next() {
		var ip TrustedIP
		var createdAt string
		if err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.CIDR, &ip.Description, &ip.AddedBy, &createdAt); err != nil {
			continue
		}
		ip.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if ip.CreatedAt.IsZero() {
			ip.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// --- Helpers ---

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

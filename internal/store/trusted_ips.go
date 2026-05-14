package store

import (
	"context"
	"fmt"
	"net"
	"time"
)

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
			return 0, fmt.Errorf("invalid CIDR %q: %w", ip.CIDR, err)
		}
	}

	// Validate IP if provided
	if ip.IPAddress != "" {
		if net.ParseIP(ip.IPAddress) == nil {
			return 0, fmt.Errorf("invalid IP address %q", ip.IPAddress)
		}
	}

	// Check for duplicates
	var existing int
	if ip.IPAddress != "" {
		s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM trusted_ips WHERE ip_address = ?", ip.IPAddress).Scan(&existing)
		if existing > 0 {
			return 0, fmt.Errorf("IP %s already trusted", ip.IPAddress)
		}
	}
	if ip.CIDR != "" {
		s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM trusted_ips WHERE cidr = ?", ip.CIDR).Scan(&existing)
		if existing > 0 {
			return 0, fmt.Errorf("CIDR %s already trusted", ip.CIDR)
		}
	}

	result, err := s.db.ExecContext(ctx, `INSERT INTO trusted_ips
		(ip_address, cidr, description, added_by)
		VALUES (?, ?, ?, ?)`,
		nullableString(ip.IPAddress),
		nullableString(ip.CIDR),
		ip.Description,
		ip.AddedBy,
	)
	if err != nil {
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
		return fmt.Errorf("trusted IP with id %d not found", id)
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

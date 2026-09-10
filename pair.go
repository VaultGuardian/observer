// pair.go
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// =============================================================================
// `vaultguardian pair <code>` - the re-pair interlock
// =============================================================================
//
// Pairing exchanges a short-lived code from the hosted dashboard for this
// instance's ingest credentials and its command-channel keys, then writes them
// into observer.env.
//
// THE ORDER IS A SECURITY BOUNDARY, NOT A CONVENIENCE [A12]
//
// The running daemon is stopped, and its exit confirmed, BEFORE the pairing
// code is claimed. Claiming rotates the command epoch on the hosted side. A
// daemon that is still alive at that moment is still holding the OLD epoch in
// memory and still polling with the OLD ingest token, so it would keep
// executing (or, worse, keep being served) commands from a pairing session the
// operator has just replaced. Stopping first collapses that window to nothing:
// there is no process holding the old epoch by the time the new one exists.
//
// The same ordering is why a failed claim leaves the service stopped rather
// than "helpfully" restarting it. A half-completed re-pair must be a visibly
// stopped Observer the operator retries, not a running one whose credentials
// nobody can name.

// pairEnvKeys are the observer.env keys this command owns. Everything else in
// the file is preserved byte-for-byte. Order is fixed so a first pairing
// appends them predictably.
var pairEnvKeys = []string{
	"SYNC_URL",
	"SYNC_TOKEN",
	"SYNC_INSTANCE_ID",
	"SYNC_VERIFY_KEY",
	"SYNC_COMMAND_EPOCH",
}

const (
	defaultEnvPath     = "/etc/vaultguardian/observer.env"
	defaultServiceName = "observer"

	// claimTimeout bounds the claim request. Short: the operator is watching a
	// stopped Observer while this runs.
	claimTimeout = 15 * time.Second

	// serviceStopTimeout bounds how long we wait for the daemon to actually
	// exit. Exceeding it aborts the pairing - we will not claim a code while
	// something might still be running with the old epoch.
	serviceStopTimeout = 30 * time.Second

	// claimBodyLimit bounds the claim response read.
	claimBodyLimit = 64 << 10
)

// pairOptions is everything `pair` needs. The service and transport hooks are
// injectable so the flow can be tested end to end without systemd or a hosted
// dashboard.
type pairOptions struct {
	Code    string
	URL     string
	EnvPath string
	Client  *http.Client
	Out     io.Writer

	// StopService must not return until the daemon process is GONE. See the
	// ordering note above - this is the interlock.
	StopService  func(context.Context) error
	StartService func(context.Context) error
	StatusTail   func(context.Context) string
}

// pairClaimResponse is the hosted side's answer to a successful claim. The
// claim endpoint itself ships in the hosted repo (chunk 2).
type pairClaimResponse struct {
	IngestURL        string `json:"ingest_url"`
	IngestToken      string `json:"ingest_token"`
	InstanceID       string `json:"instance_id"`
	CommandVerifyKey string `json:"command_verify_key"`
	CommandEpoch     string `json:"command_epoch"`
}

// runPairCLI parses the subcommand's arguments and runs the flow against the
// real systemd units.
func runPairCLI(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	url := fs.String("url", "", "hosted dashboard base URL (defaults to SYNC_URL in observer.env)")
	envPath := fs.String("env", defaultEnvPath, "path to observer.env")
	service := fs.String("service", defaultServiceName, "systemd unit to stop and start")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		// Flags first, then the code: flag.Parse stops at the first
		// non-flag argument, so the reverse order lands right back here.
		return fmt.Errorf("usage: vaultguardian pair [--url https://...] [--env %s] <code>", defaultEnvPath)
	}

	unit := *service
	return runPair(context.Background(), pairOptions{
		Code:         fs.Arg(0),
		URL:          *url,
		EnvPath:      *envPath,
		Out:          os.Stdout,
		StopService:  func(ctx context.Context) error { return systemctlStopAndWait(ctx, unit) },
		StartService: func(ctx context.Context) error { return systemctlRun(ctx, "start", unit) },
		StatusTail:   func(ctx context.Context) string { return systemctlStatus(ctx, unit) },
	})
}

// runPair executes the pairing flow in its mandatory order.
func runPair(ctx context.Context, opts pairOptions) error {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: claimTimeout}
	}

	code := canonicalPairingCode(opts.Code)
	if code == "" {
		return fmt.Errorf("a pairing code is required")
	}
	if opts.EnvPath == "" {
		return fmt.Errorf("no observer.env path given")
	}

	// The URL comes from the flag, or from the pairing this box already has.
	// A first pairing has neither, and must be told where to go.
	baseURL := strings.TrimRight(strings.TrimSpace(opts.URL), "/")
	if baseURL == "" {
		existing, err := readEnvValue(opts.EnvPath, "SYNC_URL")
		if err != nil {
			return fmt.Errorf("reading %s: %w", opts.EnvPath, err)
		}
		baseURL = strings.TrimRight(existing, "/")
	}
	if baseURL == "" {
		return fmt.Errorf("no dashboard URL: pass --url https://... (this instance has never been paired)")
	}
	if err := validateSyncURL(baseURL); err != nil {
		return fmt.Errorf("dashboard URL rejected: %w", err)
	}

	// --- 1. stop the daemon and confirm it is gone -------------------------
	if opts.StopService != nil {
		fmt.Fprintf(out, "Stopping Observer before rotating the pairing...\n")
		if err := opts.StopService(ctx); err != nil {
			return fmt.Errorf("could not stop Observer (refusing to re-pair while it may still be "+
				"running with the old pairing): %w", err)
		}
	}

	// --- 2. claim the code -------------------------------------------------
	claim, err := claimPairingCode(ctx, client, baseURL, code)
	if err != nil {
		// Env untouched, service left stopped, nonzero exit.
		return err
	}

	// --- 3. rewrite observer.env atomically --------------------------------
	updates := map[string]string{
		"SYNC_URL":           strings.TrimRight(claim.IngestURL, "/"),
		"SYNC_TOKEN":         claim.IngestToken,
		"SYNC_INSTANCE_ID":   claim.InstanceID,
		"SYNC_VERIFY_KEY":    claim.CommandVerifyKey,
		"SYNC_COMMAND_EPOCH": claim.CommandEpoch,
	}
	if err := rewriteEnvFile(opts.EnvPath, updates); err != nil {
		return fmt.Errorf("writing %s: %w", opts.EnvPath, err)
	}
	fmt.Fprintf(out, "Paired: instance %s, epoch %s (wrote %s)\n",
		claim.InstanceID, claim.CommandEpoch, opts.EnvPath)

	// --- 4. start the daemon and show what it did --------------------------
	if opts.StartService != nil {
		if err := opts.StartService(ctx); err != nil {
			return fmt.Errorf("pairing was written but Observer did not start: %w", err)
		}
	}
	if opts.StatusTail != nil {
		if tail := strings.TrimSpace(opts.StatusTail(ctx)); tail != "" {
			fmt.Fprintf(out, "\n%s\n", tail)
		}
	}
	return nil
}

// canonicalPairingCode strips whitespace and hyphens and uppercases, so a code
// read off a screen ("a1b2-c3d4") and one pasted from a terminal are the same
// code.
func canonicalPairingCode(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(b.String())
}

// claimPairingCode POSTs the code and validates the response hard.
//
// A non-2xx is reported with the server's own message and nothing else: the
// hosted side deliberately keeps claim errors opaque (an attacker guessing
// codes learns nothing about which part was wrong), and inventing a friendlier
// local interpretation would leak the distinction it is hiding.
func claimPairingCode(ctx context.Context, client *http.Client, baseURL, code string) (*pairClaimResponse, error) {
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, claimTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/api/pairing/claim", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claiming pairing code: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, claimBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("reading claim response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("pairing refused (HTTP %d): %s", resp.StatusCode, serverMessage(respBody))
	}

	var claim pairClaimResponse
	if err := json.Unmarshal(respBody, &claim); err != nil {
		return nil, fmt.Errorf("claim response is not valid JSON: %w", err)
	}

	// Validate before writing anything. A response that is missing a field or
	// carries an unusable key would produce an observer.env that silently
	// disables the very channel this command exists to set up.
	missing := []string{}
	if claim.IngestURL == "" {
		missing = append(missing, "ingest_url")
	}
	if claim.IngestToken == "" {
		missing = append(missing, "ingest_token")
	}
	if claim.InstanceID == "" {
		missing = append(missing, "instance_id")
	}
	if claim.CommandVerifyKey == "" {
		missing = append(missing, "command_verify_key")
	}
	if claim.CommandEpoch == "" {
		missing = append(missing, "command_epoch")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("claim response is incomplete (missing %s)", strings.Join(missing, ", "))
	}
	if err := validateSyncURL(strings.TrimRight(claim.IngestURL, "/")); err != nil {
		return nil, fmt.Errorf("claim response ingest_url rejected: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(claim.CommandVerifyKey)
	if err != nil {
		return nil, fmt.Errorf("claim response command_verify_key is not valid base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("claim response command_verify_key is %d bytes; an Ed25519 public key is %d",
			len(key), ed25519.PublicKeySize)
	}
	// Newlines in a value would break the env file's line structure.
	for k, v := range map[string]string{
		"ingest_token":       claim.IngestToken,
		"instance_id":        claim.InstanceID,
		"command_verify_key": claim.CommandVerifyKey,
		"command_epoch":      claim.CommandEpoch,
	} {
		if strings.ContainsAny(v, "\n\r") {
			return nil, fmt.Errorf("claim response %s contains a line break", k)
		}
	}

	return &claim, nil
}

// serverMessage extracts {"error": "..."} if that is what came back, and
// otherwise returns the raw body, bounded. Either way the text is the
// server's, not ours.
func serverMessage(body []byte) string {
	var decoded map[string]any
	if json.Unmarshal(body, &decoded) == nil {
		for _, key := range []string{"error", "message", "detail"} {
			if v, ok := decoded[key].(string); ok && v != "" {
				return truncate(v, 300)
			}
		}
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "(no message)"
	}
	return truncate(text, 300)
}

// -----------------------------------------------------------------------------
// observer.env rewriting
// -----------------------------------------------------------------------------

// readEnvValue reads one KEY=value out of an env file. A missing file is not an
// error - it means "never paired".
func readEnvValue(path, key string) (string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := splitEnvLine(line); ok && k == key {
			return strings.TrimSpace(v), nil
		}
	}
	return "", nil
}

// splitEnvLine parses "KEY=value", ignoring blank lines and comments.
func splitEnvLine(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	eq := strings.Index(trimmed, "=")
	if eq <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(trimmed[:eq]), trimmed[eq+1:], true
}

// rewriteEnvFile replaces (or appends) the managed keys and preserves every
// other line byte-for-byte.
//
// The write is atomic and never widens permissions: the temp file is CREATED
// 0600 in the same directory and renamed over the original, so no reader ever
// observes a partial file and no window exists in which the credentials sit in
// a world-readable file waiting for a chmod. Write-then-chmod would have
// exactly that window.
func rewriteEnvFile(path string, updates map[string]string) error {
	original, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	managed := make(map[string]bool, len(updates))
	for k := range updates {
		managed[k] = true
	}

	written := make(map[string]bool, len(updates))
	var kept []string
	endsWithNewline := true

	if len(original) > 0 {
		text := string(original)
		endsWithNewline = strings.HasSuffix(text, "\n")
		for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			key, _, ok := splitEnvLine(line)
			switch {
			case !ok || !managed[key]:
				// Untouched: comments, blanks, and every unrelated setting.
				kept = append(kept, line)
			case !written[key]:
				kept = append(kept, key+"="+updates[key])
				written[key] = true
			default:
				// A duplicate assignment of a managed key. Dropping it keeps
				// the file unambiguous - with two lines, whichever came last
				// would silently win.
			}
		}
	}

	// Anything not already in the file gets appended, in a fixed order.
	var appended []string
	for _, key := range pairEnvKeys {
		if _, ok := updates[key]; ok && !written[key] {
			appended = append(appended, key+"="+updates[key])
			written[key] = true
		}
	}

	content := strings.Join(append(kept, appended...), "\n")
	if content != "" && (endsWithNewline || len(appended) > 0) {
		// A file that ended without a newline keeps ending without one, unless
		// we had to extend it - in which case the keys we appended need a
		// terminator of their own.
		content += "\n"
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".observer.env.pair-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// Harmless once the rename has consumed the file.
		_ = os.Remove(tmpName)
	}()

	// os.CreateTemp creates with 0600; assert it rather than trusting it,
	// because this file holds the ingest token.
	if err := ensureMode0600(tmp); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	// fsync the directory so the rename itself survives a power loss.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ensureMode0600 verifies the temp file was created owner-only, and tightens it
// if some umask or filesystem quirk produced something looser. This is a
// check-and-repair on a file that does not exist yet from any other process's
// point of view - not a write-then-chmod of the real file.
func ensureMode0600(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm() == 0600 {
		return nil
	}
	return f.Chmod(0600)
}

// -----------------------------------------------------------------------------
// systemd
// -----------------------------------------------------------------------------

// systemctlStopAndWait stops the unit and does not return until the unit is no
// longer active. `systemctl stop` is already synchronous, but the poll makes
// the interlock explicit and survives a unit whose stop job is queued behind
// something else.
func systemctlStopAndWait(ctx context.Context, unit string) error {
	if err := systemctlRun(ctx, "stop", unit); err != nil {
		return err
	}
	deadline := time.Now().Add(serviceStopTimeout)
	for {
		state := systemctlIsActive(ctx, unit)
		switch state {
		case "active", "activating", "deactivating", "reloading":
			// still there
		default:
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("unit %s is still %s after %s", unit, state, serviceStopTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func systemctlRun(ctx context.Context, verb, unit string) error {
	cmd := exec.CommandContext(ctx, "systemctl", verb, unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %v: %s", verb, unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// systemctlIsActive returns the unit's state word. A non-zero exit from
// is-active is normal ("inactive", "failed") and is not an error here.
func systemctlIsActive(ctx context.Context, unit string) string {
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out))
}

// systemctlStatus returns the tail of the unit's status for the operator to
// read. Best effort: `systemctl status` exits non-zero for a failed unit, and
// that output is exactly what we want to show.
func systemctlStatus(ctx context.Context, unit string) string {
	out, _ := exec.CommandContext(ctx, "systemctl", "status", unit, "--no-pager", "-n", "15").CombinedOutput()
	return string(out)
}

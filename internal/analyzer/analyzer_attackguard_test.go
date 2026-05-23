package analyzer

import "testing"

// fwupd / systemd / sshd lifecycle lines contain ordinary English words
// ("update", "dropped") that substring-match the bare SQL keywords in
// attackIndicators. They are NOT attack payloads and must not block learning.
// Regression for the cache-miss bug where these re-classified on every cycle
// because the whole-line attack scan refused to learn a suppress hash for them.
func TestAttackGuard_ServiceTextNotTreatedAsPayload(t *testing.T) {
	clean := []string{
		"Started fwupd.service - Firmware update daemon.",
		"Starting fwupd.service - Firmware update daemon...",
		"Starting fwupd-refresh.service - Refresh fwupd metadata and update motd...",
		"Finished fwupd-refresh.service - Refresh fwupd metadata and update motd.",
		"sshd dropped an unauthenticated connection due to MaxStartups",
	}
	for _, ln := range clean {
		if hasAttackPayloadForLearning(ln) {
			t.Errorf("non-HTTP service line wrongly flagged as attack payload: %q", ln)
		}
	}
}

// The fix must not weaken the guard for real web attacks: an SQLi embedded in an
// nginx error-log request is still flagged.
func TestAttackGuard_NginxEmbeddedAttackStillCaught(t *testing.T) {
	line := `2026/01/02 03:04:05 [error] 1#1: *1 open() "/var/www/x" failed (2: No such file or directory), request: "GET /p?id=1 UNION SELECT pw FROM users HTTP/1.1", client: 1.2.3.4`
	if !hasAttackPayloadForLearning(line) {
		t.Fatal("SQLi inside an nginx error-log request must still be flagged")
	}
}

// Documents the root cause: the old whole-line scanner DID match these, proving
// the guard — not the data — was the problem.
func TestAttackGuard_OldWholeLineScannerWasTheBug(t *testing.T) {
	if !hasAttackIndicators("Started fwupd.service - Firmware update daemon.") {
		t.Fatal("sanity: the bare-keyword scanner should still match UPDATE in service text")
	}
}

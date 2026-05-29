// internal/rec/discovery_test.go
package rec

import (
	"encoding/json"
	"testing"
)

// A fixture /containers/json payload covering every classification branch.
const discoveryFixture = `[
  {
    "Id": "aaa111",
    "Names": ["/captain-nginx.1.abc"],
    "Ports": [
      {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 80, "Type": "tcp", "PublishMode": "ingress"},
      {"IP": "0.0.0.0", "PrivatePort": 443, "PublicPort": 443, "Type": "tcp"}
    ]
  },
  {
    "Id": "bbb222",
    "Names": ["/captain-captain.1.def"],
    "Ports": [
      {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 3000, "Type": "tcp"}
    ]
  },
  {
    "Id": "ccc333",
    "Names": ["/coredns"],
    "Ports": [
      {"IP": "0.0.0.0", "PrivatePort": 53, "PublicPort": 53, "Type": "udp"}
    ]
  },
  {
    "Id": "ddd444",
    "Names": ["/redis"],
    "Ports": [
      {"PrivatePort": 6379, "PublicPort": 0, "Type": "tcp"}
    ]
  },
  {
    "Id": "eee555",
    "Names": ["/adminer"],
    "Ports": [
      {"IP": "127.0.0.1", "PrivatePort": 8080, "PublicPort": 8080, "Type": "tcp"}
    ]
  },
  {
    "Id": "fff666",
    "Names": ["/captain-certbot.1.ghi"],
    "Ports": [
      {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8081, "Type": "tcp"}
    ]
  }
]`

func TestClassifyContainers(t *testing.T) {
	var containers []dockerContainer
	if err := json.Unmarshal([]byte(discoveryFixture), &containers); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	// Exclude entry deliberately suffixed AND mixed-case to prove both sides
	// are normalized (base name + lowercase) before comparison.
	inv := classifyContainers(containers, map[string]bool{"Captain-Certbot.1.ghi": true})

	if inv.TotalRunning != 6 {
		t.Fatalf("TotalRunning = %d, want 6", inv.TotalRunning)
	}

	// --- Public: captain-nginx (2 ports) + captain-captain (host 3000 → ctr 80) ---
	pub := indexByName(inv.Public)
	if len(inv.Public) != 2 {
		t.Fatalf("Public = %d entries, want 2 (%v)", len(inv.Public), names(inv.Public))
	}

	nginx, ok := pub["captain-nginx"]
	if !ok {
		t.Fatal("captain-nginx not public-facing")
	}
	if len(nginx.Ports) != 2 {
		t.Fatalf("captain-nginx ports = %d, want 2", len(nginx.Ports))
	}
	assertPublish(t, "captain-nginx", nginx.Ports[0], 80, 80)
	assertPublish(t, "captain-nginx", nginx.Ports[1], 443, 443)
	if nginx.Ports[0].PublishMode != "ingress" {
		t.Fatalf("captain-nginx port[0] PublishMode = %q, want ingress", nginx.Ports[0].PublishMode)
	}

	cap, ok := pub["captain-captain"]
	if !ok {
		t.Fatal("captain-captain not public-facing")
	}
	if len(cap.Ports) != 1 {
		t.Fatalf("captain-captain ports = %d, want 1", len(cap.Ports))
	}
	// The whole point: host 3000 maps to container 80; both must be captured.
	assertPublish(t, "captain-captain", cap.Ports[0], 3000, 80)

	// UDP-only must never be public.
	if _, ok := pub["coredns"]; ok {
		t.Fatal("coredns (UDP-only) must not be public-facing")
	}

	// --- Excluded: captain-certbot, matched despite suffix + case ---
	if len(inv.Excluded) != 1 || inv.Excluded[0].Name != "captain-certbot" {
		t.Fatalf("Excluded = %v, want [captain-certbot]", names(inv.Excluded))
	}

	// --- Skipped: coredns (no TCP), redis (unpublished), adminer (loopback) ---
	skip := skipReasons(inv.Skipped)
	if len(skip) != 3 {
		t.Fatalf("Skipped = %d entries, want 3 (%v)", len(skip), skip)
	}
	if got := skip["coredns"]; got != "no published TCP ports" {
		t.Fatalf("coredns skip reason = %q", got)
	}
	if got := skip["redis"]; got != "no published TCP ports" {
		t.Fatalf("redis skip reason = %q", got)
	}
	if got := skip["adminer"]; got != "loopback-only publish" {
		t.Fatalf("adminer skip reason = %q", got)
	}
}

// --- helpers ---

func indexByName(pcs []publicContainer) map[string]publicContainer {
	m := make(map[string]publicContainer, len(pcs))
	for _, pc := range pcs {
		m[pc.Name] = pc
	}
	return m
}

func names(pcs []publicContainer) []string {
	out := make([]string, 0, len(pcs))
	for _, pc := range pcs {
		out = append(out, pc.Name)
	}
	return out
}

func skipReasons(scs []skippedContainer) map[string]string {
	m := make(map[string]string, len(scs))
	for _, sc := range scs {
		m[sc.Name] = sc.Reason
	}
	return m
}

func assertPublish(t *testing.T, who string, p tcpPublish, wantPublic, wantPrivate int) {
	t.Helper()
	if p.PublicPort != wantPublic || p.PrivatePort != wantPrivate {
		t.Fatalf("%s publish = host:%d→ctr:%d, want host:%d→ctr:%d",
			who, p.PublicPort, p.PrivatePort, wantPublic, wantPrivate)
	}
}

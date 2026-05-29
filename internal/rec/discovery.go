// internal/rec/discovery.go
package rec

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// =============================================================================
// Docker public-container discovery (Session 2 — DRY-RUN inventory)
// =============================================================================
//
// This file is observability-only. It queries Docker for running containers,
// classifies which are publicly reachable (published TCP ports), and logs an
// inventory of what Session 3 WILL eventually monitor. It opens NO sockets and
// starts NO sniffers — capture behavior is unchanged in every mode.
//
// The fetch (HTTP) and classify (pure) steps are split so the heuristic is
// unit-testable from a fixture payload with no Docker socket.

// dockerPort mirrors one entry of a container's Ports array from
// GET /containers/json. PublishMode is present on Swarm specs and harmless
// (empty) otherwise.
type dockerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
	PublishMode string `json:"PublishMode,omitempty"`
}

// dockerContainer is the subset of GET /containers/json we need.
type dockerContainer struct {
	ID    string       `json:"Id"`
	Names []string     `json:"Names"`
	Ports []dockerPort `json:"Ports"`
}

// tcpPublish records one published TCP port: the host side (PublicPort) and the
// container side (PrivatePort). They can differ — Docker can map host 3000 →
// container 80. Session 3 seeds its in-namespace sniffer with the PrivatePort,
// since REC inside the namespace sees the container port, not the host mapping.
type tcpPublish struct {
	PublicPort  int
	PrivatePort int
	IP          string
	PublishMode string
}

// publicContainer is a container exposing at least one externally-reachable TCP port.
type publicContainer struct {
	ID    string
	Name  string
	Ports []tcpPublish
}

// skippedContainer is a running container that is not externally monitorable.
type skippedContainer struct {
	Name   string
	Reason string // "no published TCP ports" | "loopback-only publish"
}

// discoveryInventory is the classified result — a preview of what Session 3 would monitor.
type discoveryInventory struct {
	TotalRunning int
	Public       []publicContainer  // externally-reachable TCP, not excluded
	Excluded     []publicContainer  // externally-reachable TCP but matched REC_EXCLUDE_CONTAINERS
	Skipped      []skippedContainer // internal-only / loopback-only
}

// baseName strips Docker's leading "/" and truncates at the first "." so a
// Swarm task name like "captain-nginx.1.hjfscqq05..." becomes "captain-nginx".
// Case is preserved (used for display).
func baseName(name string) string {
	name = strings.TrimPrefix(name, "/")
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	return name
}

// normalizeName is baseName lowercased — the canonical key for exclude matching.
// Both the container name and each REC_EXCLUDE_CONTAINERS entry pass through it,
// so "captain-captain", "captain-captain.1.hjf...", and "Captain-Captain" all
// resolve to the same key. These are the exclusion semantics Session 3 inherits.
func normalizeName(name string) string {
	return strings.ToLower(baseName(name))
}

// isLoopbackIP reports whether a publish bind is host-local (not externally
// reachable). Only 127.0.0.1 / ::1 are loopback; 0.0.0.0 / :: / "" are external.
func isLoopbackIP(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}

// newDockerClient builds a unix-socket HTTP client, mirroring the shape used by
// findContainerPID (nsenter.go). No new dependency.
func newDockerClient(dockerSocket string) *http.Client {
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", dockerSocket, 5*time.Second)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// fetchRunningContainers lists running containers via the Docker API, using the
// same server-side status filter the watcher uses.
func fetchRunningContainers(dockerSocket string) ([]dockerContainer, error) {
	client := newDockerClient(dockerSocket)
	resp, err := client.Get(`http://localhost/containers/json?filters={"status":["running"]}`)
	if err != nil {
		return nil, fmt.Errorf("querying Docker for containers: %w", err)
	}
	defer resp.Body.Close()

	var containers []dockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("parsing container list: %w", err)
	}
	return containers, nil
}

// classifyContainers is the pure, unit-testable heuristic. It partitions running
// containers into public-facing (externally-reachable TCP), excluded, and skipped.
//
// Rules:
//   - UDP ports are ignored entirely.
//   - A TCP port with PublicPort == 0 is not published externally.
//   - 127.0.0.1 / ::1 binds are loopback-only (host-local), not external.
//   - A container with ≥1 external TCP publish is public-facing; if its
//     normalized name is in the exclude set it goes to Excluded, else Public.
//   - TCP publishes that are all loopback → Skipped("loopback-only publish").
//   - No published TCP at all → Skipped("no published TCP ports").
//
// Both the container name and the exclude entries are normalized (baseName +
// lowercase) before comparison, so a suffixed/cased pasted value still matches.
func classifyContainers(containers []dockerContainer, exclude map[string]bool) discoveryInventory {
	// Normalize exclude keys once.
	norm := make(map[string]bool, len(exclude))
	for k := range exclude {
		if nk := normalizeName(k); nk != "" {
			norm[nk] = true
		}
	}

	inv := discoveryInventory{TotalRunning: len(containers)}
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = baseName(c.Names[0])
		}

		var external []tcpPublish
		hasTCPPublish := false
		for _, p := range c.Ports {
			if !strings.EqualFold(p.Type, "tcp") {
				continue // skip UDP entirely
			}
			if p.PublicPort == 0 {
				continue // not published externally
			}
			hasTCPPublish = true
			if isLoopbackIP(p.IP) {
				continue // host-local, not externally reachable
			}
			external = append(external, tcpPublish{
				PublicPort:  p.PublicPort,
				PrivatePort: p.PrivatePort,
				IP:          p.IP,
				PublishMode: p.PublishMode,
			})
		}

		switch {
		case len(external) > 0:
			pc := publicContainer{ID: c.ID, Name: name, Ports: external}
			if norm[normalizeName(name)] {
				inv.Excluded = append(inv.Excluded, pc)
			} else {
				inv.Public = append(inv.Public, pc)
			}
		case hasTCPPublish:
			inv.Skipped = append(inv.Skipped, skippedContainer{Name: name, Reason: "loopback-only publish"})
		default:
			inv.Skipped = append(inv.Skipped, skippedContainer{Name: name, Reason: "no published TCP ports"})
		}
	}
	return inv
}

// logInventory emits the [rec]-prefixed startup inventory.
func logInventory(inv discoveryInventory) {
	log.Printf("[rec] Discovery (dry-run): %d running containers — %d public-facing TCP, %d excluded, %d skipped",
		inv.TotalRunning, len(inv.Public), len(inv.Excluded), len(inv.Skipped))
	for _, pc := range inv.Public {
		log.Printf("[rec]   public-facing: %s → %s", pc.Name, formatPublishes(pc.Ports))
	}
	for _, pc := range inv.Excluded {
		log.Printf("[rec]   excluded:      %s (REC_EXCLUDE_CONTAINERS) → %s", pc.Name, formatPublishes(pc.Ports))
	}
	for _, sc := range inv.Skipped {
		log.Printf("[rec]   skipped:       %s (%s)", sc.Name, sc.Reason)
	}
	log.Printf("[rec] Opening a namespace capture per public-facing container above (excluded/skipped are not monitored).")
}

// privatePorts returns the container-side TCP ports of a public container — the
// ports REC sees from inside the namespace (e.g. captain-captain's 80, not host 3000).
func privatePorts(ports []tcpPublish) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p.PrivatePort > 0 {
			out = append(out, p.PrivatePort)
		}
	}
	return out
}

// unionPorts merges two port lists, dropping non-positive values and duplicates
// while preserving first-seen order (base before extra).
func unionPorts(base, extra []int) []int {
	seen := make(map[int]bool, len(base)+len(extra))
	out := make([]int, 0, len(base)+len(extra))
	for _, list := range [][]int{base, extra} {
		for _, p := range list {
			if p > 0 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// formatPublishes renders TCP publishes as "tcp host:3000→ctr:80, host:443→ctr:443".
func formatPublishes(ports []tcpPublish) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("host:%d→ctr:%d", p.PublicPort, p.PrivatePort))
	}
	return "tcp " + strings.Join(parts, ", ")
}

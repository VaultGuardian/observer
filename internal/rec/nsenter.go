package rec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// =============================================================================
// Network Namespace Capture — Seeing Inside Container Namespaces
// =============================================================================
//
// WHY THIS EXISTS:
//   On single-node Docker Swarm, container-to-container traffic stays INSIDE
//   Docker's virtual network namespaces. It never touches the host's network
//   stack. An AF_PACKET socket on the host sees nothing.
//
//   Multi-node Swarm uses VXLAN tunnels visible on the host — v0.12 handles that.
//   Single-node Swarm uses kernel veth pairs that route traffic entirely within
//   the container network namespace — invisible from the host.
//
// HOW IT WORKS:
//   1. Find the reverse proxy container's PID via Docker API
//   2. Open /proc/<PID>/ns/net (the container's network namespace)
//   3. Enter that namespace with setns(CLONE_NEWNET)
//   4. Create the AF_PACKET socket — it binds to the container's network stack
//   5. Return to the host namespace
//   6. The socket fd is now usable from any goroutine, but it sees the
//      container's network traffic (nginx ↔ backend HTTP)
//
// DESIGN PRINCIPLE:
//   Still Linux-boundary. No container modifications, no app config changes.
//   We're using /proc and setns — standard Linux kernel interfaces.
//   Works with any container runtime that exposes /proc/<PID>/ns/net.
//
// THREAD SAFETY:
//   setns() affects the calling OS thread, not the Go goroutine. We use
//   runtime.LockOSThread() to pin the goroutine during the namespace switch,
//   then unlock after returning to the host namespace. The socket fd survives
//   the switch — once created, it's bound to the namespace it was born in.

const (
	// SYS_SETNS is the syscall number for setns on amd64 Linux.
	// Using raw syscall to avoid requiring golang.org/x/sys/unix dependency.
	sysSetns = 308 // __NR_setns on x86_64

	// CLONE_NEWNET is the namespace type flag for network namespaces.
	cloneNewnet = 0x40000000
)

// setns wraps the setns(2) syscall. Enters the namespace referenced by fd.
// The nstype parameter specifies the namespace type (CLONE_NEWNET for network).
func setns(fd int, nstype int) error {
	_, _, errno := syscall.RawSyscall(uintptr(sysSetns), uintptr(fd), uintptr(nstype), 0)
	if errno != 0 {
		return fmt.Errorf("setns: %w", errno)
	}
	return nil
}

// openSocketInNamespace creates an AF_PACKET raw socket inside a container's
// network namespace. The socket sees the container's network traffic — including
// plaintext HTTP between reverse proxy and backend containers on overlay networks.
//
// The returned fd is usable from any goroutine after this function returns.
// The calling goroutine is temporarily pinned to an OS thread during the
// namespace switch, then unpinned after returning to the host namespace.
//
// Requires CAP_NET_RAW in the host namespace (we enter the container's
// network namespace but keep the host's user namespace / capabilities).
func openSocketInNamespace(pid int) (int, error) {
	// Pin this goroutine to a single OS thread. setns affects the thread,
	// not the goroutine — without pinning, Go's scheduler could move us
	// to a different thread between setns and socket creation.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the host's network namespace so we can return after creating the socket
	hostNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return -1, fmt.Errorf("opening host network namespace: %w", err)
	}
	defer hostNS.Close()

	// Open the target container's network namespace
	nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	targetNS, err := os.Open(nsPath)
	if err != nil {
		return -1, fmt.Errorf("opening container namespace %s: %w (is PID %d still running?)", nsPath, err, pid)
	}
	defer targetNS.Close()

	// Enter the container's network namespace
	if err := setns(int(targetNS.Fd()), cloneNewnet); err != nil {
		return -1, fmt.Errorf("entering container namespace (PID %d): %w", pid, err)
	}

	// Create the AF_PACKET socket — this is now inside the container's namespace.
	// It will see the container's network interfaces (eth0, eth1, lo).
	fd, sockErr := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))

	// ALWAYS return to host namespace, even if socket creation failed.
	// If we don't, this OS thread stays in the container namespace and
	// any goroutine scheduled on it would be in the wrong namespace.
	if err := setns(int(hostNS.Fd()), cloneNewnet); err != nil {
		// This is catastrophic — the thread is stuck in the wrong namespace.
		// Close the socket if we got one, and report the error.
		if fd >= 0 {
			syscall.Close(fd)
		}
		return -1, fmt.Errorf("CRITICAL: failed to return to host namespace: %w (thread may be contaminated)", err)
	}

	// Now check if socket creation succeeded
	if sockErr != nil {
		return -1, fmt.Errorf("creating raw socket in container namespace (PID %d): %w", pid, sockErr)
	}

	// Set receive timeout so readLoop can check for ctx.Done()
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("setting socket timeout: %w", err)
	}

	return fd, nil
}

// =============================================================================
// Container PID Discovery via Docker API
// =============================================================================

// containerInfo holds the minimum info needed from Docker API.
type containerInfo struct {
	ID   string
	Name string
	PID  int
}

// findContainerPID searches for a running container matching the name pattern
// and returns its PID. The pattern is a substring match against container names
// (case-insensitive). For CapRover: "captain-nginx" matches
// "captain-nginx.1.hjfscqq05nqtarebk0ps5xsgo".
func findContainerPID(dockerSocket, namePattern string) (*containerInfo, error) {
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", dockerSocket, 5*time.Second)
			},
		},
		Timeout: 10 * time.Second,
	}

	// List running containers
	resp, err := client.Get("http://localhost/containers/json")
	if err != nil {
		return nil, fmt.Errorf("querying Docker for containers: %w", err)
	}
	defer resp.Body.Close()

	var containers []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		State string   `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("parsing container list: %w", err)
	}

	// Find the container matching the pattern
	patternLower := strings.ToLower(namePattern)
	var matchID, matchName string
	for _, c := range containers {
		if c.State != "running" {
			continue
		}
		for _, name := range c.Names {
			// Docker prepends "/" to container names
			cleanName := strings.TrimPrefix(name, "/")
			if strings.Contains(strings.ToLower(cleanName), patternLower) {
				matchID = c.ID
				matchName = cleanName
				break
			}
		}
		if matchID != "" {
			break
		}
	}

	if matchID == "" {
		return nil, fmt.Errorf("no running container matching %q found", namePattern)
	}

	// Inspect the container for its PID
	inspectResp, err := client.Get(fmt.Sprintf("http://localhost/containers/%s/json", matchID))
	if err != nil {
		return nil, fmt.Errorf("inspecting container %s: %w", matchID, err)
	}
	defer inspectResp.Body.Close()

	var inspect struct {
		State struct {
			Pid int `json:"Pid"`
		} `json:"State"`
	}
	if err := json.NewDecoder(inspectResp.Body).Decode(&inspect); err != nil {
		return nil, fmt.Errorf("parsing container inspect: %w", err)
	}

	if inspect.State.Pid == 0 {
		return nil, fmt.Errorf("container %s has PID 0 (not running?)", matchName)
	}

	return &containerInfo{
		ID:   matchID[:12],
		Name: matchName,
		PID:  inspect.State.Pid,
	}, nil
}

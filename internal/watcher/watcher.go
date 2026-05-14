package watcher

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Container represents a running Docker container.
type Container struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	State string   `json:"State"`
	Image string   `json:"Image"`
}

// LogLine is a raw log line received from any collector.
type LogLine struct {
	// Docker fields (populated by Docker watcher)
	ContainerID   string
	ContainerName string

	// Generic source identity (populated by journald and future watchers).
	// When set, these override ContainerName/SourceDocker in event creation.
	SourceType string            // "docker", "journal", "file", etc.
	SourceName string            // container name, unit name, file path, etc.
	Metadata   map[string]string // source-specific extras (unit, pid, priority, etc.)

	Line      string
	Stream    string // "stdout", "stderr", "journal", "kernel", etc.
	Timestamp time.Time
}

// LogHandler is called for each log line received.
type LogHandler func(line LogLine)

// Watcher connects to the Docker socket and streams container logs.
type Watcher struct {
	socketPath      string
	selfContainerID string
	handler         LogHandler
	httpClient      *http.Client
}

func New(socketPath string, handler LogHandler) *Watcher {
	return &Watcher{
		socketPath: socketPath,
		handler:    handler,
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		},
	}
}

// SetSelfID tells the watcher to skip its own container's logs.
func (w *Watcher) SetSelfID(id string) {
	w.selfContainerID = id
}

// Run starts watching all running containers and listening for new ones.
func (w *Watcher) Run(ctx context.Context) error {
	// Get currently running containers
	containers, err := w.listContainers(ctx)
	if err != nil {
		return fmt.Errorf("listing containers: %w", err)
	}

	log.Printf("[watcher] Found %d running containers", len(containers))

	// Start streaming logs for each container
	for _, c := range containers {
		if c.ID == w.selfContainerID {
			continue
		}
		go w.streamLogs(ctx, c)
	}

	// Watch for new containers starting/stopping
	return w.watchEvents(ctx)
}

func (w *Watcher) listContainers(ctx context.Context) ([]Container, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://docker/v1.43/containers/json?filters={\"status\":[\"running\"]}", nil)
	if err != nil {
		return nil, err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var containers []Container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, err
	}

	return containers, nil
}

func (w *Watcher) streamLogs(ctx context.Context, c Container) {
	name := cleanName(c.Names)
	log.Printf("[watcher] Streaming logs for %s (%s)", name, shortID(c.ID))

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("http://docker/v1.43/containers/%s/logs?follow=true&stdout=true&stderr=true&since=%d&timestamps=true",
			c.ID, time.Now().Unix()), nil)
	if err != nil {
		log.Printf("[watcher] Error creating request for %s: %v", name, err)
		return
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		log.Printf("[watcher] Error streaming %s: %v", name, err)
		return
	}
	defer resp.Body.Close()

	// v0.52: Verify Docker API returned success before parsing frames.
	// Error responses are not multiplexed and would be misinterpreted as
	// frame headers.
	if resp.StatusCode != http.StatusOK {
		log.Printf("[watcher] Docker API returned %d for %s — skipping", resp.StatusCode, name)
		return
	}

	// Docker multiplexed stream format:
	// [8-byte header][payload]
	// Header: [stream_type(1)][0][0][0][size(4 big-endian)]
	reader := bufio.NewReader(resp.Body)
	header := make([]byte, 8)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, err := io.ReadFull(reader, header)
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				log.Printf("[watcher] Stream ended for %s: %v", name, err)
			}
			return
		}

		streamType := "stdout"
		if header[0] == 2 {
			streamType = "stderr"
		}

		size := binary.BigEndian.Uint32(header[4:8])

		// v0.52: Cap frame size to prevent OOM from malicious/noisy containers.
		// Docker's multiplexed log protocol includes a 32-bit size field — a
		// crafted frame could request up to 4GB. Normal log lines are well
		// under 1MB; anything larger is either malicious or a binary dump.
		// Kill the stream rather than draining attacker-controlled length.
		const maxFrameSize = 1 << 20 // 1MB
		if size > maxFrameSize {
			log.Printf("[watcher] Oversized frame from %s: %d bytes — killing stream", name, size)
			return
		}

		payload := make([]byte, size)
		_, err = io.ReadFull(reader, payload)
		if err != nil {
			return
		}

		line := strings.TrimSpace(string(payload))
		if line == "" {
			continue
		}

		// Parse Docker timestamp from log line.
		// Docker API with timestamps=true prepends RFC3339Nano:
		//   "2026-04-06T16:46:30.916575123Z actual log content"
		// Parse it for accurate event timing. Keep full line intact —
		// the normalizer already strips the timestamp prefix downstream.
		emittedAt := time.Now() // fallback if parsing fails
		if len(line) > 30 && line[4] == '-' && line[7] == '-' && line[10] == 'T' {
			if spaceIdx := strings.IndexByte(line, ' '); spaceIdx > 0 && spaceIdx < 40 {
				if ts, err := time.Parse(time.RFC3339Nano, line[:spaceIdx]); err == nil {
					emittedAt = ts
				}
			}
		}

		w.handler(LogLine{
			ContainerID:   c.ID,
			ContainerName: name,
			Line:          line,
			Stream:        streamType,
			Timestamp:     emittedAt,
		})
	}
}

func (w *Watcher) watchEvents(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://docker/v1.43/events?filters={\"event\":[\"start\"],\"type\":[\"container\"]}", nil)
	if err != nil {
		return err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var event struct {
			Action string `json:"Action"`
			Actor  struct {
				ID         string            `json:"ID"`
				Attributes map[string]string `json:"Attributes"`
			} `json:"Actor"`
		}

		if err := decoder.Decode(&event); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// v0.52: EOF or persistent decode error = dead stream. Break out
			// so the caller can reconnect. Prior to this fix, EOF caused a
			// hot-loop: Decode returns EOF instantly, ctx.Err() is nil, continue
			// loops back to Decode which returns EOF instantly again.
			if err == io.EOF {
				log.Printf("[watcher] Event stream closed (EOF) — will reconnect")
				return fmt.Errorf("event stream EOF: %w", err)
			}
			log.Printf("[watcher] Event decode error: %v — will reconnect", err)
			return fmt.Errorf("event decode: %w", err)
		}

		if event.Action == "start" && event.Actor.ID != w.selfContainerID {
			name := event.Actor.Attributes["name"]
			log.Printf("[watcher] New container started: %s (%s)", name, shortID(event.Actor.ID))
			go w.streamLogs(ctx, Container{
				ID:    event.Actor.ID,
				Names: []string{"/" + name},
			})
		}
	}
}

func cleanName(names []string) string {
	if len(names) == 0 {
		return "unknown"
	}
	return strings.TrimPrefix(names[0], "/")
}

// shortID safely truncates a container/actor ID for log display.
// Docker IDs are normally 64-char hex, but malformed responses,
// alternate runtimes, or mocked sockets could return shorter strings.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

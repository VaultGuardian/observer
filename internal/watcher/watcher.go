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

// LogLine is a raw log line received from a container.
type LogLine struct {
	ContainerID   string
	ContainerName string
	Line          string
	Stream        string // "stdout" or "stderr"
	Timestamp     time.Time
}

// LogHandler is called for each log line received.
type LogHandler func(line LogLine)

// Watcher connects to the Docker socket and streams container logs.
type Watcher struct {
	socketPath     string
	selfContainerID string
	handler        LogHandler
	httpClient     *http.Client
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
	log.Printf("[watcher] Streaming logs for %s (%s)", name, c.ID[:12])

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
		payload := make([]byte, size)
		_, err = io.ReadFull(reader, payload)
		if err != nil {
			return
		}

		line := strings.TrimSpace(string(payload))
		if line == "" {
			continue
		}

		w.handler(LogLine{
			ContainerID:   c.ID,
			ContainerName: name,
			Line:          line,
			Stream:        streamType,
			Timestamp:     time.Now(),
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
			log.Printf("[watcher] Event decode error: %v", err)
			continue
		}

		if event.Action == "start" && event.Actor.ID != w.selfContainerID {
			name := event.Actor.Attributes["name"]
			log.Printf("[watcher] New container started: %s (%s)", name, event.Actor.ID[:12])
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

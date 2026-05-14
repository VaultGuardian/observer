package rec

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// hasCapNetRaw checks if the current process has CAP_NET_RAW (bit 13)
// by reading the effective capabilities from /proc/self/status.
//
// To grant this capability without running as root, add to observer.service:
//
//	AmbientCapabilities=CAP_NET_RAW
func hasCapNetRaw() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		caps, err := strconv.ParseUint(hexStr, 16, 64)
		if err != nil {
			return false
		}
		// CAP_NET_RAW = bit 13
		return caps&(1<<13) != 0
	}
	return false
}

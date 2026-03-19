package normalizer

// DockerNormalizer handles logs from Docker containers where we don't have
// a more specific normalizer (nginx, postgres, etc.).
//
// Docker-specific framing (8-byte stream header, ISO timestamp prefix) is
// stripped upstream in NormalizeEvent() before this normalizer is called.
// So this normalizer only deals with the application log content itself.
//
// Since we don't know what application produced the log, we delegate entirely
// to GenericNormalizer for timestamp/IP/number stripping.
type DockerNormalizer struct {
	generic GenericNormalizer
}

func (d *DockerNormalizer) Family() string { return "docker" }

func (d *DockerNormalizer) Normalize(line string) string {
	// Docker framing already stripped by NormalizeEvent().
	// Delegate to generic for remaining variable stripping.
	return d.generic.Normalize(line)
}

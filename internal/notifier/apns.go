package notifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"crypto"
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// APNsNotifier sends push notifications to iOS devices via Apple's
// HTTP/2 APNs gateway using token-based (JWT) authentication.
type APNsNotifier struct {
	config     APNsConfig
	httpClient *http.Client
	privateKey *ecdsa.PrivateKey

	// JWT token cache — APNs tokens are valid for 1 hour,
	// we refresh at 50 minutes to avoid edge-case rejections.
	tokenMu   sync.RWMutex
	cachedJWT string
	tokenExp  time.Time
}

// APNsPayload is the notification payload sent to Apple's push service.
type APNsPayload struct {
	Aps APNsAps `json:"aps"`
}

type APNsAps struct {
	Alert APNsAlert `json:"alert"`
	Sound string    `json:"sound,omitempty"`
	Badge int       `json:"badge,omitempty"`
}

type APNsAlert struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Body     string `json:"body"`
}

func NewAPNsNotifier(cfg APNsConfig) (*APNsNotifier, error) {
	// Load the .p8 private key
	keyData, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading APNs key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from APNs key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing APNs private key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("APNs key is not ECDSA (got %T)", key)
	}

	return &APNsNotifier{
		config:     cfg,
		privateKey: ecKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			// Go's net/http supports HTTP/2 by default for HTTPS
		},
	}, nil
}

func (a *APNsNotifier) Name() string { return "push/ios" }

func (a *APNsNotifier) Send(ctx context.Context, alert Alert) error {
	token, err := a.getToken()
	if err != nil {
		return fmt.Errorf("generating APNs JWT: %w", err)
	}

	payload := APNsPayload{
		Aps: APNsAps{
			Alert: APNsAlert{
				Title:    formatAlertTitle(alert),
				Subtitle: string(alert.Severity),
				Body:     fmt.Sprintf("%s: %s", alert.ContainerName, truncateStr(alert.Reason, 200)),
			},
			Sound: "default",
			Badge: 1,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling APNs payload: %w", err)
	}

	// Select endpoint: sandbox vs production
	host := "https://api.sandbox.push.apple.com"
	if a.config.Production {
		host = "https://api.push.apple.com"
	}

	endpoint := fmt.Sprintf("%s/3/device/%s", host, a.config.DeviceToken)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating APNs request: %w", err)
	}

	req.Header.Set("Authorization", "bearer "+token)
	req.Header.Set("apns-topic", a.config.BundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10") // immediate delivery

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("APNs request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("APNs returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// getToken returns a cached JWT or creates a new one.
// APNs JWTs are valid for 60 minutes; we refresh at 50.
func (a *APNsNotifier) getToken() (string, error) {
	a.tokenMu.RLock()
	if a.cachedJWT != "" && time.Now().Before(a.tokenExp) {
		token := a.cachedJWT
		a.tokenMu.RUnlock()
		return token, nil
	}
	a.tokenMu.RUnlock()

	// Generate new JWT
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	// Double-check after acquiring write lock
	if a.cachedJWT != "" && time.Now().Before(a.tokenExp) {
		return a.cachedJWT, nil
	}

	now := time.Now()
	token, err := a.signJWT(now)
	if err != nil {
		return "", err
	}

	a.cachedJWT = token
	a.tokenExp = now.Add(50 * time.Minute)
	return token, nil
}

// signJWT creates an ES256-signed JWT for APNs authentication.
// Minimal implementation — no external JWT library needed.
func (a *APNsNotifier) signJWT(now time.Time) (string, error) {
	header := base64URLEncode([]byte(fmt.Sprintf(
		`{"alg":"ES256","kid":"%s"}`, a.config.KeyID)))

	claims := base64URLEncode([]byte(fmt.Sprintf(
		`{"iss":"%s","iat":%d}`, a.config.TeamID, now.Unix())))

	signingInput := header + "." + claims

	// Sign with ES256 (ECDSA using P-256 curve and SHA-256 hash)
	hash := crypto.SHA256.New()
	hash.Write([]byte(signingInput))
	digest := hash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, a.privateKey, digest)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	// ES256 signature is r || s, each padded to 32 bytes
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64URLEncode(sig), nil
}

func base64URLEncode(data []byte) string {
	s := base64.StdEncoding.EncodeToString(data)
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

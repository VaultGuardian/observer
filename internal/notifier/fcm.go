package notifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// FCMNotifier sends push notifications to Android devices via
// Firebase Cloud Messaging HTTP v1 API with OAuth2 service account auth.
type FCMNotifier struct {
	config       FCMConfig
	httpClient   *http.Client
	privateKey   *rsa.PrivateKey
	clientEmail  string

	// OAuth2 token cache — access tokens are typically valid for 1 hour
	tokenMu     sync.RWMutex
	accessToken string
	tokenExp    time.Time
}

// ServiceAccountKey is the parsed Google service account JSON.
type ServiceAccountKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

func NewFCMNotifier(cfg FCMConfig) (*FCMNotifier, error) {
	// Load service account JSON
	data, err := os.ReadFile(cfg.CredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("reading FCM credentials: %w", err)
	}

	var sa ServiceAccountKey
	if err := json.Unmarshal(data, &sa); err != nil {
		return nil, fmt.Errorf("parsing FCM credentials: %w", err)
	}

	if sa.Type != "service_account" {
		return nil, fmt.Errorf("FCM credentials must be a service_account (got %q)", sa.Type)
	}

	// Parse the RSA private key from PEM
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM from service account key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing FCM private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("FCM key is not RSA (got %T)", key)
	}

	// Use project ID from credentials if not set via env
	if cfg.ProjectID == "" {
		cfg.ProjectID = sa.ProjectID
	}

	return &FCMNotifier{
		config:      cfg,
		privateKey:  rsaKey,
		clientEmail: sa.ClientEmail,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

func (f *FCMNotifier) Name() string { return "push/fcm" }

func (f *FCMNotifier) Send(ctx context.Context, alert Alert) error {
	token, err := f.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("getting FCM access token: %w", err)
	}

	// FCM v1 message payload
	message := map[string]interface{}{
		"message": map[string]interface{}{
			"token": f.config.DeviceToken,
			"notification": map[string]string{
				"title": formatAlertTitle(alert),
				"body":  fmt.Sprintf("%s: %s", alert.ContainerName, truncateStr(alert.Reason, 200)),
			},
			"android": map[string]interface{}{
				"priority": "high",
				"notification": map[string]string{
					"channel_id": "vg_alerts",
					"sound":      "default",
				},
			},
			"data": map[string]string{
				"severity":       string(alert.Severity),
				"container_name": alert.ContainerName,
				"container_id":   alert.ContainerID,
				"reason":         alert.Reason,
				"timestamp":      alert.Timestamp.Format(time.RFC3339),
			},
		},
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshalling FCM payload: %w", err)
	}

	endpoint := fmt.Sprintf(
		"https://fcm.googleapis.com/v1/projects/%s/messages:send",
		f.config.ProjectID,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating FCM request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("FCM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("FCM returned %d: %s", resp.StatusCode, string(respBody))
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

// getAccessToken returns a cached OAuth2 access token or fetches a new one.
func (f *FCMNotifier) getAccessToken(ctx context.Context) (string, error) {
	f.tokenMu.RLock()
	if f.accessToken != "" && time.Now().Before(f.tokenExp) {
		token := f.accessToken
		f.tokenMu.RUnlock()
		return token, nil
	}
	f.tokenMu.RUnlock()

	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()

	// Double-check after write lock
	if f.accessToken != "" && time.Now().Before(f.tokenExp) {
		return f.accessToken, nil
	}

	// Create a self-signed JWT for Google's OAuth2 token endpoint
	now := time.Now()
	jwt, err := f.createGoogleJWT(now)
	if err != nil {
		return "", err
	}

	// Exchange JWT for an access token
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://oauth2.googleapis.com/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("google oauth2 returned %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	f.accessToken = tokenResp.AccessToken
	// Refresh 5 minutes before expiry
	f.tokenExp = now.Add(time.Duration(tokenResp.ExpiresIn-300) * time.Second)

	return f.accessToken, nil
}

// createGoogleJWT creates an RS256-signed JWT for Google's OAuth2 endpoint.
func (f *FCMNotifier) createGoogleJWT(now time.Time) (string, error) {
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims := fmt.Sprintf(`{"iss":"%s","scope":"https://www.googleapis.com/auth/firebase.messaging","aud":"https://oauth2.googleapis.com/token","iat":%d,"exp":%d}`,
		f.clientEmail, now.Unix(), now.Add(time.Hour).Unix())

	claimsEncoded := base64URLEncode([]byte(claims))
	signingInput := header + "." + claimsEncoded

	// Sign with RS256
	hash := crypto.SHA256.New()
	hash.Write([]byte(signingInput))
	digest := hash.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, f.privateKey, crypto.SHA256, digest)
	if err != nil {
		return "", fmt.Errorf("signing Google JWT: %w", err)
	}

	return signingInput + "." + base64URLEncode(sig), nil
}

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// config is everything learned from the selected .env file, before discovery.
type config struct {
	// Label distinguishes instances on screen and in /debug/state.
	Label string

	// WellKnownURL is the OIDC discovery document. Everything endpoint-shaped
	// (authorize, token, userinfo, end_session) comes from it, so the same
	// binary targets staging or production by switching ENV.
	WellKnownURL string

	ClientID     string
	ClientSecret string
	Redirect     string

	// Optional TrustNet machine-plane wiring. Discovery does not describe these:
	//   MachineURL is the /api/rp/v1/userinfo origin read with the consent-time
	//   access token; JWKSURL is where TrustNet's purge-webhook signing keys
	//   live. Either being empty disables its UI and route.
	MachineURL string
	JWKSURL    string

	Listen string

	// CAFile adds a PEM root (staging's internal CA) on top of the system
	// roots. TLSInsecure disables verification entirely — loud, dev-only.
	CAFile      string
	TLSInsecure bool
}

var env config

// disc is the discovered OIDC document, populated once at startup.
var disc oidcDiscovery

// httpc is shared by discovery, token exchange, userinfo and the machine probe.
var httpc *http.Client

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvBool(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// loadDotEnv reads a KEY=VALUE file into the process environment, without
// overwriting variables that are already set — so a real env var always wins
// over the selected file.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // absent is fine; loadConfig reports missing required vars
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if k == "" || os.Getenv(k) != "" {
			continue
		}
		os.Setenv(k, v)
	}
}

// selectEnvFile returns the file to load: ENV=staging -> .env.staging;
// ENV unset or empty -> .env.
func selectEnvFile() string {
	if e := strings.TrimSpace(os.Getenv("ENV")); e != "" {
		return ".env." + e
	}
	return ".env"
}

func loadConfig() {
	file := selectEnvFile()
	if _, err := os.Stat(file); err != nil && os.Getenv("ENV") != "" {
		log.Printf("warning: ENV=%s selected %s, which was not found", os.Getenv("ENV"), file)
	}
	loadDotEnv(file)

	env = config{
		Label:        getenv("LABEL", "oidc client"),
		WellKnownURL: getenv("WELL_KNOWN_URL", ""),
		ClientID:     getenv("CLIENT_ID", ""),
		ClientSecret: getenv("CLIENT_SECRET", ""),
		Redirect:     getenv("REDIRECT_URI", "http://localhost:5556/callback"),
		MachineURL:   strings.TrimSuffix(getenv("MACHINE_URL", ""), "/"),
		JWKSURL:      getenv("JWKS_URL", ""),
		Listen:       getenv("LISTEN", ":5556"),
		CAFile:       getenv("CA_FILE", ""),
		TLSInsecure:  getenvBool("TLS_INSECURE"),
	}
	// ISSUER is a convenience: derive the well-known URL from it.
	if env.WellKnownURL == "" {
		if iss := strings.TrimSuffix(getenv("ISSUER", ""), "/"); iss != "" {
			env.WellKnownURL = iss + "/.well-known/openid-configuration"
		}
	}
	if env.WellKnownURL == "" {
		log.Fatalf("WELL_KNOWN_URL (or ISSUER) is required (loaded %s)", file)
	}
	if env.ClientID == "" || env.ClientSecret == "" {
		log.Fatalf("CLIENT_ID and CLIENT_SECRET are required (loaded %s)", file)
	}

	httpc = newHTTPClient(env)
	d, err := fetchDiscovery(httpc, env.WellKnownURL)
	if err != nil {
		log.Fatalf("OIDC discovery %s: %v", env.WellKnownURL, err)
	}
	disc = d

	log.Printf("discovered issuer %s", disc.Issuer)
	log.Printf("  authorization_endpoint: %s", disc.AuthorizationEndpoint)
	log.Printf("  token_endpoint:         %s", disc.TokenEndpoint)
	log.Printf("  userinfo_endpoint:      %s", orNone(disc.UserInfoEndpoint))
	log.Printf("  end_session_endpoint:   %s", orNone(disc.EndSessionEndpoint))
	if env.MachineURL != "" {
		log.Printf("  machine URL:            %s", env.MachineURL)
	}
	if env.TLSInsecure {
		log.Printf("WARNING: TLS_INSECURE=true — certificate verification disabled")
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func newHTTPClient(c config) *http.Client {
	tlsCfg := &tls.Config{}
	if c.TLSInsecure {
		tlsCfg.InsecureSkipVerify = true
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			log.Fatalf("CA_FILE %s: %v", c.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("CA_FILE %s: no certificates found", c.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// --- PKCE + random -----------------------------------------------------------

// randB64(16) yields 22 characters. Keep the state above 8: Hydra rejects a
// shorter `state` with invalid_state, surfacing as a 302 to the callback
// carrying an error.
func randB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- flow state (in-memory, keyed by state) ----------------------------------

type flowState struct {
	State       string         `json:"state"`
	Nonce       string         `json:"nonce"`
	Verifier    string         `json:"code_verifier"`
	ClaimsParam string         `json:"claims_param,omitempty"`
	AuthURL     string         `json:"auth_url"`
	Code        string         `json:"code,omitempty"`
	TokenResp   map[string]any `json:"token_response,omitempty"`
	IDClaims    map[string]any `json:"id_token_claims,omitempty"`
	UserInfo    map[string]any `json:"userinfo,omitempty"`
	Error       string         `json:"error,omitempty"`
	// MachineProbe is the machine-plane /api/rp/v1/userinfo read, distinct from
	// UserInfo, which is the OIDC /userinfo.
	MachineProbe *machineProbe `json:"machine_probe,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
}

var (
	flowsMu sync.Mutex
	flows   = map[string]*flowState{}
	// Most recent logout token received on the back-channel.
	lastLogout   map[string]any
	lastLogoutMu sync.Mutex

	// Purge webhooks received. One entry per POST /purge; /debug/purge exposes
	// what arrived and whether its JWS verified against TrustNet's JWKS.
	purgeMu         sync.Mutex
	purgeDeliveries []purgeDelivery
)

// purgeDelivery is one received (and verification-attempted) purge webhook.
type purgeDelivery struct {
	ReceivedAt time.Time      `json:"received_at"`
	Verified   bool           `json:"verified"`
	Kid        string         `json:"kid,omitempty"`
	Error      string         `json:"error,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
	BodyLen    int            `json:"body_len"`
}

func recordPurge(d purgeDelivery) {
	purgeMu.Lock()
	defer purgeMu.Unlock()
	purgeDeliveries = append(purgeDeliveries, d)
}

func allPurges() []purgeDelivery {
	purgeMu.Lock()
	defer purgeMu.Unlock()
	out := make([]purgeDelivery, len(purgeDeliveries))
	copy(out, purgeDeliveries)
	return out
}

func putFlow(f *flowState) {
	flowsMu.Lock()
	defer flowsMu.Unlock()
	flows[f.State] = f
}

func getFlow(state string) *flowState {
	flowsMu.Lock()
	defer flowsMu.Unlock()
	return flows[state]
}

func allFlows() []*flowState {
	flowsMu.Lock()
	defer flowsMu.Unlock()
	out := make([]*flowState, 0, len(flows))
	for _, f := range flows {
		out = append(out, f)
	}
	return out
}

func resetFlows() {
	flowsMu.Lock()
	flows = map[string]*flowState{}
	flowsMu.Unlock()
	lastLogoutMu.Lock()
	lastLogout = nil
	lastLogoutMu.Unlock()
	purgeMu.Lock()
	purgeDeliveries = nil
	purgeMu.Unlock()
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupTest isolates the process globals and gives each test a fresh SQLite
// store. Tests run sequentially; each one restores the previous globals.
func setupTest(t *testing.T) *store {
	t.Helper()

	oldEnv, oldDisc, oldHTTP, oldStore := env, disc, httpc, dataStore
	oldKeys, oldFetched := jwksKeys, jwksFetched
	oldLast := lastLogout

	t.Cleanup(func() {
		env = oldEnv
		disc = oldDisc
		httpc = oldHTTP
		dataStore = oldStore
		jwksKeys = oldKeys
		jwksFetched = oldFetched
		lastLogoutMu.Lock()
		lastLogout = oldLast
		lastLogoutMu.Unlock()
		flowsMu.Lock()
		flows = map[string]*flowState{}
		flowsMu.Unlock()
	})

	env = config{
		Label:           "test RP",
		ClientID:        "client-1",
		ClientSecret:    "secret",
		Redirect:        "http://localhost:5556/callback",
		TokenAuthMethod: "post",
		SessionTTL:      time.Hour,
		PurgeStrict:     true,
		DBPath:          filepath.Join(t.TempDir(), "test.db"),
	}
	disc = oidcDiscovery{Issuer: "https://issuer.example"}
	httpc = &http.Client{Timeout: 5 * time.Second}
	jwksKeys = nil
	jwksFetched = time.Time{}
	lastLogoutMu.Lock()
	lastLogout = nil
	lastLogoutMu.Unlock()
	flowsMu.Lock()
	flows = map[string]*flowState{}
	flowsMu.Unlock()

	s, err := openStore(env.DBPath, env.SessionTTL)
	if err != nil {
		t.Fatal(err)
	}
	dataStore = s
	t.Cleanup(func() { s.Close() })
	return s
}

func testSession(t *testing.T, s *store, cookieID, sub, sid string) session {
	t.Helper()
	now := time.Now().UTC()
	x := session{
		IDHash:            hashSessionID(cookieID),
		Sub:               sub,
		SID:               sid,
		PreferredUsername: "vladimir",
		IDToken:           "id.token",
		AccessToken:       "access.token",
		Claims:            map[string]any{"sub": sub, "sid": sid, "preferred_username": "vladimir"},
		UserInfo:          map[string]any{"sub": sub},
		CreatedAt:         now,
		ExpiresAt:         now.Add(env.SessionTTL),
	}
	if err := s.createSession(x); err != nil {
		t.Fatal(err)
	}
	return x
}

func testCookie(id string) *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: id}
}

func serve(mux *http.ServeMux, method, target, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// unsignedJWT is enough for logout-token claim validation, which deliberately
// does not verify the OP's signature (this tool is an inspector).
func unsignedJWT(payload map[string]any) string {
	hb, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT"})
	pb, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb) + ".sig"
}

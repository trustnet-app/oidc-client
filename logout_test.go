package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func validLogoutClaims() map[string]any {
	return map[string]any{
		"iss": "https://issuer.example",
		"aud": "client-1",
		"iat": float64(time.Now().Unix()),
		"sid": "sid_1",
		"sub": "ppid_1",
		"events": map[string]any{
			backchannelLogoutEvent: map[string]any{},
		},
	}
}

func TestValidateLogoutToken(t *testing.T) {
	setupTest(t)

	if err := validateLogoutToken(validLogoutClaims()); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	withAud := validLogoutClaims()
	withAud["aud"] = []any{"other", "client-1"}
	if err := validateLogoutToken(withAud); err != nil {
		t.Fatalf("array aud rejected: %v", err)
	}

	noSID := validLogoutClaims()
	delete(noSID, "sid")
	if err := validateLogoutToken(noSID); err != nil {
		t.Fatalf("sub-only token rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example" }},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other" }},
		{"old iat", func(c map[string]any) { c["iat"] = float64(time.Now().Add(-10 * time.Minute).Unix()) }},
		{"future iat", func(c map[string]any) { c["iat"] = float64(time.Now().Add(5 * time.Minute).Unix()) }},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }},
		{"missing events", func(c map[string]any) { delete(c, "events") }},
		{"wrong event", func(c map[string]any) { c["events"] = map[string]any{"other": map[string]any{}} }},
		{"nonce", func(c map[string]any) { c["nonce"] = "not-allowed" }},
		{"no sid or sub", func(c map[string]any) { delete(c, "sid"); delete(c, "sub") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validLogoutClaims()
			tc.mutate(c)
			if err := validateLogoutToken(c); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	if err := validateLogoutToken(nil); err == nil {
		t.Fatal("nil claims accepted")
	}
}

func TestBackchannelLogoutEndsSessionAndShowsScreen(t *testing.T) {
	s := setupTest(t)
	x := testSession(t, s, "cookie-1", "ppid_1", "sid_1")

	form := "logout_token=" + url.QueryEscape(unsignedJWT(validLogoutClaims()))
	rr := serve(newMux(), "POST", "/backchannel-logout", form, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if got, _ := s.sessionByID(x.IDHash); got != nil {
		t.Fatal("session was not deleted")
	}
	ev, err := s.tombstoneByIDHash(x.IDHash)
	if err != nil || ev == nil || ev.Event != "logged_out" {
		t.Fatalf("tombstone = %+v, %v", ev, err)
	}

	rr = serve(newMux(), "GET", "/account", "", testCookie("cookie-1"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "You were signed out by TrustNet") {
		t.Fatalf("ended screen: status=%d body=%s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Expires.Before(time.Now()) {
		t.Fatalf("stale cookie was not cleared: %+v", cookies)
	}
}

func TestBackchannelLogoutRejectsInvalidAndAliases(t *testing.T) {
	setupTest(t)
	mux := newMux()

	if rr := serve(mux, "GET", "/backchannel", "", nil); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /backchannel = %d", rr.Code)
	}
	for _, path := range []string{"/backchannel", "/backchannel-logout"} {
		if rr := serve(mux, "POST", path, "", nil); rr.Code != http.StatusBadRequest {
			t.Fatalf("POST %s without token = %d", path, rr.Code)
		}
	}

	c := validLogoutClaims()
	c["nonce"] = "x"
	form := "logout_token=" + url.QueryEscape(unsignedJWT(c))
	if rr := serve(mux, "POST", "/backchannel", form, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid token = %d", rr.Code)
	}
}

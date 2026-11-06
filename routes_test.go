package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHomeAndAccountRedirects(t *testing.T) {
	s := setupTest(t)
	testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	mux := newMux()

	rr := serve(mux, "GET", "/", "", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Start login") {
		t.Fatalf("signed-out home: status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = serve(mux, "GET", "/", "", testCookie("cookie-1"))
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/account" {
		t.Fatalf("signed-in home: status=%d location=%q", rr.Code, rr.Header().Get("Location"))
	}

	rr = serve(mux, "GET", "/account", "", testCookie("cookie-1"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Logged in as vladimir") {
		t.Fatalf("dashboard: status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = serve(mux, "GET", "/account", "", nil)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/" {
		t.Fatalf("signed-out dashboard: status=%d location=%q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestLogoutClearsSessionAndRedirects(t *testing.T) {
	s := setupTest(t)
	disc.EndSessionEndpoint = "https://issuer.example/oauth2/sessions/logout"
	x := testSession(t, s, "cookie-1", "ppid_1", "sid_1")

	rr := serve(newMux(), "GET", "/logout", "", testCookie("cookie-1"))
	if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), disc.EndSessionEndpoint) {
		t.Fatalf("logout: status=%d location=%q", rr.Code, rr.Header().Get("Location"))
	}
	if got, _ := s.sessionByID(x.IDHash); got != nil {
		t.Fatal("session was not deleted")
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Expires.Before(time.Now()) {
		t.Fatalf("cookie was not cleared: %+v", cookies)
	}
	ev, err := s.latestSessionEvent(&session{IDHash: x.IDHash, Sub: x.Sub, SID: x.SID})
	if err != nil || ev == nil || ev.Event != "logged_out" || ev.Reason != "rp_initiated" {
		t.Fatalf("logout event = %+v, %v", ev, err)
	}
}

func TestResultRequiresMatchingSession(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()
	flowsMu.Lock()
	flows["state-1"] = &flowState{
		State: "state-1", CreatedAt: now,
		IDClaims: map[string]any{"sub": "ppid_1"},
	}
	flowsMu.Unlock()
	testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	testSession(t, s, "cookie-2", "ppid_2", "sid_2")

	rr := serve(newMux(), "GET", "/result?state=state-1", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated result = %d", rr.Code)
	}
	rr = serve(newMux(), "GET", "/result?state=state-1", "", testCookie("cookie-1"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Flow result") {
		t.Fatalf("owner result = %d %s", rr.Code, rr.Body.String())
	}
	rr = serve(newMux(), "GET", "/result?state=state-1", "", testCookie("cookie-2"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("foreign result = %d", rr.Code)
	}

	// A denial/error flow remains inspectable without a session.
	flowsMu.Lock()
	flows["state-error"] = &flowState{State: "state-error", Error: "access_denied", CreatedAt: now}
	flowsMu.Unlock()
	rr = serve(newMux(), "GET", "/result?state=state-error", "", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "access_denied") {
		t.Fatalf("error result = %d %s", rr.Code, rr.Body.String())
	}
}

func TestProtectedActionsAndStaticRoutes(t *testing.T) {
	setupTest(t)
	mux := newMux()

	if rr := serve(mux, "POST", "/rp-userinfo", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("probe without session = %d", rr.Code)
	}
	if rr := serve(mux, "GET", "/purge", "", nil); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /purge = %d", rr.Code)
	}
	if rr := serve(mux, "GET", "/does-not-exist", "", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d", rr.Code)
	}
	if rr := serve(mux, "GET", "/styles.css", "", nil); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "--accent") {
		t.Fatalf("styles = %d", rr.Code)
	}
	if rr := serve(mux, "GET", "/design.js", "", nil); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "demo-rp-theme") {
		t.Fatalf("design.js = %d", rr.Code)
	}
	if rr := serve(mux, "GET", "/healthz", "", nil); rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", rr.Code, rr.Body.String())
	}
}

func TestDebugResetRedirectsWhenAsked(t *testing.T) {
	setupTest(t)
	rr := serve(newMux(), "POST", "/debug/reset", "next=%2Fwebhooks", nil)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/webhooks" {
		t.Fatalf("reset = %d %q", rr.Code, rr.Header().Get("Location"))
	}
	rr = serve(newMux(), "POST", "/debug/reset", "", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("plain reset = %d", rr.Code)
	}
}

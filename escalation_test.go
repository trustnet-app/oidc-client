package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEscalateRequiresSessionAndRendersForm(t *testing.T) {
	s := setupTest(t)
	testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	mux := newMux()

	if rr := serve(mux, "GET", "/escalate", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("signed-out escalate = %d", rr.Code)
	}
	if rr := serve(mux, "POST", "/escalate", "", testCookie("cookie-1")); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST escalate = %d", rr.Code)
	}

	rr := serve(mux, "GET", "/escalate", "", testCookie("cookie-1"))
	if rr.Code != http.StatusOK {
		t.Fatalf("escalate = %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Request more claims from TrustNet",
		"Already shared",
		`name="escalate" value="1"`,
		`name="claim" value="preferred_username"`,
		`name="claim" value="phone_number"`,
		"Continue to TrustNet",
		`href="/escalate" aria-current="page"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("escalate form missing %q:\n%s", want, body)
		}
	}
}

func TestEscalateNavbarOnlyWhenSignedIn(t *testing.T) {
	s := setupTest(t)
	testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	mux := newMux()

	home := serve(mux, "GET", "/", "", nil).Body.String()
	if strings.Contains(home, `href="/escalate"`) {
		t.Fatal("signed-out home shows Escalate")
	}
	dashboard := serve(mux, "GET", "/account", "", testCookie("cookie-1")).Body.String()
	if !strings.Contains(dashboard, `href="/escalate"`) {
		t.Fatal("dashboard is missing Escalate")
	}
}

func TestEscalationStartCombinesClaimsAndForcesConsent(t *testing.T) {
	s := setupTest(t)
	testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	disc.AuthorizationEndpoint = "https://issuer.example/oauth2/auth"

	rr := serve(newMux(), "GET", "/start?escalate=1&claim=phone_number&claim=email", "", testCookie("cookie-1"))
	if rr.Code != http.StatusFound {
		t.Fatalf("escalation start = %d %s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if got := q.Get("prompt"); got != "consent" {
		t.Fatalf("prompt = %q", got)
	}
	if got := q.Get("scope"); got != "openid" {
		t.Fatalf("scope = %q", got)
	}

	var claimsDoc map[string]map[string]any
	if err := json.Unmarshal([]byte(q.Get("claims")), &claimsDoc); err != nil {
		t.Fatalf("claims parameter: %v", err)
	}
	for _, name := range []string{"email", "phone_number", "preferred_username"} {
		if _, ok := claimsDoc["id_token"][name]; !ok {
			t.Fatalf("claims parameter missing %q: %v", name, claimsDoc)
		}
	}

	f := getFlow(q.Get("state"))
	if f == nil || !f.Escalation {
		t.Fatalf("flow = %+v", f)
	}
	if got := strings.Join(f.PriorClaims, ","); got != "preferred_username" {
		t.Fatalf("prior claims = %q", got)
	}
	if got := strings.Join(f.RequestedClaims, ","); got != "email,phone_number,preferred_username" {
		t.Fatalf("requested claims = %q", got)
	}
}

func TestEscalationStartValidation(t *testing.T) {
	s := setupTest(t)
	testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	disc.AuthorizationEndpoint = "https://issuer.example/oauth2/auth"

	if rr := serve(newMux(), "GET", "/start?escalate=1&claim=phone_number", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("escalation without session = %d", rr.Code)
	}
	if rr := serve(newMux(), "GET", "/start?escalate=1&claim=preferred_username", "", testCookie("cookie-1")); rr.Code != http.StatusBadRequest {
		t.Fatalf("escalation without a new claim = %d", rr.Code)
	}
}

func TestEscalationOutcomeOnResult(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()
	flowsMu.Lock()
	flows["state-esc"] = &flowState{
		State:           "state-esc",
		CreatedAt:       now,
		Escalation:      true,
		PriorClaims:     []string{"email", "preferred_username"},
		RequestedClaims: []string{"email", "over_18", "phone_number", "preferred_username"},
		IDClaims:        map[string]any{"sub": "ppid_1", "email": "v@example.com"},
		UserInfo:        map[string]any{"sub": "ppid_1", "phone_number": "+15550001"},
	}
	flows["state-normal"] = &flowState{
		State:     "state-normal",
		CreatedAt: now,
		IDClaims:  map[string]any{"sub": "ppid_1", "email": "v@example.com"},
	}
	flows["state-denied"] = &flowState{
		State:           "state-denied",
		CreatedAt:       now,
		Escalation:      true,
		RequestedClaims: []string{"email", "phone_number"},
		Error:           "access_denied: the user cancelled",
	}
	flowsMu.Unlock()
	testSession(t, s, "cookie-1", "ppid_1", "sid_1")

	rr := serve(newMux(), "GET", "/result?state=state-esc", "", testCookie("cookie-1"))
	if rr.Code != http.StatusOK {
		t.Fatalf("escalation result = %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`data-testid="escalation-outcome"`,
		"2 of 4 requested claims returned",
		`data-claim="phone_number" data-outcome="shared"`,
		`data-claim="over_18" data-outcome="not_returned"`,
		"Already shared",
		"New request",
		"Not returned",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("result missing %q:\n%s", want, body)
		}
	}

	normal := serve(newMux(), "GET", "/result?state=state-normal", "", testCookie("cookie-1")).Body.String()
	if strings.Contains(normal, "Escalation outcome") {
		t.Fatal("normal result shows the escalation outcome card")
	}

	denied := serve(newMux(), "GET", "/result?state=state-denied", "", nil)
	if denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), "access_denied") {
		t.Fatalf("denied escalation = %d %s", denied.Code, denied.Body.String())
	}
	if strings.Contains(denied.Body.String(), "Escalation outcome") {
		t.Fatal("denied escalation shows the outcome card")
	}
}

func TestEscalationCallbackRedirectsToResult(t *testing.T) {
	setupTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token",
				"id_token":     unsignedJWT(map[string]any{"sub": "ppid_1"}),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sub": "ppid_1", "phone_number": "+15550001"})
	}))
	defer srv.Close()
	disc.TokenEndpoint = srv.URL + "/token"
	disc.UserInfoEndpoint = srv.URL + "/userinfo"
	httpc = srv.Client()

	now := time.Now().UTC()
	putFlow(&flowState{State: "state-esc", Verifier: "verifier", CreatedAt: now, Escalation: true, PriorSub: "ppid_1"})
	putFlow(&flowState{State: "state-normal", Verifier: "verifier", CreatedAt: now})

	rr := serve(newMux(), "GET", "/callback?state=state-esc&code=abc", "", nil)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/result?state=state-esc" {
		t.Fatalf("escalation callback = %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("escalation callback did not set a session cookie")
	}
	if f := getFlow("state-esc"); f == nil || f.Error != "" || claimString(f.IDClaims, "sub") != "ppid_1" {
		t.Fatalf("matching escalation was not accepted: %+v", f)
	}

	rr = serve(newMux(), "GET", "/callback?state=state-normal&code=abc", "", nil)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/account" {
		t.Fatalf("normal callback = %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestEscalationRejectsDifferentAccount(t *testing.T) {
	s := setupTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token",
				"id_token":     unsignedJWT(map[string]any{"sub": "ppid_other", "email": "other@example.com"}),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sub": "ppid_other"})
	}))
	defer srv.Close()
	disc.TokenEndpoint = srv.URL + "/token"
	disc.UserInfoEndpoint = srv.URL + "/userinfo"
	httpc = srv.Client()

	existing := testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	putFlow(&flowState{State: "state-esc", Verifier: "verifier", CreatedAt: time.Now().UTC(), Escalation: true, PriorSub: "ppid_1"})

	rr := serve(newMux(), "GET", "/callback?state=state-esc&code=abc", "", testCookie("cookie-1"))
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/result?state=state-esc" {
		t.Fatalf("mismatched callback = %d %q", rr.Code, rr.Header().Get("Location"))
	}
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("mismatched callback set a session cookie: %+v", cookies)
	}
	got, err := s.sessionByID(existing.IDHash)
	if err != nil || got == nil || got.Sub != "ppid_1" {
		t.Fatalf("existing session changed: %+v, %v", got, err)
	}
	f := getFlow("state-esc")
	if f == nil || !strings.Contains(f.Error, "same account") {
		t.Fatalf("flow error = %+v", f)
	}
	if f.IDClaims != nil || f.UserInfo != nil {
		t.Fatalf("rejected account claims were kept: %+v", f)
	}

	// The old session can view the error result; the other account's claims are
	// not rendered and the outcome card is absent.
	result := serve(newMux(), "GET", "/result?state=state-esc", "", testCookie("cookie-1"))
	if result.Code != http.StatusOK {
		t.Fatalf("mismatch result = %d %s", result.Code, result.Body.String())
	}
	if !strings.Contains(result.Body.String(), "same account") {
		t.Fatalf("mismatch result missing account error:\n%s", result.Body.String())
	}
	if strings.Contains(result.Body.String(), "Escalation outcome") {
		t.Fatal("mismatch result shows the outcome card")
	}
}

func TestEscalationEmptyState(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()
	claims := map[string]any{"sub": "ppid_1"}
	for _, name := range requestableClaims {
		claims[name] = "value"
	}
	if err := s.createSession(session{
		IDHash:    hashSessionID("cookie-1"),
		Sub:       "ppid_1",
		Claims:    claims,
		UserInfo:  map[string]any{"sub": "ppid_1"},
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	rr := serve(newMux(), "GET", "/escalate", "", testCookie("cookie-1"))
	if rr.Code != http.StatusOK {
		t.Fatalf("escalate = %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Every available claim is already shared with this RP.") {
		t.Fatalf("missing empty state:\n%s", body)
	}
	if strings.Contains(body, "Continue to TrustNet") {
		t.Fatal("empty state still offers the submit action")
	}
}

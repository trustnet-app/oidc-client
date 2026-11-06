package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func countRows(t *testing.T, s *store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestStoreSessionRoundTripAndTTL(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()

	x := testSession(t, s, "cookie-1", "ppid_1", "sid_1")
	got, err := s.sessionByID(x.IDHash)
	if err != nil || got == nil {
		t.Fatalf("sessionByID = %v, %v", got, err)
	}
	if got.Sub != "ppid_1" || got.SID != "sid_1" || got.Claims["preferred_username"] != "vladimir" || got.UserInfo["sub"] != "ppid_1" {
		t.Fatalf("unexpected session: %+v", got)
	}
	if got.IDToken != "id.token" || got.AccessToken != "access.token" {
		t.Fatalf("tokens not persisted: %+v", got)
	}

	if err := s.createSession(session{IDHash: "expired", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.sessionByID("expired"); err != nil || got != nil {
		t.Fatalf("expired session = %v, %v", got, err)
	}
	if n := countRows(t, s, "sessions"); n != 1 {
		t.Fatalf("expired session was not deleted: %d rows", n)
	}
}

func TestStorePruneRemovesOnlyExpiredState(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()
	testSession(t, s, "live", "ppid_live", "sid_live")

	if err := s.createSession(session{IDHash: "old", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordSessionEvent(sessionEvent{SessionHash: "h", Event: "logged_in", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordSessionEvent(sessionEvent{SessionHash: "h", Event: "logged_out", CreatedAt: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordWebhook(webhookRecord{ReceivedAt: now, Verified: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordWebhook(webhookRecord{ReceivedAt: now.Add(-2 * time.Hour), Verified: true}); err != nil {
		t.Fatal(err)
	}

	if err := s.prune(now); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, "sessions"); n != 1 {
		t.Fatalf("sessions after prune = %d, want 1", n)
	}
	if n := countRows(t, s, "session_events"); n != 1 {
		t.Fatalf("session events after prune = %d, want 1", n)
	}
	if n := countRows(t, s, "webhook_deliveries"); n != 1 {
		t.Fatalf("webhook deliveries after prune = %d, want 1", n)
	}
}

func TestDeleteSessionsForLogoutUsesSIDThenSub(t *testing.T) {
	s := setupTest(t)
	testSession(t, s, "a", "ppid_1", "sid_1")
	testSession(t, s, "b", "ppid_2", "sid_1")
	testSession(t, s, "c", "ppid_3", "sid_2")

	hashes, err := s.deleteSessionsForLogout("sid_1", "ppid_3")
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 2 {
		t.Fatalf("sid deletion returned %d hashes, want 2", len(hashes))
	}
	if n := countRows(t, s, "sessions"); n != 1 {
		t.Fatalf("sessions after sid deletion = %d, want 1", n)
	}

	// No matching sid: fall back to sub.
	testSession(t, s, "d", "ppid_4", "sid_4")
	testSession(t, s, "e", "ppid_4", "sid_5")
	hashes, err = s.deleteSessionsForLogout("missing", "ppid_4")
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 2 {
		t.Fatalf("sub fallback returned %d hashes, want 2", len(hashes))
	}
}

func TestTombstoneLookup(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()
	if err := s.recordSessionEvent(sessionEvent{
		SessionHash: "h1", Sub: "ppid_1", SID: "sid_1", Event: "revoked",
		Reason: "user_revoke", DeliveryID: "dlv_1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordSessionEvent(sessionEvent{
		SessionHash: "h1", Sub: "ppid_1", SID: "sid_1", Event: "logged_in", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	ev, err := s.tombstoneByIDHash("h1")
	if err != nil || ev == nil {
		t.Fatalf("tombstone = %v, %v", ev, err)
	}
	if ev.Event != "revoked" || ev.Reason != "user_revoke" || ev.DeliveryID != "dlv_1" {
		t.Fatalf("unexpected tombstone: %+v", ev)
	}
	if ev, err := s.tombstoneByIDHash("missing"); err != nil || ev != nil {
		t.Fatalf("missing tombstone = %v, %v", ev, err)
	}
}

func TestRecentWebhooksAndLogoutEvents(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()
	if err := s.recordWebhook(webhookRecord{
		ReceivedAt: now, Verified: true, Kid: "kid_1",
		Payload: map[string]any{"event": "access.revoked", "delivery_id": "dlv_1"}, BodyLen: 100,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordWebhook(webhookRecord{ReceivedAt: now.Add(-time.Minute), Error: "bad"}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordSessionEvent(sessionEvent{
		SessionHash: "h1", Sub: "ppid_1", SID: "sid_1", Event: "logged_out",
		Reason: "backchannel_logout", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordSessionEvent(sessionEvent{
		SessionHash: "h1", Sub: "ppid_1", SID: "sid_1", Event: "logged_out",
		Reason: "rp_initiated", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	deliveries, err := s.recentWebhooks(10)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("deliveries = %d, %v", len(deliveries), err)
	}
	if !deliveries[0].Verified || deliveries[0].Kid != "kid_1" || deliveries[0].Payload["event"] != "access.revoked" {
		t.Fatalf("unexpected newest delivery: %+v", deliveries[0])
	}

	events, err := s.recentLogoutEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("logout events = %d, %v", len(events), err)
	}
	if events[0].Reason != "backchannel_logout" {
		t.Fatalf("unexpected logout event: %+v", events[0])
	}
}

func TestStoreReset(t *testing.T) {
	s := setupTest(t)
	testSession(t, s, "cookie", "ppid", "sid")
	if err := s.recordSessionEvent(sessionEvent{Event: "logged_in", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordWebhook(webhookRecord{ReceivedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.reset(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"sessions", "session_events", "webhook_deliveries"} {
		if n := countRows(t, s, table); n != 0 {
			t.Fatalf("%s after reset = %d", table, n)
		}
	}
}

func TestSessionCookie(t *testing.T) {
	setupTest(t)
	env.SessionTTL = time.Hour
	env.CookieSecure = true

	id, hash := newSessionID()
	if len(id) == 0 || hashSessionID(id) != hash {
		t.Fatal("session id/hash mismatch")
	}

	w := httptest.NewRecorder()
	setSessionCookie(w, id)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != sessionCookieName || c.Value != id || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || !c.Secure {
		t.Fatalf("unexpected cookie: %+v", c)
	}
	if c.MaxAge <= 0 {
		t.Fatalf("cookie MaxAge = %d", c.MaxAge)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if got := sessionIDFromRequest(req); got != id {
		t.Fatalf("sessionIDFromRequest = %q", got)
	}

	clear := httptest.NewRecorder()
	clearSessionCookie(clear)
	cleared := clear.Result().Cookies()
	if len(cleared) != 1 || !cleared[0].Expires.Before(time.Now()) {
		t.Fatalf("clear cookie = %+v", cleared)
	}
}

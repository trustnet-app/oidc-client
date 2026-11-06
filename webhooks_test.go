package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func purgeTestKey(t *testing.T, priv ed25519.PrivateKey, kid string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "OKP", "crv": "Ed25519", "kid": kid,
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	env.JWKSURL = srv.URL
	jwksKeys = nil
	jwksFetched = time.Time{}
	return srv
}

func signJWS(t *testing.T, priv ed25519.PrivateKey, kid string, payload map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(priv, []byte(h+"."+p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func purgePayload(clientID, event, sub, reason, deliveryID string) map[string]any {
	return map[string]any{
		"event":       event,
		"client_id":   clientID,
		"subs":        []any{sub},
		"reason":      reason,
		"delivery_id": deliveryID,
	}
}

func postPurge(mux *http.ServeMux, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/purge", strings.NewReader(token))
	req.Header.Set("Content-Type", "application/jwt")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestPurgeErasesSessionAndShowsErasedScreen(t *testing.T) {
	s := setupTest(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	purgeTestKey(t, priv, "test-kid", nil)
	x := testSession(t, s, "cookie-erase", "ppid_1", "sid_1")

	token := signJWS(t, priv, "test-kid", purgePayload("client-1", "account.erased", "ppid_1", "user_erasure", "dlv_1"))
	if rr := postPurge(newMux(), token); rr.Code != http.StatusOK {
		t.Fatalf("purge status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if got, _ := s.sessionByID(x.IDHash); got != nil {
		t.Fatal("session was not deleted")
	}
	ev, err := s.tombstoneByIDHash(x.IDHash)
	if err != nil || ev == nil || ev.Event != "erased" || ev.DeliveryID != "dlv_1" {
		t.Fatalf("tombstone = %+v, %v", ev, err)
	}
	deliveries, err := s.recentWebhooks(10)
	if err != nil || len(deliveries) != 1 || !deliveries[0].Verified {
		t.Fatalf("deliveries = %+v, %v", deliveries, err)
	}

	rr := serve(newMux(), "GET", "/account", "", testCookie("cookie-erase"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Your demo RP data was erased") {
		t.Fatalf("erased screen: status=%d body=%s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Expires.Before(time.Now()) {
		t.Fatalf("stale cookie was not cleared: %+v", cookies)
	}

	jsonRR := serve(newMux(), "GET", "/debug/purge", "", nil)
	if jsonRR.Code != http.StatusOK || !strings.Contains(jsonRR.Body.String(), `"delivery_id":"dlv_1"`) {
		t.Fatalf("debug purge = %d %s", jsonRR.Code, jsonRR.Body.String())
	}
}

func TestPurgeRevokesSessionAndShowsEndedScreen(t *testing.T) {
	s := setupTest(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	purgeTestKey(t, priv, "test-kid", nil)
	x := testSession(t, s, "cookie-revoke", "ppid_2", "sid_2")

	token := signJWS(t, priv, "test-kid", purgePayload("client-1", "access.revoked", "ppid_2", "user_revoke", "dlv_2"))
	if rr := postPurge(newMux(), token); rr.Code != http.StatusOK {
		t.Fatalf("purge status = %d", rr.Code)
	}
	if got, _ := s.sessionByID(x.IDHash); got != nil {
		t.Fatal("session was not deleted")
	}
	ev, err := s.tombstoneByIDHash(x.IDHash)
	if err != nil || ev == nil || ev.Event != "revoked" {
		t.Fatalf("tombstone = %+v, %v", ev, err)
	}

	rr := serve(newMux(), "GET", "/account", "", testCookie("cookie-revoke"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "You were signed out by TrustNet") {
		t.Fatalf("ended screen: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPurgeRejectsBadSignatureStrict(t *testing.T) {
	s := setupTest(t)
	_, goodKey, _ := ed25519.GenerateKey(rand.Reader)
	_, badKey, _ := ed25519.GenerateKey(rand.Reader)
	purgeTestKey(t, goodKey, "test-kid", nil)
	x := testSession(t, s, "cookie-bad", "ppid_3", "sid_3")

	token := signJWS(t, badKey, "test-kid", purgePayload("client-1", "access.revoked", "ppid_3", "user_revoke", "dlv_3"))
	if rr := postPurge(newMux(), token); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad signature status = %d, want 400", rr.Code)
	}
	if got, _ := s.sessionByID(x.IDHash); got == nil {
		t.Fatal("session was deleted by an unverified purge")
	}
	deliveries, _ := s.recentWebhooks(10)
	if len(deliveries) != 1 || deliveries[0].Verified || deliveries[0].Error == "" {
		t.Fatalf("delivery = %+v", deliveries)
	}
}

func TestPurgeNonStrictRecordsAndReturnsOK(t *testing.T) {
	s := setupTest(t)
	env.PurgeStrict = false
	_, goodKey, _ := ed25519.GenerateKey(rand.Reader)
	_, badKey, _ := ed25519.GenerateKey(rand.Reader)
	purgeTestKey(t, goodKey, "test-kid", nil)
	x := testSession(t, s, "cookie-loose", "ppid_4", "sid_4")

	token := signJWS(t, badKey, "test-kid", purgePayload("client-1", "access.revoked", "ppid_4", "user_revoke", "dlv_4"))
	if rr := postPurge(newMux(), token); rr.Code != http.StatusOK {
		t.Fatalf("non-strict status = %d, want 200", rr.Code)
	}
	if got, _ := s.sessionByID(x.IDHash); got == nil {
		t.Fatal("session was deleted by an unverified purge")
	}
	deliveries, _ := s.recentWebhooks(10)
	if len(deliveries) != 1 || deliveries[0].Verified {
		t.Fatalf("delivery = %+v", deliveries)
	}
}

func TestPurgeRejectsBadPayload(t *testing.T) {
	s := setupTest(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	purgeTestKey(t, priv, "test-kid", nil)
	x := testSession(t, s, "cookie-payload", "ppid_5", "sid_5")

	token := signJWS(t, priv, "test-kid", purgePayload("wrong-client", "access.revoked", "ppid_5", "user_revoke", "dlv_5"))
	if rr := postPurge(newMux(), token); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad payload status = %d, want 400", rr.Code)
	}
	if got, _ := s.sessionByID(x.IDHash); got == nil {
		t.Fatal("session was deleted by an invalid payload")
	}
	deliveries, _ := s.recentWebhooks(10)
	if len(deliveries) != 1 || !deliveries[0].Verified || !strings.HasPrefix(deliveries[0].Error, "payload:") {
		t.Fatalf("delivery = %+v", deliveries)
	}
}

func TestJWKSCache(t *testing.T) {
	setupTest(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var hits atomic.Int32
	purgeTestKey(t, priv, "test-kid", &hits)

	if _, err := jwksKey("test-kid"); err != nil {
		t.Fatal(err)
	}
	if _, err := jwksKey("test-kid"); err != nil {
		t.Fatal(err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 (cache miss then hit)", got)
	}

	jwksFetched = time.Time{}
	if _, err := jwksKey("test-kid"); err != nil {
		t.Fatal(err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("JWKS fetches after expiry = %d, want 2", got)
	}
}

func TestWebhooksPage(t *testing.T) {
	s := setupTest(t)
	now := time.Now().UTC()
	if err := s.recordWebhook(webhookRecord{
		ReceivedAt: now, Verified: true,
		Payload: map[string]any{
			"event": "access.revoked", "reason": "user_revoke",
			"delivery_id": "dlv_page", "subs": []any{"ppid_page"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordSessionEvent(sessionEvent{
		SessionHash: "h", Sub: "ppid_page", SID: "sid_page",
		Event: "logged_out", Reason: "backchannel_logout", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	rr := serve(newMux(), "GET", "/webhooks", "", nil)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, "dlv_page") ||
		!strings.Contains(body, "Back-channel logout events") ||
		!strings.Contains(body, "sid_page") {
		t.Fatalf("webhooks page: status=%d body=%s", rr.Code, body)
	}

	if err := s.reset(); err != nil {
		t.Fatal(err)
	}
	rr = serve(newMux(), "GET", "/webhooks", "", nil)
	if !strings.Contains(rr.Body.String(), "No deliveries yet") {
		t.Fatalf("empty webhooks page: %s", rr.Body.String())
	}
}

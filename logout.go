package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// POST /backchannel-logout (and /backchannel) — TrustNet's server-to-server
// logout. The token is inspected, not signature-verified (this tool remains an
// inspector); its claims must still be internally consistent.
func handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	claims := decodeJWT(r.PostFormValue("logout_token"))
	if err := validateLogoutToken(claims); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lastLogoutMu.Lock()
	lastLogout = claims
	lastLogoutMu.Unlock()

	sid := claimString(claims, "sid")
	sub := claimString(claims, "sub")
	hashes, err := dataStore.deleteSessionsForLogout(sid, sub)
	if err != nil {
		http.Error(w, "session store: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// One tombstone per deleted session lets a stale browser cookie resolve to
	// the ended screen. With no matching session, still record the event so the
	// delivery is visible in state/debug surfaces.
	now := time.Now().UTC()
	if len(hashes) == 0 {
		hashes = []string{""}
	}
	for _, h := range hashes {
		if err := dataStore.recordSessionEvent(sessionEvent{
			SessionHash: h,
			Sub:         sub,
			SID:         sid,
			Event:       "logged_out",
			Reason:      "backchannel_logout",
			CreatedAt:   now,
		}); err != nil {
			log.Printf("backchannel logout: record event: %v", err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func validateLogoutToken(claims map[string]any) error {
	if claims == nil {
		return fmt.Errorf("logout_token is missing or malformed")
	}
	if iss, _ := claims["iss"].(string); iss != disc.Issuer {
		return fmt.Errorf("logout_token iss does not match the issuer")
	}
	if !audienceContains(claims["aud"], env.ClientID) {
		return fmt.Errorf("logout_token aud does not include the client_id")
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("logout_token iat is missing")
	}
	now := float64(time.Now().Unix())
	if iat > now+60 || iat < now-300 {
		return fmt.Errorf("logout_token iat is outside the accepted window")
	}
	events, ok := claims["events"].(map[string]any)
	if !ok {
		return fmt.Errorf("logout_token events is missing")
	}
	if _, ok := events[backchannelLogoutEvent]; !ok {
		return fmt.Errorf("logout_token is missing the back-channel logout event")
	}
	if _, ok := claims["nonce"]; ok {
		return fmt.Errorf("logout_token must not contain nonce")
	}
	if claimString(claims, "sid") == "" && claimString(claims, "sub") == "" {
		return fmt.Errorf("logout_token must contain sid or sub")
	}
	return nil
}

func audienceContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// tombstoneForRequest resolves the browser's stale cookie to an ended/erased
// event, if one exists.
func tombstoneForRequest(r *http.Request) (*sessionEvent, error) {
	id := sessionIDFromRequest(r)
	if id == "" || dataStore == nil {
		return nil, nil
	}
	return dataStore.tombstoneByIDHash(hashSessionID(id))
}

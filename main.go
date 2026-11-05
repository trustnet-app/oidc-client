// oidc_oauth2_client — a standalone OIDC Relying Party inspector.
//
// A server-rendered OIDC client (authorization code + PKCE) configured from a
// .env file: WELL_KNOWN_URL + CLIENT_ID + CLIENT_SECRET. Endpoints are read from
// the well-known document, so the same binary targets staging or production by
// switching ENV (which selects .env.staging / .env.production).
//
// Derived from TrustNet's _DEV/mock-rp fixture, with discovery in place of the
// hardcoded local Hydra wiring. Like that fixture, this is a test tool: it
// decodes JWTs without verifying signatures — an inspector, not a validator.
package main

import (
	"log"
	"net/http"
	"net/url"
	"time"
)

func main() {
	loadConfig()

	st, err := openStore(env.DBPath, env.SessionTTL)
	if err != nil {
		log.Fatalf("store %s: %v", env.DBPath, err)
	}
	dataStore = st
	defer st.Close()
	st.startSweeper(time.Minute)
	log.Printf("store %s (session TTL %s, cookie Secure=%t)", env.DBPath, env.SessionTTL, env.CookieSecure)

	mux := http.NewServeMux()
	mux.HandleFunc("/styles.css", handleStyles)
	mux.HandleFunc("/design.js", handleDesignScript)
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/start", handleStart)
	mux.HandleFunc("/callback", handleCallback)
	// TrustNet sends the browser back to the configured REDIRECT_URI, whose path
	// may be anything (staging's client uses /redirect). Serve the authorization
	// response on that exact path so the redirect is always handled.
	if p := redirectPath(env.Redirect); p != "" && p != "/callback" {
		mux.HandleFunc(p, handleCallback)
	}
	mux.HandleFunc("/account", handleAccount)
	mux.HandleFunc("/result", handleResult)
	mux.HandleFunc("/rp-userinfo", handleRpUserinfo)
	mux.HandleFunc("/backchannel-logout", handleBackchannelLogout)
	mux.HandleFunc("/logout", handleLogout)
	// The RP purge webhook: TrustNet POSTs a signed revocation here after a user
	// revokes; /debug/purge exposes what arrived. Verification needs JWKS_URL.
	mux.HandleFunc("/purge", handlePurge)
	mux.HandleFunc("/debug/purge", handleDebugPurge)
	mux.HandleFunc("/debug/state", handleDebugState)
	mux.HandleFunc("/debug/reset", handleDebugReset)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("oidc client %q listening on %s (client_id=%s, redirect=%s)",
		env.Label, env.Listen, env.ClientID, env.Redirect)
	log.Fatal(http.ListenAndServe(env.Listen, mux))
}

// redirectPath returns the path of REDIRECT_URI, or "" when it is "/" (already
// covered by the home handler) or unparseable.
func redirectPath(redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil || u.Path == "" || u.Path == "/" {
		return ""
	}
	return u.Path
}

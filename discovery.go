package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// oidcDiscovery is the subset of the OIDC discovery document this client uses.
// Endpoints are absolute URLs; staging and production are single-origin, so the
// browser-facing and server-dialed origins are the same.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// fetchDiscovery retrieves and parses the well-known document. It fails loudly
// on anything that would make the flow impossible (unreachable, non-200,
// unparseable, or missing the two required endpoints).
func fetchDiscovery(c *http.Client, url string) (oidcDiscovery, error) {
	var d oidcDiscovery
	resp, err := c.Get(url)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return d, fmt.Errorf("decode document: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return d, fmt.Errorf("document missing authorization_endpoint or token_endpoint")
	}
	return d, nil
}

package main

import (
	_ "embed"
	"fmt"
	"html"
	"io"
	"net/http"
)

// The app and the _DESIGN catalogue share one visual language. Embedding the
// catalogue's stylesheet and theme script keeps the implementation from drifting
// away from the approved renderings.
//
//go:embed _DESIGN/styles.css
var appStyles string

//go:embed _DESIGN/design.js
var appScript string

func handleStyles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	io.WriteString(w, appStyles)
}

func handleDesignScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	io.WriteString(w, appScript)
}

func displayLabel() string {
	if env.Label == "" {
		return "OIDC test client"
	}
	return env.Label
}

// pageStart writes the shared shell: header, nav, and the opening <main>.
// Handlers append their content and finish with pageEnd. signedIn adds the
// Escalate action, which is only meaningful for a valid session.
func pageStart(w io.Writer, title, active string, signedIn bool) {
	escalate := ""
	if signedIn {
		escalate = navLink("/escalate", "Escalate", active == "escalate")
	}
	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<link rel="stylesheet" href="/styles.css">
<script src="/design.js" defer></script>
</head>
<body>
<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="/"><span class="brand-mark" aria-hidden="true"></span> %s</a>
    <nav class="nav" aria-label="Main">
      %s
      %s
      %s
      %s
      <a href="/debug/state">State</a>
      <a href="/logout">Log out</a>
      <button class="btn ghost small" type="button" data-theme-toggle>Dark</button>
    </nav>
  </div>
</header>
<main class="wrap">`, html.EscapeString(title), html.EscapeString(displayLabel()),
		navLink("/", "Home", active == "home"),
		navLink("/account", "Dashboard", active == "account"),
		escalate,
		navLink("/webhooks", "Webhooks", active == "webhooks"))
}

func navLink(href, text string, current bool) string {
	if current {
		return fmt.Sprintf(`<a href="%s" aria-current="page">%s</a>`, href, text)
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`, href, text)
}

func pageEnd(w io.Writer) {
	io.WriteString(w, `</main></body></html>`)
}

// renderError is the shared failure surface for HTML routes.
func renderError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	pageStart(w, "OIDC · error", "", false)
	fmt.Fprintf(w, `<section class="page-head">
<p class="eyebrow">Request failed</p>
<h1>Something went wrong</h1>
<p class="muted">%s</p>
</section>`, html.EscapeString(message))
	fmt.Fprintf(w, `<section class="card"><div class="card-head"><h2>Details</h2><span class="badge danger">%d</span></div><p>%s</p></section>`,
		status, html.EscapeString(message))
	fmt.Fprint(w, `<div class="row actions"><a class="btn" href="/">Back to home</a><a class="btn secondary" href="/account">Open dashboard</a></div>`)
	pageEnd(w)
}

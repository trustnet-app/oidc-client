# `_DESIGN` — rendered screen catalogue

Static, human-inspectable renderings of the demo RP's screens. This is a visual
laboratory, not the application: the data is fake, but the layout, hierarchy,
states, responsiveness, and accessibility are meant to match the real server-
rendered pages.

`_DOCS/screens/` remains the source of truth for behaviour, copy, and actions.
When a rendering and a doc disagree, the doc wins and the rendering is the
defect.

## Open it

No build step. Serve the directory (relative links work over HTTP):

```sh
python3 -m http.server -d _DESIGN 8000
# http://localhost:8000/
```

## Structure

```text
_DESIGN/
├── index.html          # catalogue hub
├── styles.css          # tokens + components (light/dark)
├── design.js           # theme switch, probe toggle, copy, reset preview
└── screens/
    ├── home.html
    ├── account-dashboard.html
    ├── flow-result.html
    ├── auth-preview.html
    ├── session-ended.html
    ├── account-erased.html
    ├── webhook-log.html
    └── error.html
```

## Rules

- **Docs first.** Every page maps 1:1 to a `_DOCS/screens/*.md` doc and a
  registry row in `_DOCS/index.md`.
- **One shell.** The header, nav, cards, tables, and buttons come from
  `styles.css`; do not add per-page copies.
- **No external assets.** System fonts and inline SVG/CSS only — the live demo
  serves no CDN resources.
- **A11y.** Keyboard-reachable focus, labels, semantic tables, and no meaning by
  colour alone.
- **Keep in sync.** When a screen doc changes, update its rendering in the same
  change.

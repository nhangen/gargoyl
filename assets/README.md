# Gargoyl logo and app icons

- `gargoyle.svg` — **the one canonical source** for the Gargoyl mark. It is
  stroke/fill agnostic on purpose: the outline uses `currentColor` so it
  inherits the surrounding text colour, and the two eyes are the accent
  (`.eyes`). Inline this path data in HTML, or reference the file from
  `assets/` directly.
- `icon/` — rendered icon set for browsers and packaged app surfaces:
  - `favicon.svg` — browser favicon
  - `apple-touch-icon.png` — 180×180, iOS home screen
  - `icon-192.png` / `icon-512.png` — PWA / manifest icons
  - `icon-maskable-512.png` — PWA maskable icon (safe-zone padded)
  - `gargoyl.icns` — macOS application icon

The renderer reads `gargoyle.svg` and writes `icon/` and
`gargoyl/dashboard/favicon.py` for the self-contained operator console.
Install librsvg to provide `rsvg-convert`, then run
`python assets/render_icons.py` after changing the mark.

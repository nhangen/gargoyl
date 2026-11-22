# Gargoyl logo and app icons

- `gargoyle.svg` — **the one canonical source** for the Gargoyl mark. It is
  stroke/fill agnostic on purpose: the outline uses `currentColor` so it
  inherits the surrounding text colour, and the two eyes are the accent
  (`.eyes`). Inline this path data in HTML, or reference the file from
  `assets/` directly.
- `icon/` — rendered icon set for browsers and packaged app surfaces:
  - `favicon.svg` — favicon (rounded dark plate + mark)
  - `apple-touch-icon.png` — 180×180, iOS home screen
  - `icon-192.png` / `icon-512.png` — PWA / manifest icons
  - `icon-maskable-512.png` — PWA maskable icon (safe-zone padded)
  - `gargoyl.icns` — macOS application icon

`icon/` is generated from `gargoyle.svg` by `assets/render_icons.py`;
re-render with `python assets/render_icons.py` after changing the mark.

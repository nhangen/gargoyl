# gargoyl.dev

Static homepage for Gargoyl. One third-party request: Google Analytics
(gtag, property Gargoyl (gargoyl.dev), measurement ID G-1DC6Z83Z0P) plus an
inline `site_click` event tracker. The display face (Archivo, SIL OFL 1.1)
is self-hosted, and the site ships no other JavaScript beyond the GA snippet
and the copy-button/click-tracker inline scripts.

- `links.json`: **the one place for external links** (GitHub, X, pilot sign-up)
- `src/`: page source. Links are written as `{{link:<name>}}` in `src/index.html`
- `src/docs/`: the developer docs page, served at `/docs/`. It links to repository docs with
  `{{doc:<file>}}`, which resolves against `docs_base` in `links.json`
  (lowercase file names in `docs/`; an unresolved token fails the build)
- `build.py`: renders `src/` into `dist/` (gitignored) with links filled in
- `og/`: source for the 1200×630 link-preview image `src/og.png`;
  re-render with `node site/og/render.js` (needs Playwright) after changing it;
  it exits non-zero if the self-hosted Archivo font does not load

## Before publishing

The GitHub and pilot links point at the repository, which is private. Visitors
without access get a 404, so make the repository public or repoint those links
in `links.json` before the site goes live. Any URL containing `REPLACE_ME`
renders with a dashed "placeholder URL" tag, and `python site/build.py --strict`
exits non-zero. Use `--strict` in the deploy build.

## Build and preview

```sh
python site/build.py
python -m http.server -d site/dist 8000
```

Then open http://localhost:8000. Any static host works: build command
`python site/build.py --strict`, output directory `site/dist`.

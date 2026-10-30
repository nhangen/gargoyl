# gargoyl.dev

Static homepage for Gargoyl. No JavaScript and no third-party requests; the
display face (Archivo, SIL OFL 1.1) is self-hosted.

- `links.json`: **the one place for external links** (GitHub, X, pilot sign-up)
- `src/`: page source. Links are written as `{{link:<name>}}` in `src/index.html`
- `build.py`: renders `src/` into `dist/` (gitignored) with links filled in

## Before publishing

Replace the `x` and `pilot` placeholders in `links.json`. The pilot link must be
reachable by visitors (the GitHub repository is private, so not a GitHub issue). While any URL contains
`REPLACE_ME`, its links render with a dashed "placeholder URL" tag, and
`python site/build.py --strict` exits non-zero. Use `--strict` in the deploy build.

## Build and preview

```sh
python site/build.py
python -m http.server -d site/dist 8000
```

Then open http://localhost:8000. Any static host works: build command
`python site/build.py --strict`, output directory `site/dist`.

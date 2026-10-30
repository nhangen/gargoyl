# gargoyl.dev

Static homepage for Gargoyl. No build step and no third-party requests (system fonts, inline SVG).

- `index.html` — page markup
- `styles.css` — styles, including reduced-motion handling
- `config.js` — **the one place for external links** (GitHub, X)
- `main.js` — applies links from `config.js` to every `[data-link]` element

## Before publishing

Replace `x: "https://x.com/REPLACE_ME"` in `config.js`. While the value contains
`REPLACE_ME`, each X link shows a dashed "placeholder URL" tag.

## Preview

```sh
python -m http.server -d site 8000
```

Then open http://localhost:8000. Any static host works; serve the `site/` directory as the web root.

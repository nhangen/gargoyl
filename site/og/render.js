// Renders site/og/og.html to site/src/og.png (1200x630). Requires Playwright.
const path = require("path");
const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
    await page.goto("file://" + path.join(__dirname, "og.html"));
    // Wait for the self-hosted Archivo font to actually load; if it is
    // missing, fail loudly instead of capturing in a fallback typeface.
    const fontReady = await page.evaluate(() =>
      Promise.race([
        document.fonts.ready.then(() => true),
        new Promise((resolve) => setTimeout(() => resolve(false), 5000)),
      ])
    );
    if (!fontReady) {
      throw new Error("timed out waiting for document.fonts.ready");
    }
    // fonts.check() is true when no face matches the family at all, so look
    // for a loaded Archivo face instead.
    const archivoLoaded = await page.evaluate(() =>
      [...document.fonts].some(
        (f) => f.family.replace(/"/g, "") === "Archivo" && f.status === "loaded"
      )
    );
    if (!archivoLoaded) {
      throw new Error("self-hosted Archivo font did not load");
    }
    await page.screenshot({ path: path.join(__dirname, "..", "src", "og.png") });
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(`og render failed: ${err.message}`);
  process.exit(1);
});

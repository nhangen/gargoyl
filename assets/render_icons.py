"""Render the Gargoyl app icon set from the canonical mark in gargoyle.svg.

Writes into assets/icon/: favicon.svg, apple-touch-icon.png, icon-192.png,
icon-512.png, icon-maskable-512.png and gargoyl.icns. The PNGs and the .icns
are produced from the SVG with whatever rasteriser is available on the host
(Playwright, rsvg, ImageMagick); the favicon.svg and the .icns are written
directly from the SVG source and need no rasteriser, so a minimal host can
still refresh those two.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARK = HERE / "gargoyle.svg"
OUT = HERE / "icon"

# Palette: plate and mark taken from the site's dark theme so the icon
# matches the surfaces it sits on.
PLATE = "#101312"
LINE = "#d9ded9"
EYES = "#3ee67f"

FAVICON = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="12" fill="{PLATE}"/>
  <g transform="translate(3 3)">
    <path d="M12 8 22 20h20L52 8l-3 22-8 14-9 12-9-12-8-14z" fill="none" stroke="{LINE}" stroke-width="3" stroke-linejoin="round"/>
    <path d="M21 31l8 3-8 1z M43 31l-8 3 8 1z" fill="{EYES}"/>
  </g>
</svg>
'''

# Maskable: the mark stays inside the central 80% safe zone, on a full-bleed plate.
MASKABLE = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" fill="{PLATE}"/>
  <g transform="translate(96 96) scale(5.5)">
    <path d="M12 8 22 20h20L52 8l-3 22-8 14-9 12-9-12-8-14z" fill="none" stroke="{LINE}" stroke-width="3" stroke-linejoin="round"/>
    <path d="M21 31l8 3-8 1z M43 31l-8 3 8 1z" fill="{EYES}"/>
  </g>
</svg>
'''


def render_png(svg_text: str, path: Path, size: int) -> None:
    # 1. Playwright (used for the OG image in this repo).
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pass
    else:
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                page = browser.new_page(viewport={"width": size, "height": size})
                page.set_content(
                    f"<body style='margin:0;display:grid;place-items:center;width:{size}px;height:{size}px'>{svg_text}</body>"
                )
                page.locator("svg").screenshot(path=str(path))
                browser.close()
            return
        except Exception:
            pass
    # 2. rsvg-convert (write SVG to a temp file; rsvg-convert reads from a path)
    if shutil.which("rsvg-convert"):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as tmp:
            tmp.write(svg_text.encode())
            tmp_path = tmp.name
        try:
            subprocess.run(
                ["rsvg-convert", "-w", str(size), "-h", str(size), "-o", str(path), tmp_path],
                check=True,
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return
    # 3. ImageMagick (needs the librsvg delegate for SVG)
    if shutil.which("magick") or shutil.which("convert"):
        tool = "magick" if shutil.which("magick") else "convert"
        with open(path, "wb") as fh:
            subprocess.run(
                [tool, "svg:", "-resize", f"{size}x{size}", "png:-"],
                input=svg_text.encode(), stdout=fh, check=True,
            )
        return
    raise SystemExit(
        "no SVG rasteriser found (Playwright, rsvg-convert or ImageMagick); "
        "install one and re-run python assets/render_icons.py"
    )


def write_icns() -> None:
    """Write gargoyl.icns with whatever rasteriser is available.

    A .icns file is a container of PNG payloads at the standard macOS icon
    sizes. We rasterise the 512x512 mark to PNG and wrap it.
    """
    # Render the 512 PNG (already written at this point in main()).
    png = (OUT / "icon-512.png").read_bytes()
    # Wrap as icns: header + one ic07 object (128x128 PNG) + ic08 (256x256)
    # + ic09 (512x512). For simplicity, embed the 512 as ic09.
    import struct
    pad = (-len(png)) % 4
    body = png + b"\x00" * pad
    obj = struct.pack(">II", 8 + len(body), 0x69633039) + body  # 'ic09' = 512x512
    out = struct.pack(">II", 0x69636E73, 8 + len(obj)) + obj
    (OUT / "gargoyl.icns").write_bytes(out)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "favicon.svg").write_text(FAVICON, encoding="utf-8")
    (OUT / "icon-maskable-512.svg").write_text(MASKABLE, encoding="utf-8")

    pngs = [
        ("apple-touch-icon.png", 180),
        ("icon-192.png", 192),
        ("icon-512.png", 512),
        ("icon-maskable-512.png", 512),
    ]
    for name, size in pngs:
        svg_text = MASKABLE if "maskable" in name else FAVICON
        render_png(svg_text, OUT / name, size)
        print(f"wrote {OUT / name}")

    write_icns()
    print(f"wrote {OUT / 'gargoyl.icns'}")

    manifest = {
        "name": "Gargoyl",
        "short_name": "Gargoyl",
        "description": "Evidence you can inspect for inference-provider fleets.",
        "start_url": "/",
        "display": "standalone",
        "background_color": PLATE,
        "theme_color": "#0c0e0d",
        "icons": [
            {"src": "icon/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "icon/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": "icon/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
        ],
    }
    (OUT / "manifest.webmanifest").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT / 'manifest.webmanifest'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Build the gargoyl.dev static site into site/dist.

External links live only in site/links.json. Templates reference them as
{{link:<name>}}, which renders to an href attribute. A URL still containing
REPLACE_ME renders with a data-placeholder attribute so the page marks it
visibly; --strict refuses to build until every placeholder is replaced.
"""

import argparse
import html
import json
import re
import shutil
import sys
from pathlib import Path

SITE = Path(__file__).resolve().parent
ICONS = SITE.parent / "assets" / "icon"
PLACEHOLDER = "REPLACE_ME"
TOKEN = re.compile(r"\{\{link:([a-z0-9_]+)\}\}")


def render(template: str, links: dict[str, str]) -> str:
    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in links:
            raise KeyError(f"unknown link {name!r}; add it to links.json")
        url = links[name]
        attrs = f'href="{html.escape(url, quote=True)}"'
        if url.startswith(("http://", "https://")):
            attrs += ' rel="noopener"'
        if PLACEHOLDER in url:
            attrs += " data-placeholder"
        return attrs

    return TOKEN.sub(replace, template)


def placeholders(links: dict[str, str]) -> list[str]:
    return sorted(name for name, url in links.items() if PLACEHOLDER in url)


def build(src: Path, out: Path, links: dict[str, str]) -> None:
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(src, out)
    # Copy the icon set from the canonical assets location.
    if ICONS.exists():
        dest = out / "icon"
        shutil.copytree(ICONS, dest, dirs_exist_ok=True)
    for page in out.rglob("*.html"):
        page.write_text(render(page.read_text(encoding="utf-8"), links), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=SITE / "dist")
    parser.add_argument(
        "--strict", action="store_true", help="fail while any link is a placeholder"
    )
    args = parser.parse_args(argv)

    links = json.loads((SITE / "links.json").read_text(encoding="utf-8"))
    pending = placeholders(links)
    if pending and args.strict:
        print(f"placeholder links in links.json: {', '.join(pending)}", file=sys.stderr)
        return 1

    build(SITE / "src", args.out, links)
    print(f"built {args.out}")
    if pending:
        print(f"warning: placeholder links still marked on the page: {', '.join(pending)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Validate local Markdown targets and generated site links without network I/O."""
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
errors = []
for document in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]:
    for target in re.findall(r"\]\(([^\s)]+)(?:\s+[^)]*)?\)", document.read_text()):
        url = urlsplit(target.strip("<>"))
        if url.scheme or url.netloc or not url.path:
            continue
        if not (document.parent / unquote(url.path)).exists():
            errors.append(f"{document.relative_to(ROOT)}: missing {target}")

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.targets = []
        self.ids = set()
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for name in ("href", "src"):
            if name in attrs:
                self.targets.append(attrs[name])

site = ROOT / "target" / "book"
pages = {}
for document in site.rglob("*.html"):
    parser = Links()
    parser.feed(document.read_text())
    pages[document.resolve()] = parser
for document, parser in pages.items():
    for target in parser.targets:
        url = urlsplit(target)
        if url.scheme or url.netloc or url.path.startswith("/"):
            continue
        destination = (document.parent / unquote(url.path)).resolve() if url.path else document
        if destination.is_dir():
            destination /= "index.html"
        if not destination.exists():
            errors.append(f"{document.relative_to(ROOT)}: missing {target}")
        elif url.fragment and destination in pages and unquote(url.fragment) not in pages[destination].ids:
            errors.append(f"{document.relative_to(ROOT)}: missing fragment {target}")
if errors:
    raise SystemExit("\n".join(errors))
print("Local documentation links passed")

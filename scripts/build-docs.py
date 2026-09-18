#!/usr/bin/env python3
"""Build the book and repair mdBook 0.5.4's non-keyboard sidebar label.

Keep this targeted transform until upstream ships a native button. The existing
controller remains the state owner; navigation.js supplies checkbox activation.
"""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
subprocess.run(["mdbook", "build"], cwd=root, check=True)
pattern = re.compile(r'<label (id="mdbook-sidebar-toggle"[^>]*)>(.*?)</label>', re.S)
for page in (root / "target" / "book").rglob("*.html"):
    content = page.read_text()
    if page.name == "toc.html":  # Separate no-JS TOC iframe, without a toggle.
        continue
    def button(match):
        attributes = match[1].replace(' for="mdbook-sidebar-toggle-anchor"', '')
        return '<button type="button" ' + attributes + '>' + match[2] + '</button>'
    updated, count = pattern.subn(button, content)
    if count != 1:
        raise SystemExit(f"{page}: expected one mdBook sidebar toggle, got {count}; review theme compatibility")
    updated = updated.replace('aria-describedby="searchresults-header"', 'aria-describedby="mdbook-searchresults-header"')
    page.write_text(updated)
# Search must also work with paste, dictation and other native input methods.
for script in (root / "target" / "book").glob("searcher-*.js"):
    source = script.read_text()
    old = "searchbar.addEventListener('keyup',"
    if source.count(old) != 1:
        raise SystemExit("Review mdBook search input compatibility")
    script.write_text(source.replace(old, "searchbar.addEventListener('input',"))

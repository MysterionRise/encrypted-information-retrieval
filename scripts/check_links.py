#!/usr/bin/env python3
"""Check that relative links in maintained Markdown files resolve.

Scans every tracked *.md file except docs/archive/ (historical material whose relative
links are allowed to break). Covers inline links `[text](target)` and reference
definitions `[label]: target`. Skips external URLs, mailto links and pure in-page
anchors. Exits non-zero and lists each broken link if any target does not exist.

Usage: python scripts/check_links.py
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

INLINE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
REFERENCE = re.compile(r"^\s*\[[^\]]+\]:\s+(\S+)", re.MULTILINE)
FENCE = re.compile(r"^(```|~~~).*?^\1", re.MULTILINE | re.DOTALL)
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def tracked_markdown(root: Path) -> list[Path]:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required to list tracked Markdown files")
    # Fixed argument list, no shell, no user input.
    out = subprocess.run(  # noqa: S603  # nosec B603
        [git, "ls-files", "*.md"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    return [root / line for line in out.splitlines() if not line.startswith("docs/archive/")]


def broken_links(path: Path) -> list[str]:
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    targets = INLINE.findall(text) + REFERENCE.findall(text)
    broken = []
    for target in targets:
        if target.startswith(SKIP_PREFIXES):
            continue
        file_part = target.split("#", 1)[0]
        if file_part and not (path.parent / file_part).exists():
            broken.append(target)
    return broken


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failures = 0
    files = tracked_markdown(root)
    for path in files:
        for target in broken_links(path):
            print(f"{path.relative_to(root)}: broken link -> {target}")
            failures += 1
    print(f"checked {len(files)} Markdown files: {failures} broken link(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

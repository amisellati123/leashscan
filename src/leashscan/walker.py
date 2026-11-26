"""File walking helpers."""

from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", ".nuxt",
    "target", ".gradle", ".idea", "vendor", "coverage", ".terraform", "site-packages",
}
# macOS app bundles and media libraries: huge, full of caches and OCR text, never agent config.
SKIP_SUFFIXES = (
    ".photoslibrary", ".photolibrary", ".musiclibrary", ".tvlibrary", ".app", ".bundle",
    ".framework", ".xcarchive", ".dSYM", ".lrcat", ".lrdata", ".fcpbundle", ".imovielibrary",
)
# Top-level folders of a home directory that hold app data and caches, not projects.
SKIP_AT_HOME = {"Library", ".Trash", ".cache", ".npm", ".cargo", ".rustup", ".pyenv", ".nvm",
                ".gradle", ".m2", "go", ".docker", "Music", "Movies", "Pictures", "AppData", "snap"}
MAX_FILES = 100_000

# Reports written by leashscan quote the suspicious text they found, so don't re-scan them.
# Strict: the file must *start* like one of our reports, and agent instruction files never count.
REPORT_PREFIXES = (
    "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
    "content=\"width=device-width,initial-scale=1\">\n<title>AI Agent Exposure Report \u00b7 leashscan</title>",
    "{\n  \"tool\": \"leashscan\",",
    "## \U0001F415 leashscan: grade",
    "\n  leashscan  v",
)
NEVER_SKIP = {"agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules",
              "copilot-instructions.md", "readme.md"}


def is_leashscan_report(path: Path, text: str) -> bool:
    if path.name.lower() in NEVER_SKIP:
        return False
    if text.startswith(REPORT_PREFIXES):
        return True
    # SARIF: our driver block sits right at the top of the run
    return text.startswith('{\n  "$schema": "https://json.schemastore.org/sarif-2.1.0.json"') and \
        '"driver": {\n            "name": "leashscan"' in text[:400]


def iter_files(root: Path, max_size: int = 1_000_000) -> Iterator[Path]:
    count = 0
    root = Path(root)
    at_home = root.resolve() == Path.home().resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        top = at_home and Path(dirpath).resolve() == root.resolve()
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.endswith(SKIP_SUFFIXES)
                       and not (top and d in SKIP_AT_HOME)]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield p


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    if is_leashscan_report(path, text):
        return None
    return text


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        pass
    home = str(Path.home())
    s = str(path)
    return "~" + s[len(home):] if s.startswith(home) else s


class IgnoreChecker:
    """Answers "is this path gitignored?" using git when possible."""

    def __init__(self, root: Path):
        self.root = root
        self.use_git = (root / ".git").exists() and _has_git()
        self.patterns: list[str] = []
        gi = root / ".gitignore"
        if gi.is_file():
            for raw in gi.read_text(errors="ignore").splitlines():
                line = raw.strip()
                if line and not line.startswith("#") and not line.startswith("!"):
                    self.patterns.append(line.rstrip("/"))

    def ignored(self, path: Path) -> bool:
        if self.use_git:
            try:
                r = subprocess.run(
                    ["git", "-C", str(self.root), "check-ignore", "-q", str(path)],
                    capture_output=True, timeout=5,
                )
                return r.returncode == 0
            except (OSError, subprocess.SubprocessError):
                pass
        rel = str(path.relative_to(self.root)).replace(os.sep, "/")
        name = path.name
        for pat in self.patterns:
            p = pat.lstrip("/")
            if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*"):
                return True
            if any(fnmatch.fnmatch(part, p) for part in rel.split("/")[:-1]):
                return True
        return False


def _has_git() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False

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
MAX_FILES = 25_000


def iter_files(root: Path, max_size: int = 1_000_000) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
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
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


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

"""Command-line entry point."""

from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

from . import __version__, injection, mcp, permissions, report, secrets
from .findings import SEVERITY_RANK, Finding, dedupe

EPILOG = """examples:
  leashscan                      scan the current project
  leashscan --home               also check ~/.ssh, ~/.aws, global MCP + agent configs
  leashscan repo1 repo2 repo3    one combined report for many repos
  leashscan --format html -o report.html    client-ready report
  leashscan --format sarif -o leashscan.sarif   for GitHub code scanning
  leashscan --fail-on high       exit 1 in CI if anything high or worse is found
"""


def apply_ignores(root: Path, findings: list[Finding]) -> list[Finding]:
    """Honor `.leashscanignore` globs (path or path:RULE_ID) and inline `leashscan:ignore` comments."""
    rules: list[tuple[str, str | None]] = []
    ig = root / ".leashscanignore"
    if ig.is_file():
        for raw in ig.read_text(errors="ignore").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                pat, _, rule = line.partition(":")
                rules.append((pat.strip(), rule.strip() or None))
    cache: dict[str, list[str]] = {}
    kept = []
    for f in findings:
        p = f.path.replace("\\", "/")
        if any((fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(p, pat.rstrip("/") + "/*"))
               and (rule is None or rule == f.rule_id) for pat, rule in rules):
            continue
        if f.line and not p.startswith("~"):
            if p not in cache:
                try:
                    cache[p] = (root / p).read_text(errors="ignore").splitlines()
                except OSError:
                    cache[p] = []
            lines = cache[p]
            near = lines[max(0, f.line - 2):f.line]
            if any("leashscan:ignore" in ln for ln in near):
                continue
        kept.append(f)
    return kept


def scan_paths(paths: list[Path], include_home: bool, max_size: int, only: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    multi = len(paths) > 1
    for root in paths:
        root = root.resolve()
        part: list[Finding] = []
        if not only or "secrets" in only:
            part += secrets.scan_repo(root, max_size)
        if not only or "mcp" in only:
            part += mcp.scan(root, include_home=False)
        if not only or "permissions" in only:
            part += permissions.scan(root, include_home=False)
        if not only or "injection" in only:
            part += injection.scan(root, max_size)
        part = apply_ignores(root, part)
        if multi:
            for f in part:
                f.path = f"{root.name}/{f.path}"
        findings += part
    if include_home:
        home = Path.home()
        if not only or "home" in only:
            findings += secrets.scan_home(home)
        if not only or "mcp" in only:
            findings += mcp.scan(Path("/nonexistent-leashscan"), include_home=True, home=home)
        if not only or "permissions" in only:
            findings += permissions.scan(Path("/nonexistent-leashscan"), include_home=True, home=home)
    return dedupe(findings)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="leashscan",
        description="See what your AI coding agents and MCP servers can reach: secrets, risky configs, "
                    "over-broad permissions and hidden prompt injection. Offline, read-only, zero dependencies.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("paths", nargs="*", default=["."], help="folders to scan (default: current folder)")
    ap.add_argument("--home", action="store_true", help="also scan your home folder credentials and global agent configs")
    ap.add_argument("-f", "--format", choices=["text", "json", "sarif", "markdown", "html"], default="text")
    ap.add_argument("-o", "--output", help="write report to a file instead of stdout")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none",
                    help="exit with code 1 if a finding at or above this severity exists")
    ap.add_argument("--only", help="comma list: secrets,home,mcp,permissions,injection")
    ap.add_argument("--min-severity", choices=["critical", "high", "medium", "low"], default="low",
                    help="hide findings below this severity")
    ap.add_argument("--max-file-size", type=int, default=1_000_000, help="skip files bigger than this (bytes)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true", help="show every finding")
    ap.add_argument("--badge", action="store_true", help="print a README badge for your grade")
    ap.add_argument("--version", action="version", version=f"leashscan {__version__}")
    args = ap.parse_args(argv)

    paths = [Path(p) for p in args.paths]
    for p in paths:
        if not p.is_dir():
            print(f"leashscan: not a folder: {p}", file=sys.stderr)
            return 2
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    findings = scan_paths(paths, args.home, args.max_file_size, only)
    cutoff = SEVERITY_RANK[args.min_severity]
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= cutoff]

    targets = [str(p.resolve().name or p.resolve()) for p in paths] + (["~ (home)"] if args.home else [])
    if args.format == "json":
        out = report.json_report(findings, targets)
    elif args.format == "sarif":
        out = report.sarif_report(findings, targets)
    elif args.format == "markdown":
        out = report.markdown_report(findings, targets)
    elif args.format == "html":
        out = report.html_report(findings, targets)
    else:
        color = report.use_color(args.no_color) and not args.output
        out = report.text_report(findings, targets, color, args.verbose)

    from .walker import LIMIT_HIT, MAX_FILES
    for r in LIMIT_HIT:
        print(f"leashscan: warning: stopped after {MAX_FILES:,} files in {r}; results are incomplete. "
              "Scan specific project folders instead.", file=sys.stderr)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _, grade = report.score(findings)
        print(f"leashscan: grade {grade}, {len(findings)} finding(s), report written to {args.output}", file=sys.stderr)
    else:
        try:
            sys.stdout.write(out)
        except UnicodeEncodeError:
            sys.stdout.write(out.encode("ascii", "replace").decode())
    if args.badge:
        _, grade = report.score(findings)
        print(f"\n[![leashscan {grade}]({report.badge_url(findings)})]({report.REPO_URL})", file=sys.stderr)

    if args.fail_on != "none":
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] <= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

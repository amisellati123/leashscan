"""Output formats: terminal report card, JSON, SARIF, Markdown, HTML."""

from __future__ import annotations

import html
import re
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__, REPO_URL
from .findings import SEVERITIES, Finding, counts, score

CATEGORY_NAMES = {
    "secrets": "Secrets in the workspace",
    "home": "Credentials in your home folder",
    "mcp": "MCP servers",
    "permissions": "Agent permissions",
    "injection": "Prompt injection & hidden text",
}
SEV_COLOR = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
GRADE_COLOR = {"A": "\033[1;32m", "B": "\033[1;32m", "C": "\033[1;33m", "D": "\033[1;31m", "F": "\033[1;97;41m"}
BADGE_COLOR = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def use_color(force_off: bool) -> bool:
    if force_off or os.environ.get("NO_COLOR"):
        return False
    return bool(os.environ.get("FORCE_COLOR")) or sys.stdout.isatty()


def _c(s: str, code: str, on: bool) -> str:
    return f"{code}{s}{RESET}" if on else s


def text_report(findings: list[Finding], targets: list[str], color: bool, verbose: bool = False) -> str:
    val, grade = score(findings)
    cnt = counts(findings)
    lines = []
    lines.append("")
    lines.append(_c("  leashscan", BOLD, color) + _c(f"  v{__version__}  ·  is your AI agent on a leash?", DIM, color))
    lines.append(_c("  scanned: " + ", ".join(targets), DIM, color))
    lines.append("")
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    for cat in CATEGORY_NAMES:
        items = by_cat.get(cat, [])
        if not items:
            continue
        lines.append(_c(f"  {CATEGORY_NAMES[cat]} ({len(items)})", BOLD, color))
        shown = items if verbose else items[:12]
        for f in shown:
            sev = _c(f" {f.severity.upper():<8} ", SEV_COLOR[f.severity], color)
            loc = f.path + (f":{f.line}" if f.line else "")
            lines.append(f"  {sev} {f.title}")
            lines.append(_c(f"             {loc}", DIM, color))
            if f.detail:
                lines.append(f"             {f.detail}")
            if f.fix:
                lines.append(_c(f"             fix: {f.fix}", "\033[32m", color))
        if len(items) > len(shown):
            lines.append(_c(f"             … {len(items) - len(shown)} more (use --verbose)", DIM, color))
        lines.append("")
    if not findings:
        lines.append(_c("  Nothing found. Your agent is on a short leash. 🐕", "\033[32m", color))
        lines.append("")
    bar = "─" * 46
    lines.append(f"  ┌{bar}┐")
    gtxt = _c(f" {grade} ", GRADE_COLOR[grade], color)
    plain = f"  AGENT EXPOSURE GRADE:  {grade}    score {val:>3}/100"
    lines.append(f"  │  AGENT EXPOSURE GRADE: {gtxt}   score {val:>3}/100{' ' * (46 - len(plain))}│")
    summary = "  ".join(f"{cnt[s]} {s}" for s in SEVERITIES)
    lines.append(f"  │  {summary:<44}│")
    lines.append(f"  └{bar}┘")
    lines.append(_c(f"  share: {share_line(findings)}", DIM, color))
    lines.append("")
    return "\n".join(lines)


def share_line(findings: list[Finding]) -> str:
    _, grade = score(findings)
    c = counts(findings)
    article = "an" if grade in "AF" else "a"
    return (f"My AI agent setup got {article} {grade} on leashscan "
            f"({c['critical']} critical, {c['high']} high). Is yours on a leash? {REPO_URL}")


def badge_url(findings: list[Finding]) -> str:
    _, grade = score(findings)
    return f"https://img.shields.io/badge/leashscan-{grade}-{BADGE_COLOR[grade]}"


def json_report(findings: list[Finding], targets: list[str]) -> str:
    val, grade = score(findings)
    return json.dumps({
        "tool": "leashscan", "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "targets": targets, "score": val, "grade": grade, "counts": counts(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def sarif_report(findings: list[Finding], targets: list[str]) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    sec = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id, "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "help": {"text": f.fix or f.title},
            "properties": {"security-severity": sec[f.severity], "tags": ["security", f.category]},
        })
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.path.replace("\\", "/").removeprefix("./")}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule_id, "level": level[f.severity],
            "message": {"text": f"{f.title}. {f.detail} Fix: {f.fix}".strip()},
            "locations": [loc],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "leashscan", "version": __version__,
                                      "informationUri": REPO_URL, "rules": list(rules.values())}},
                  "results": results}],
    }, indent=2)


def markdown_report(findings: list[Finding], targets: list[str]) -> str:
    val, grade = score(findings)
    c = counts(findings)
    out = [f"## 🐕 leashscan: grade **{grade}** ({val}/100)", "",
           f"![leashscan]({badge_url(findings)})", "",
           "| Critical | High | Medium | Low |", "|---|---|---|---|",
           f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} |", ""]
    if findings:
        out += ["| Severity | Finding | Location | Fix |", "|---|---|---|---|"]
        for f in findings[:100]:
            loc = f"`{f.path}{':' + str(f.line) if f.line else ''}`"
            title = f.title + (f"<br><sub>{f.detail}</sub>" if f.detail else "")
            out.append(f"| {f.severity} | {title.replace('|', '/')} | {loc} | {f.fix.replace('|', '/')} |")
    else:
        out.append("No findings. Your agent is on a short leash.")
    return "\n".join(out) + "\n"


def html_report(findings: list[Finding], targets: list[str]) -> str:
    val, grade = score(findings)
    c = counts(findings)
    def esc(t: str) -> str:
        return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(t))
    now = datetime.now().strftime("%B %d, %Y %H:%M")
    rows = []
    for cat, name in CATEGORY_NAMES.items():
        items = [f for f in findings if f.category == cat]
        if not items:
            continue
        rows.append(f"<h2>{esc(name)} <span class='n'>{len(items)}</span></h2>")
        for f in items:
            loc = esc(f.path + (f":{f.line}" if f.line else ""))
            rows.append(
                f"<div class='f {f.severity}'><div class='top'><span class='sev'>{f.severity}</span>"
                f"<b>{esc(f.title)}</b><code>{loc}</code></div>"
                + (f"<p>{esc(f.detail)}</p>" if f.detail else "")
                + (f"<p class='fix'>Fix: {esc(f.fix)}</p>" if f.fix else "") + "</div>")
    body = "\n".join(rows) or "<p class='ok'>No findings. The agent is on a short leash.</p>"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Agent Exposure Report · leashscan</title>
<style>
:root{{--bg:#fafaf7;--fg:#1d1d1b;--mut:#6b6b66;--line:#e4e3dc;--crit:#b3261e;--high:#d9480f;--med:#b08800;--low:#1c7ed6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151514;--fg:#ececea;--mut:#9a9a94;--line:#2c2c2a}}}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:900px;margin:0 auto;padding:48px 24px}}h1{{font-size:28px;margin:0 0 4px}}.mut{{color:var(--mut)}}
.card{{display:flex;gap:28px;align-items:center;border:1px solid var(--line);border-radius:14px;padding:24px;margin:28px 0}}
.grade{{font-size:64px;font-weight:800;width:110px;height:110px;border-radius:16px;display:grid;place-items:center;color:#fff;background:var(--g)}}
.counts{{display:flex;gap:22px;flex-wrap:wrap}}.counts div b{{display:block;font-size:24px}}
h2{{font-size:18px;margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}}.n{{color:var(--mut);font-weight:400}}
.f{{border-left:4px solid var(--c);padding:10px 14px;margin:10px 0;background:color-mix(in srgb,var(--c) 6%,transparent);border-radius:0 8px 8px 0}}
.f p{{margin:4px 0}}.top{{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline}}code{{color:var(--mut);font-size:13px}}
.sev{{text-transform:uppercase;font-size:11px;font-weight:700;letter-spacing:.05em;color:var(--c)}}
.critical{{--c:var(--crit)}}.high{{--c:var(--high)}}.medium{{--c:var(--med)}}.low{{--c:var(--low)}}.fix{{color:#2b8a3e}}
footer{{margin-top:48px;color:var(--mut);font-size:13px}}@media print{{.f{{break-inside:avoid}}}}
</style></head><body><main>
<h1>AI Agent Exposure Report</h1>
<div class="mut">{esc(now)} · Scope: {esc(', '.join(targets))}</div>
<div class="card" style="--g:{ {'A':'#2b8a3e','B':'#5c940d','C':'#e67700','D':'#d9480f','F':'#b3261e'}[grade] }">
<div class="grade">{grade}</div><div><div style="font-size:18px;margin-bottom:10px">Score <b>{val}</b>/100</div>
<div class="counts"><div><b style="color:var(--crit)">{c['critical']}</b>critical</div><div><b style="color:var(--high)">{c['high']}</b>high</div>
<div><b style="color:var(--med)">{c['medium']}</b>medium</div><div><b style="color:var(--low)">{c['low']}</b>low</div></div></div></div>
<p class="mut">What AI coding agents (Claude Code, Cursor, Codex, Copilot, Windsurf, Gemini CLI) and their MCP servers could read, run or leak in this environment.
The scan ran locally and read-only. Secret values are redacted.</p>
{body}
<footer>Generated by leashscan v{__version__} · {esc(REPO_URL)}</footer>
</main></body></html>
"""

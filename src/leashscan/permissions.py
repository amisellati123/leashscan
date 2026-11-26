"""Check how much freedom AI coding agents have been given (auto-approve, YOLO modes, hooks)."""

from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    from . import minitoml as tomllib  # type: ignore

from .findings import Finding
from .walker import display, read_text


def _json(path: Path) -> dict:
    text = read_text(path)
    if not text:
        return {}
    for candidate in (text, re.sub(r"(?m)^\s*//.*$", "", text)):
        try:
            data = json.loads(candidate)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            continue
    return {}


def _claude(path: Path, where: str, is_project: bool) -> list[Finding]:
    data = _json(path)
    out: list[Finding] = []
    perms = data.get("permissions") or {}
    if not isinstance(perms, dict):
        perms = {}
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode == "bypassPermissions" or data.get("dangerouslySkipPermissions"):
        out.append(Finding(
            "PERM001", "critical", "permissions", "Claude Code runs with all permission checks off", where,
            detail="Every file edit, command and network call is auto-approved.",
            fix="Remove `bypassPermissions`. Use `acceptEdits` plus a short allow list, or run inside a sandbox/devcontainer.",
        ))
    allow = [str(a) for a in perms.get("allow") or []]
    for rule in allow:
        r = rule.replace(" ", "")
        if r in ("Bash", "Bash(*)", "Bash(:*)", "Bash(**)"):
            out.append(Finding("PERM002", "high", "permissions", "Any shell command is auto-approved", where,
                               detail=f"allow: {rule}",
                               fix="Allow specific commands only, e.g. `Bash(npm test:*)`, `Bash(git status)`."))
        elif re.match(r"Bash\((curl|wget|nc|ssh|scp|rsync|python3?|node|sh|bash|eval|sudo|rm)(:\*|\s\*|\*)", r):
            out.append(Finding("PERM003", "medium", "permissions", f"Risky command auto-approved: {rule}", where,
                               detail="This command can send data out or run arbitrary code.",
                               fix="Keep it on ask, or narrow it to exact arguments."))
        elif re.match(r"(Read|Edit|Write)\((//|~/|/)\*\*\)$", r) or r in ("Read", "Edit", "Write"):
            out.append(Finding("PERM004", "medium", "permissions", f"Agent can touch files outside the project: {rule}",
                               where, fix="Scope to the project, e.g. `Edit(./src/**)`."))
        elif r.startswith("mcp__") and r.count("__") == 1:
            out.append(Finding("PERM005", "low", "permissions", f"All tools of an MCP server auto-approved: {rule}",
                               where, fix="Approve individual tools instead of the whole server."))
    deny = " ".join(str(d) for d in perms.get("deny") or [])
    if allow and ".env" not in deny and "secrets" not in deny:
        out.append(Finding("PERM006", "low", "permissions", "No deny rule for secrets", where,
                           fix="Add `\"deny\": [\"Read(./.env*)\", \"Read(./secrets/**)\", \"Read(~/.ssh/**)\"]`."))
    hooks = data.get("hooks")
    if is_project and isinstance(hooks, dict) and hooks:
        cmds = []
        for groups in hooks.values():
            for g in groups if isinstance(groups, list) else []:
                for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                    if isinstance(h, dict) and h.get("command"):
                        cmds.append(str(h["command"]))
        if cmds:
            sev = "high" if any(re.search(r"curl|wget|\|\s*(ba)?sh|base64|nc\s|/dev/tcp", c) for c in cmds) else "low"
            out.append(Finding(
                "PERM007", sev, "permissions", f"Repo defines {len(cmds)} hook command(s) that run automatically", where,
                detail="First: " + cmds[0][:140],
                fix="Read every hook before trusting this repo. Hooks run without asking.",
            ))
    if data.get("enableAllProjectMcpServers") is True:
        out.append(Finding("PERM008", "medium", "permissions", "All MCP servers from any repo are auto-enabled", where,
                           detail="A cloned repo's .mcp.json can launch programs without asking.",
                           fix="Remove `enableAllProjectMcpServers` and approve servers one by one."))
    return out


def _codex(path: Path, where: str) -> list[Finding]:
    try:
        data = tomllib.loads(read_text(path) or "")
    except Exception:
        return []
    out = []
    sandbox = data.get("sandbox_mode")
    approval = data.get("approval_policy")
    if sandbox == "danger-full-access" and approval == "never":
        out.append(Finding("PERM010", "critical", "permissions", "Codex runs with no sandbox and no approvals", where,
                           fix="Use `sandbox_mode = \"workspace-write\"` and `approval_policy = \"on-request\"`."))
    elif sandbox == "danger-full-access":
        out.append(Finding("PERM011", "high", "permissions", "Codex sandbox disabled", where,
                           fix="Use `sandbox_mode = \"workspace-write\"`."))
    return out


def _vscode(path: Path, where: str) -> list[Finding]:
    data = _json(path)
    out = []
    for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
        if data.get(key) is True:
            out.append(Finding("PERM020", "high", "permissions", "VS Code agent tools auto-approved (YOLO mode)", where,
                               detail=f"{key}: true", fix=f"Set `{key}` to false."))
    term = data.get("chat.tools.terminal.autoApprove") or data.get("github.copilot.chat.agent.terminal.allowList")
    if isinstance(term, dict) and any(v is True and str(k).strip("/") in ("", ".*", "*") for k, v in term.items()):
        out.append(Finding("PERM021", "high", "permissions", "VS Code auto-approves every terminal command", where,
                           fix="Remove the catch-all rule."))
    return out


def _gemini(path: Path, where: str) -> list[Finding]:
    data = _json(path)
    if data.get("autoAccept") is True or data.get("yolo") is True or (data.get("tools") or {}).get("autoAccept") is True:
        return [Finding("PERM030", "high", "permissions", "Gemini CLI auto-accepts tool calls", where,
                        fix="Set autoAccept to false.")]
    return []


def scan(root: Path, include_home: bool, home: Path | None = None) -> list[Finding]:
    home = home or Path.home()
    out: list[Finding] = []
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        p = root / rel
        if p.is_file():
            out += _claude(p, display(p, root), is_project=True)
    for rel, fn in ((".codex/config.toml", _codex), (".vscode/settings.json", _vscode), (".gemini/settings.json", _gemini)):
        p = root / rel
        if p.is_file():
            out += fn(p, display(p, root))
    if include_home:
        for rel in (".claude/settings.json", ".claude.json"):
            p = home / rel
            if p.is_file():
                out += _claude(p, "~/" + rel, is_project=False)
        p = home / ".codex/config.toml"
        if p.is_file():
            out += _codex(p, "~/.codex/config.toml")
        p = home / ".gemini/settings.json"
        if p.is_file():
            out += _gemini(p, "~/.gemini/settings.json")
        for rel in (".config/Code/User/settings.json", "Library/Application Support/Code/User/settings.json",
                    "AppData/Roaming/Code/User/settings.json", ".config/Cursor/User/settings.json",
                    "Library/Application Support/Cursor/User/settings.json"):
            p = home / rel
            if p.is_file():
                out += _vscode(p, "~/" + rel)
    return out

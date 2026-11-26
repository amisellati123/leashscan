"""Audit MCP server configs used by Claude, Cursor, VS Code, Windsurf, Codex and Gemini."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None  # type: ignore

from .findings import Finding
from .patterns import SECRET_NAME, is_env_reference, looks_like_placeholder, match_known_secret, redact
from .walker import display, read_text

PROJECT_CONFIGS = [
    ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json",
    ".codex/config.toml", ".windsurf/mcp.json", ".roo/mcp.json", "mcp.json",
]


def home_configs(home: Path) -> list[Path]:
    paths = [
        ".claude.json", ".cursor/mcp.json", ".codeium/windsurf/mcp_config.json", ".codex/config.toml",
        ".gemini/settings.json", ".config/Claude/claude_desktop_config.json",
        "Library/Application Support/Claude/claude_desktop_config.json",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        ".config/Code/User/mcp.json", "Library/Application Support/Code/User/mcp.json",
        "AppData/Roaming/Code/User/mcp.json",
    ]
    return [home / p for p in paths]


SHELL_HINTS = re.compile(r"(?i)(shell|terminal|exec|desktop-?commander|server-commands|run-?command|bash|powershell|cmd-?mcp)")
FS_HINTS = re.compile(r"(?i)(server-filesystem|filesystem|fs-mcp|file-?system)")
RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "dlx"}


def load_servers(path: Path) -> dict[str, dict]:
    text = read_text(path)
    if not text:
        return {}
    data: object
    if path.suffix == ".toml":
        if tomllib is None:
            return {}
        try:
            data = tomllib.loads(text)
        except Exception:
            return {}
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # tolerate JSONC comments
            stripped = re.sub(r"(?m)^\s*//.*$", "", text)
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                return {}
    if not isinstance(data, dict):
        return {}
    servers: dict[str, dict] = {}
    for key in ("mcpServers", "servers", "mcp_servers", "context_servers"):
        block = data.get(key)
        if isinstance(block, dict):
            servers.update({k: v for k, v in block.items() if isinstance(v, dict)})
    projects = data.get("projects")  # ~/.claude.json
    if isinstance(projects, dict):
        for proj, cfg in projects.items():
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                for k, v in cfg["mcpServers"].items():
                    if isinstance(v, dict):
                        servers[f"{k} ({Path(proj).name})"] = v
    return servers


def _package_from_args(command: str, args: list[str]) -> str | None:
    cmd = Path(command).name.lower().removesuffix(".cmd").removesuffix(".exe")
    rest = list(args)
    if cmd in {"pnpm", "yarn", "bun"} and rest[:1] == ["dlx"]:
        rest = rest[1:]
        cmd = "dlx"
    if cmd == "pipx" and rest[:1] == ["run"]:
        rest = rest[1:]
    if cmd not in RUNNERS:
        return None
    for a in rest:
        if a.startswith("-"):
            continue
        return a
    return None


def _unpinned(pkg: str, runner_is_py: bool) -> bool:
    if runner_is_py:
        return not re.search(r"(==|@)\d", pkg)
    name = pkg[1:] if pkg.startswith("@") else pkg
    if "@" not in name:
        return True
    version = name.split("@", 1)[1]
    return version in ("latest", "next", "") or not re.match(r"^\d", version)


def audit_server(name: str, cfg: dict, where: str, home: Path) -> list[Finding]:
    out: list[Finding] = []
    command = str(cfg.get("command", "") or "")
    args = [str(a) for a in (cfg.get("args") or []) if isinstance(a, (str, int, float))]
    joined = " ".join([command, *args])
    label = f"MCP server `{name}`"

    # 1. Plaintext secrets in env / headers / args / url
    blobs: list[tuple[str, str]] = []
    for field in ("env", "headers", "http_headers", "env_http_headers"):
        block = cfg.get(field)
        if isinstance(block, dict):
            blobs += [(str(k), str(v)) for k, v in block.items()]
    blobs += [("arg", a) for a in args]
    if cfg.get("url"):
        blobs.append(("url", str(cfg["url"])))
    for k, v in blobs:
        if is_env_reference(v):
            continue
        known = match_known_secret(v)
        named = k != "arg" and k != "url" and SECRET_NAME.search(k) and len(v) >= 8 and not looks_like_placeholder(v)
        bearer = v.lower().startswith("bearer ") and len(v) > 20
        token_in_url = k == "url" and re.search(r"(?i)[?&](key|token|api_key|apikey|access_token)=[^&]{8,}", v)
        if known or named or bearer or token_in_url:
            what = known[1] if known else (k if k not in ("arg", "url") else "token")
            out.append(Finding(
                "MCP001", "high", "mcp", f"{label} has a plain-text secret", where,
                detail=f"{what}: {redact(v.split()[-1])}",
                fix="Reference an env var instead (e.g. `\"${API_KEY}\"`, VS Code `${input:...}`) and rotate the key.",
            ))

    # 2. Unpinned packages pulled at launch
    pkg = _package_from_args(command, args)
    if pkg:
        is_py = Path(command).name.startswith(("uvx", "pipx"))
        if _unpinned(pkg, is_py):
            out.append(Finding(
                "MCP002", "medium", "mcp", f"{label} runs an unpinned package", where,
                detail=f"`{pkg}` is fetched fresh on every launch. If that package is hijacked, the new code runs as you.",
                fix=f"Pin an exact version, e.g. `{pkg.split('@latest')[0]}@1.2.3`.",
            ))
    if re.search(r"curl[^|]*\|\s*(sudo\s+)?(ba|z)?sh|wget[^|]*\|\s*(ba)?sh|iwr[^|]*\|\s*iex", joined):
        out.append(Finding("MCP007", "high", "mcp", f"{label} pipes a download into a shell", where,
                           detail=joined[:160], fix="Install a pinned, checksummed release instead."))

    # 3. Broad filesystem access
    if FS_HINTS.search(joined) or (command and Path(command).name in ("node", "npx") and "filesystem" in joined):
        broad = []
        for a in args:
            a2 = a.rstrip("/\\")
            if a2 in ("", "~", "$HOME", "${HOME}", "C:", "/Users", "/home", "/root") or a == "/" \
                    or a2 == str(home).rstrip("/") or re.fullmatch(r"[A-Za-z]:", a2):
                broad.append(a or "/")
        if broad:
            out.append(Finding(
                "MCP003", "high", "mcp", f"{label} can read/write your whole disk or home", where,
                detail=f"Root(s): {', '.join(broad)}. That includes ~/.ssh, ~/.aws and browser profiles.",
                fix="Limit it to the project folders it actually needs.",
            ))

    # 4. Insecure remote transport
    url = str(cfg.get("url") or cfg.get("serverUrl") or "")
    if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)", url):
        out.append(Finding("MCP004", "high", "mcp", f"{label} uses unencrypted HTTP", where,
                           detail=url.split("?")[0], fix="Use https://."))

    # 5. Arbitrary command execution
    if SHELL_HINTS.search(" ".join(args) + " " + name) and not FS_HINTS.search(joined):
        out.append(Finding(
            "MCP005", "medium", "mcp", f"{label} can run shell commands", where,
            detail="One prompt injection in a web page, issue or file can become a command on your machine.",
            fix="Keep manual approval on for this server's tools, or run it in a container.",
        ))

    # 6. Dangerous docker flags
    if Path(command).name == "docker" or "docker run" in joined:
        bad = [f for f in ("--privileged", "/var/run/docker.sock", "--net=host", "--network=host", "--pid=host")
               if f in joined]
        if re.search(r"-v\s+/:/|--volume[= ]/:/|-v\s+~[:/]|-v\s+\$HOME", joined):
            bad.append("host root/home mounted")
        if bad:
            out.append(Finding("MCP006", "high", "mcp", f"{label} container escapes its sandbox", where,
                               detail=", ".join(bad), fix="Drop these flags and mount only the folders needed."))
    return out


def scan(root: Path, include_home: bool, home: Path | None = None) -> list[Finding]:
    home = home or Path.home()
    findings: list[Finding] = []
    targets: list[tuple[Path, bool]] = [(root / p, False) for p in PROJECT_CONFIGS]
    if include_home:
        targets += [(p, True) for p in home_configs(home)]
    for path, is_home in targets:
        if not path.is_file():
            continue
        servers = load_servers(path)
        where = ("~/" + str(path.relative_to(home))) if is_home else display(path, root)
        for name, cfg in servers.items():
            findings += audit_server(name, cfg, where, home)
        if servers and not is_home:
            findings.append(Finding(
                "MCP010", "low", "mcp", f"Repo ships {len(servers)} MCP server(s)", where,
                detail="Anyone who clones this and trusts the folder will launch: " + ", ".join(sorted(servers)[:6]),
                fix="Review these before approving them in your editor.",
            ))
    return findings


if __name__ == "__main__":  # pragma: no cover
    for f in scan(Path(sys.argv[1] if len(sys.argv) > 1 else "."), True):
        print(f)

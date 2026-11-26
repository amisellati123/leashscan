"""Find secrets and sensitive files that an AI agent working in this folder can read."""

from __future__ import annotations

import base64
import fnmatch
import re
from pathlib import Path

from .findings import Finding
from .patterns import (
    GENERIC_ASSIGN, SECRET_PATTERNS, looks_like_placeholder, redact,
)
from .walker import IgnoreChecker, display, iter_files, line_of, read_text

ENV_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")

SENSITIVE_FILES = [
    ("id_rsa", "SSH private key"), ("id_ed25519", "SSH private key"), ("id_ecdsa", "SSH private key"),
    ("id_dsa", "SSH private key"), ("*.pem", "PEM key/certificate"), ("*.key", "Private key file"),
    ("*.p12", "PKCS#12 keystore"), ("*.pfx", "PKCS#12 keystore"), ("*.keystore", "Java keystore"),
    ("credentials.json", "Cloud credentials"), ("service-account*.json", "GCP service account"),
    ("*-sa.json", "GCP service account"), (".npmrc", "npm config"), (".pypirc", "PyPI config"),
    (".netrc", "netrc credentials"), ("kubeconfig", "Kubernetes config"), ("*.tfstate", "Terraform state"),
    (".htpasswd", "htpasswd file"),
]

DOC_EXT = {".md", ".mdx", ".rst", ".txt"}
MCP_CONFIGS = {".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".windsurf/mcp.json", ".roo/mcp.json", "mcp.json"}


def is_env_file(name: str) -> bool:
    return (name == ".env" or name.startswith(".env.") or name.endswith(".env")) and not name.endswith(ENV_SAFE_SUFFIXES)


def scan_repo(root: Path, max_size: int) -> list[Finding]:
    findings: list[Finding] = []
    ignore = IgnoreChecker(root)
    for path in iter_files(root, max_size):
        name = path.name
        rel = display(path, root)

        if is_env_file(name):
            text = read_text(path) or ""
            has_values = bool(re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S", text))
            if has_values and not ignore.ignored(path):
                findings.append(Finding(
                    "FILE001", "high", "secrets", "Env file is not gitignored", rel,
                    detail="This file holds real values and could be committed and pushed.",
                    fix=f"Add `{name}` to .gitignore and rotate anything that was ever committed.",
                ))
            elif has_values:
                findings.append(Finding(
                    "FILE002", "low", "secrets", "Env file readable by agents", rel,
                    detail="Gitignored, but any AI agent in this folder can read it and send it to a model.",
                    fix="Add it to your agent's deny list (e.g. Claude Code `permissions.deny: [\"Read(./.env*)\"]`).",
                ))

        for pattern, label in SENSITIVE_FILES:
            if fnmatch.fnmatch(name, pattern):
                text = read_text(path)
                if pattern in (".npmrc", ".pypirc") and (not text or not re.search(r"_authToken|password", text)):
                    break
                if pattern.endswith(".pem") and text and "PRIVATE KEY" not in text:
                    break
                sev = "low" if ignore.ignored(path) else "high"
                findings.append(Finding(
                    "FILE003", sev, "secrets", f"{label} inside the agent's workspace", rel,
                    detail="Gitignored, but still readable by agents." if sev == "low" else "Not gitignored, can be committed.",
                    fix="Move it out of the project folder or add it to .gitignore and your agent's deny list.",
                ))
                break

        text = read_text(path)
        if not text:
            continue
        if rel.replace("\\", "/") in MCP_CONFIGS:
            continue  # the MCP scanner reports secrets in these with better context
        for rule_id, label, sev, rx in SECRET_PATTERNS:
            for m in rx.finditer(text):
                if looks_like_placeholder(m.group(0)) and rule_id != "SEC001":
                    continue
                findings.append(Finding(
                    rule_id, sev if not ignore.ignored(path) else "medium", "secrets",
                    f"{label} found", rel, line_of(text, m.start()),
                    detail=f"Value: {redact(m.group(0))}",
                    fix="Revoke and rotate this credential, then load it from an env var or secret manager.",
                ))
        if is_env_file(name) or path.suffix in DOC_EXT:
            continue  # env files covered above; docs too noisy for generic rule
        for m in GENERIC_ASSIGN.finditer(text):
            value = m.group(2)
            if looks_like_placeholder(value) or any(rx.search(value) for _, _, _, rx in SECRET_PATTERNS):
                continue
            if path.suffix in {".py", ".js", ".ts", ".go", ".rb", ".java"} and not re.match(r"^[A-Za-z0-9_\-+/=.]+$", value):
                continue
            findings.append(Finding(
                "SEC100", "medium", "secrets", f"Hardcoded secret in `{m.group(1)}`", rel,
                line_of(text, m.start()), detail=f"Value: {redact(value)}",
                fix="Move it to an env var or secret manager.",
            ))
    return findings


def _ssh_key_unencrypted(text: str) -> bool:
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        body = "".join(l for l in text.splitlines() if l and not l.startswith("-----"))
        try:
            raw = base64.b64decode(body + "==", validate=False)
        except Exception:
            return False
        # openssh-key-v1\0 + string ciphername
        if raw.startswith(b"openssh-key-v1\x00") and len(raw) > 19:
            n = int.from_bytes(raw[15:19], "big")
            return raw[19:19 + n] == b"none"
        return False
    return "PRIVATE KEY" in text and "ENCRYPTED" not in text and "Proc-Type: 4,ENCRYPTED" not in text


def scan_home(home: Path | None = None) -> list[Finding]:
    """Credentials in your home folder. Any agent running as you can read these."""
    home = home or Path.home()
    findings: list[Finding] = []

    ssh = home / ".ssh"
    if ssh.is_dir():
        for p in sorted(ssh.iterdir()):
            if p.name.startswith("id_") and not p.name.endswith(".pub") and p.is_file():
                text = read_text(p) or ""
                if _ssh_key_unencrypted(text):
                    findings.append(Finding(
                        "HOME001", "high", "home", "SSH key has no passphrase", "~/.ssh/" + p.name,
                        detail="Any agent or tool running as you can read and use it.",
                        fix=f"Add a passphrase: `ssh-keygen -p -f ~/.ssh/{p.name}` and use ssh-agent.",
                    ))

    checks = [
        (".aws/credentials", r"aws_secret_access_key", "AWS long-lived keys in plain text",
         "Use `aws sso login` or short-lived credentials instead of static keys."),
        (".config/gcloud/application_default_credentials.json", r"refresh_token|private_key",
         "Google Cloud credentials in plain text", "Revoke with `gcloud auth application-default revoke` when not needed."),
        (".kube/config", r"token:|client-key-data", "Kubernetes credentials in plain text",
         "Use exec-based auth plugins instead of embedded tokens/keys."),
        (".npmrc", r"_authToken\s*=\s*(?!\$\{)\S", "npm publish token in plain text",
         "Use `${NPM_TOKEN}` in .npmrc or a granular, short-lived token."),
        (".pypirc", r"password\s*[=:]\s*\S", "PyPI token in plain text", "Use trusted publishing or keyring."),
        (".netrc", r"password\s+\S", "Plain-text passwords in ~/.netrc", "Use a credential helper."),
        (".docker/config.json", r"\"auth\"\s*:\s*\"[^\"]+\"", "Docker registry password in plain text",
         "Configure a `credsStore` (e.g. osxkeychain, desktop, pass)."),
        (".git-credentials", r"https?://[^:\s]+:[^@\s]+@", "Git passwords/tokens in plain text",
         "Switch to `git config --global credential.helper` with an OS keychain."),
        (".config/gh/hosts.yml", r"oauth_token:\s*\S", "GitHub CLI token in plain text",
         "Run `gh auth login` again with keyring storage (default on newer gh)."),
    ]
    for rel, rx, title, fix in checks:
        p = home / rel
        if p.is_file():
            text = read_text(p) or ""
            if re.search(rx, text):
                findings.append(Finding("HOME002", "medium", "home", title, "~/" + rel,
                                        detail="Readable by every agent, MCP server and npm postinstall script you run.",
                                        fix=fix))
    for name in (".env", ".bash_history", ".zsh_history"):
        p = home / name
        if p.is_file():
            text = read_text(p) or ""
            for rule_id, label, sev, sx in SECRET_PATTERNS:
                m = sx.search(text)
                if m:
                    findings.append(Finding("HOME003", "high", "home", f"{label} in ~/{name}", "~/" + name,
                                            line_of(text, m.start()), detail=f"Value: {redact(m.group(0))}",
                                            fix="Rotate it and remove it from the file."))
    return findings

"""Secret detection patterns shared by scanners."""

from __future__ import annotations

import re

# (rule_id, name, severity, regex)
SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    ("SEC001", "Private key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("SEC002", "AWS access key", "critical", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SEC003", "GitHub token", "critical",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("SEC004", "Anthropic API key", "critical", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("SEC005", "OpenAI API key", "critical", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}")),
    ("SEC006", "Slack token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("SEC007", "Stripe live key", "critical", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("SEC008", "Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("SEC009", "Hugging Face token", "high", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("SEC010", "npm token", "high", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
]

GENERIC_ASSIGN = re.compile(
    r"(?im)^\s*(?:export\s+)?[\"']?([A-Z0-9_]*(?:SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|PRIVATE_KEY)[A-Z0-9_]*)[\"']?"
    r"\s*[:=]\s*[\"']?([^\s\"'#,}]{12,})"
)

PLACEHOLDER = re.compile(
    r"(?i)(your|xxx|changeme|change_me|example|placeholder|dummy|redacted|replace|todo|<|\$\{|\$\(|"
    r"process\.env|os\.environ|getenv|\*\*\*|^\.\.\.|test_?key|fake|sample)"
)

SECRET_NAME = re.compile(r"(?i)(secret|token|api_?key|password|passwd|private_key|auth|credential)")


def redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * 8 + value[-2:]


def looks_like_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.search(value)) or len(set(value)) <= 3


def match_known_secret(value: str) -> tuple[str, str, str] | None:
    """Return (rule_id, name, severity) if value contains a known secret format."""
    for rule_id, name, sev, rx in SECRET_PATTERNS:
        if rx.search(value):
            return rule_id, name, sev
    return None


def is_env_reference(value: str) -> bool:
    v = value.strip()
    return (not v) or v.startswith("${") or v.startswith("$") or v.startswith("{{") or "${env:" in v or "${input:" in v

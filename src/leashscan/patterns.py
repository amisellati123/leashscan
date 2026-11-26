"""Secret detection patterns shared by scanners."""

from __future__ import annotations

import re

# (rule_id, name, severity, regex)
SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    ("SEC001", "Private key", "critical",
     # header followed by real key material, not code/docs that merely mention the header
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
                r"(?:\r?\n|\\n)(?:[A-Za-z0-9+/=:\- ]+(?:\r?\n|\\n)){0,3}[A-Za-z0-9+/=]{40,}")),
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

# Generic "name = value" secrets. Only used on config files, only for clearly secret field names.
GENERIC_ASSIGN = re.compile(
    r"(?im)^\s*(?:export\s+)?[\"']?([A-Za-z0-9_.\-]*?(?:secret|token|api_?key|apikey|password|passwd|pwd|"
    r"private_?key|access_?key|client_?secret|auth_?token|authtoken))[\"']?\s*[:=]\s*[\"']?([^\s\"'#,}]{8,})"
)
NOT_SECRET_NAME = re.compile(r"(?i)(tokens|_?name|_?url|_?uri|_?id|_?path|_?file|_?type|_?count|max|min|limit|"
                             r"hashed|length|endpoint|header|prefix|_?env|_?ref|_?field|policy|expire|ttl)$")
CONFIG_EXT = {".yml", ".yaml", ".ini", ".conf", ".cfg", ".properties", ".toml", ".env", ".json", ""}


def looks_random(value: str) -> bool:
    """True for values that look like generated credentials rather than words or identifiers."""
    import math
    v = value.strip()
    if len(v) < 10 or re.search(r"[./\\]{1}.*[./\\]", v) or re.fullmatch(r"[a-z_]+|[A-Z_]+|[a-z]+(?:[A-Z][a-z]+)+", v):
        return False
    if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
        return False
    freq = {c: v.count(c) for c in set(v)}
    entropy = -sum(n / len(v) * math.log2(n / len(v)) for n in freq.values())
    return entropy >= 3.0


TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata|test_data|examples?|docs_src|samples?|mocks?|__mocks__|"
    r"cookbook|tutorials?)(/|$)|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(go|py|rb)$|(^|/)test_[^/]*\.py$"
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

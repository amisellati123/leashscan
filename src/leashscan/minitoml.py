"""Tiny TOML subset parser, used only when the stdlib `tomllib` (3.11+) is missing.

Handles what agent configs use: [tables], [dotted."quoted".tables], key = "str" | 'str' | bool |
number | ["arrays", ...] (incl. multi-line) | { inline = "tables" }. Anything else is skipped.
"""

from __future__ import annotations

import json
import re

_KEY = r'(?:"[^"]*"|\'[^\']*\'|[A-Za-z0-9_\-]+)'


def _split_key(k: str) -> list[str]:
    return [p.strip().strip('"').strip("'") for p in re.findall(_KEY, k)]


def _value(src: str):
    s = src.strip()
    if s in ("true", "false"):
        return s == "true"
    if s.startswith("'") and s.endswith("'"):
        return s[1:-1]
    if s.startswith('"') or s.startswith("[") or s.startswith("{"):
        j = re.sub(r"'([^']*)'", lambda m: json.dumps(m.group(1)), s)
        j = re.sub(r"([{,]\s*)(" + _KEY + r")\s*=", lambda m: m.group(1) + json.dumps(_split_key(m.group(2))[0]) + ":", j)
        j = re.sub(r",\s*([\]}])", r"\1", j)
        return json.loads(j)
    try:
        return int(s.replace("_", ""))
    except ValueError:
        return float(s)


def _strip_comment(line: str) -> str:
    out, q = [], None
    for ch in line:
        if q:
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out).strip()


def loads(text: str) -> dict:
    root: dict = {}
    cur = root
    buf = ""
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if buf:
            buf += " " + line
            if buf.count("[") > buf.count("]") or buf.count("{") > buf.count("}"):
                continue
            line, buf = buf, ""
        if not line:
            continue
        if line.startswith("[") and not line.startswith("[["):
            cur = root
            for part in _split_key(line.strip("[]")):
                cur = cur.setdefault(part, {})
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        if val.count("[") > val.count("]") or val.count("{") > val.count("}"):
            buf = line
            continue
        parts = _split_key(key)
        target = cur
        for p in parts[:-1]:
            target = target.setdefault(p, {})
        try:
            target[parts[-1]] = _value(val)
        except (ValueError, json.JSONDecodeError):
            continue
    return root

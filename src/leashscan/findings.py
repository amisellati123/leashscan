"""Finding model and scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"critical": 30, "high": 12, "medium": 4, "low": 1}


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    path: str
    line: int | None = None
    detail: str = ""
    fix: str = ""

    def key(self) -> tuple:
        return (self.rule_id, self.path, self.line, self.detail)

    def to_dict(self) -> dict:
        return asdict(self)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        if f.key() in seen:
            continue
        seen.add(f.key())
        out.append(f)
    out.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.path, f.line or 0))
    return out


def score(findings: list[Finding]) -> tuple[int, str]:
    """Return (score 0-100, letter grade)."""
    penalty = 0
    # Diminishing returns per rule so one noisy rule can't dominate.
    per_rule: dict[str, int] = {}
    for f in findings:
        n = per_rule.get(f.rule_id, 0)
        per_rule[f.rule_id] = n + 1
        w = SEVERITY_WEIGHT[f.severity]
        penalty += w if n == 0 else max(1, w // (n + 1))
    value = max(0, 100 - penalty)
    if value >= 90:
        grade = "A"
    elif value >= 75:
        grade = "B"
    elif value >= 60:
        grade = "C"
    elif value >= 40:
        grade = "D"
    else:
        grade = "F"
    if any(f.severity == "critical" for f in findings) and grade in "ABC":
        grade = "D"
        value = min(value, 59)
    return value, grade


def counts(findings: list[Finding]) -> dict[str, int]:
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f.severity] += 1
    return c

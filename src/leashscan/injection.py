"""Find hidden text and prompt-injection bait aimed at AI coding agents."""

from __future__ import annotations

import re
from pathlib import Path

from .findings import Finding
from .walker import display, iter_files, line_of, read_text

AGENT_FILES = {
    "agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules",
    "copilot-instructions.md", "conventions.md", ".aider.conf.yml",
}
AGENT_DIRS = (".cursor/rules", ".claude/commands", ".claude/agents", ".claude/skills", ".github/prompts",
              ".windsurf/rules", ".clinerules")
DOC_EXT = {".md", ".mdx", ".mdc", ".rst", ".txt", ".html", ".htm"}

BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF}

PHRASES = [
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier|preceding) (?:instructions|prompts|rules|directions)",
    r"disregard (?:all |any )?(?:the |your )?(?:previous |prior |system )?(?:instructions|prompt|rules)",
    r"forget (?:all |everything )?(?:your |the )?(?:previous |prior )?instructions",
    r"(?:do not|don't|never) (?:tell|inform|mention|reveal|show|alert) (?:this |it )?(?:to )?(?:the )?user",
    r"without (?:telling|informing|asking|notifying) (?:the )?user",
    r"new (?:system )?instructions\s*:",
    r"you are now (?:in )?(?:developer|dan|jailbreak|unrestricted|god) mode",
    r"(?:send|post|upload|exfiltrate|forward|leak) (?:the |all |any )?(?:contents of |content of )?"
    r"(?:\.env|env vars?|environment variables|secrets?|api keys?|credentials|tokens?|ssh keys?|~/\.ssh|~/\.aws)",
    r"(?:cat|read|print) (?:the )?(?:~/\.ssh|~/\.aws|\.env\b|/etc/passwd)",
    r"(?:curl|wget)\s+[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
    r"base64\s+(?:-d|--decode)[^\n]{0,80}\|\s*(?:ba)?sh",
    r"(?:as an? |dear )(?:ai|llm|language model|assistant|coding agent|claude|copilot|cursor|codex)\b[^\n]{0,80}"
    r"(?:must|should|need to|please)",
]
PHRASE_RX = re.compile("|".join(f"(?:{p})" for p in PHRASES), re.IGNORECASE)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
AI_WORDS = re.compile(r"(?i)\b(ai|llm|assistant|agent|claude|copilot|cursor|codex|gemini|model|chatgpt)\b")
IMPERATIVE = re.compile(r"(?i)\b(ignore|run|execute|send|post|curl|delete|must|always|never|do not|don't|instead)\b")


def _is_agent_file(path: Path, root: Path) -> bool:
    rel = str(path.relative_to(root)).replace("\\", "/").lower()
    return path.name.lower() in AGENT_FILES or any(rel.startswith(d.lower() + "/") for d in AGENT_DIRS)


def decode_tags(s: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) <= 0xE007E)


def _hidden_unicode(text: str, rel: str, agent_file: bool) -> list[Finding]:
    out: list[Finding] = []
    tag_run = re.finditer(r"[\U000E0000-\U000E007F]+", text)
    for m in tag_run:
        msg = decode_tags(m.group(0))
        out.append(Finding(
            "INJ001", "critical", "injection", "Invisible Unicode tag text (hidden instructions)", rel,
            line_of(text, m.start()), detail=f"Decoded hidden text: \"{msg[:160]}\"",
            fix="Delete the invisible characters. Humans can't see this text, but AI models read it.",
        ))
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in BIDI:
            out.append(Finding("INJ002", "high", "injection", "Bidirectional control character (Trojan Source)", rel,
                               line_of(text, i), detail=f"U+{cp:04X} can make code look different from what runs.",
                               fix="Remove it unless the file genuinely contains right-to-left text."))
            break
    zw = 0
    first = None
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in ZERO_WIDTH:
            if cp == 0xFEFF and i == 0:
                continue
            if cp in (0x200D, 0xFE0F, 0x200C) and i > 0 and ord(text[i - 1]) > 0x2000:
                continue  # emoji / script joiners
            zw += 1
            first = first if first is not None else i
    if zw >= (1 if agent_file else 3):
        out.append(Finding("INJ003", "high" if agent_file else "medium", "injection",
                           f"{zw} zero-width character(s) hidden in text", rel, line_of(text, first or 0),
                           detail="Often used to smuggle or obfuscate instructions for AI agents.",
                           fix="Strip them: `leashscan` reports exact lines; most editors can show invisible chars."))
    return out


def scan(root: Path, max_size: int) -> list[Finding]:
    out: list[Finding] = []
    for path in iter_files(root, max_size):
        agent_file = _is_agent_file(path, root)
        if not agent_file and path.suffix.lower() not in DOC_EXT and path.name.lower() not in AGENT_FILES:
            # still check source files for invisible unicode
            text = read_text(path)
            if text and any(ord(c) > 0x2000 for c in text):
                out += _hidden_unicode(text, display(path, root), False)
            continue
        text = read_text(path)
        if not text:
            continue
        rel = display(path, root)
        out += _hidden_unicode(text, rel, agent_file)
        for m in PHRASE_RX.finditer(text):
            out.append(Finding(
                "INJ010", "high" if agent_file else "medium", "injection",
                "Prompt-injection phrase" + (" in an agent instructions file" if agent_file else ""), rel,
                line_of(text, m.start()), detail=f"\"{m.group(0)[:120]}\"",
                fix="If you didn't write this, remove it. Agents treat this text as instructions.",
            ))
        if path.suffix.lower() in {".md", ".mdx", ".mdc", ".html", ".htm"}:
            for m in HTML_COMMENT.finditer(text):
                body = m.group(1)
                if AI_WORDS.search(body) and IMPERATIVE.search(body) and len(body.strip()) > 20:
                    if PHRASE_RX.search(body):
                        continue  # already reported
                    out.append(Finding(
                        "INJ011", "medium", "injection", "Hidden HTML comment with instructions for AI", rel,
                        line_of(text, m.start()), detail=f"\"{' '.join(body.split())[:120]}\"",
                        fix="Rendered Markdown hides this from humans but agents read it. Review or remove.",
                    ))
    return out

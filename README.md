<div align="center">

# 🐕 leashscan

### Is your AI agent on a leash?

**See what Claude Code, Cursor, Codex, Copilot, Windsurf and your MCP servers can actually reach:**
leaked secrets, YOLO permissions, risky MCP configs and invisible prompt injection. One command. Offline. Zero dependencies.

[![CI](https://github.com/amisellati123/leashscan/actions/workflows/ci.yml/badge.svg)](https://github.com/amisellati123/leashscan/actions)
[![PyPI](https://img.shields.io/pypi/v/leashscan)](https://pypi.org/project/leashscan/)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

```bash
pipx run leashscan            # or: uvx leashscan
```

**New: use it as a skill.** Ask your AI agent *"is my setup safe?"* and it scans, explains and fixes with your OK.<br>
Claude Code: `/plugin install leashscan --marketplace amisellati123/leashscan` · [Cursor, Codex and others](#use-it-as-an-agent-skill)

<img src="docs/screenshot.png" alt="leashscan output showing an F grade" width="820">

</div>

---

## Why this exists

You gave an AI agent a terminal, your files and a dozen MCP servers. Now ask yourself:

- Can it read your `.env`, `~/.aws/credentials` or unencrypted SSH key? (Yes, probably.)
- Did someone's `AGENTS.md` or README hide **invisible Unicode instructions** your agent will happily follow?
- Is that MCP server pulling `@latest` from npm on every launch, as you?
- Did a repo you cloned ship a `.claude/settings.json` hook that runs `curl … | sh`?
- Is "auto-approve everything" switched on somewhere you forgot about?

Secret scanners don't check agent configs. Agent tools don't check your secrets. **leashscan checks both**, in seconds, without sending a single byte anywhere.

## What it checks

| Area | Examples |
|---|---|
| 🔑 **Secrets in the workspace** | OpenAI / Anthropic / AWS / GitHub / Stripe / Slack / HF keys, private keys, `.env` files not gitignored, hardcoded passwords |
| 🏠 **Home folder credentials** (`--home`) | SSH keys with no passphrase, `~/.aws/credentials`, kubeconfig tokens, npm/PyPI/Docker/gh tokens, keys in shell history |
| 🔌 **MCP servers** | plain-text tokens in configs, unpinned `npx`/`uvx` packages, filesystem servers rooted at `/` or `~`, shell-exec servers, `http://` remotes, `docker --privileged`, `curl \| sh` installs |
| 🛂 **Agent permissions** | Claude Code `bypassPermissions`, `Bash(*)`, auto-run repo hooks, `enableAllProjectMcpServers`; Codex `danger-full-access`; VS Code / Copilot auto-approve; Gemini CLI auto-accept |
| 🕵️ **Prompt injection** | invisible Unicode tag text (decoded so you can read it!), Trojan Source bidi chars, zero-width smuggling, hidden HTML comments aimed at AI, injection phrases in `AGENTS.md`, `CLAUDE.md`, `.cursorrules` and friends |

Supports configs from **Claude Code, Claude Desktop, Cursor, VS Code / Copilot, Windsurf, Codex CLI, Gemini CLI, Roo and Cline.**

Every finding comes with a **specific fix**, not just a warning.

## Usage

```bash
leashscan                          # scan the current project
leashscan --home                   # + your home folder and global agent configs
leashscan ~/code/*                 # many repos, one combined report
leashscan -f html -o report.html   # shareable report (great for security reviews)
leashscan -f sarif -o out.sarif    # GitHub code scanning
leashscan -f json                  # pipe into anything
leashscan --fail-on high           # non-zero exit for CI
leashscan --badge                  # get a README badge for your grade
```

**False positive?** Add a `leashscan:ignore` comment on or above the line, or list paths in `.leashscanignore`:

```
docs/security-talk.md            # ignore everything in this file
README.md:INJ010                 # ignore one rule in one file
```

Install it for good with `pipx install leashscan` or `pip install leashscan`.

### Try it on a deliberately leaky project

```bash
git clone https://github.com/amisellati123/leashscan && cd leashscan
python demo/make_demo.py /tmp/leaky-app
leashscan /tmp/leaky-app
```

## GitHub Action

Block risky agent configs and hidden prompt injection before they merge:

```yaml
# .github/workflows/leashscan.yml
name: leashscan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v5
      - uses: amisellati123/leashscan@v0.1.5
        with:
          fail-on: high
```

You get a summary on every run, results in the Security tab, and a failed check when something high or critical shows up.

## Use it as an agent skill

leashscan ships as an [Agent Skill](https://agentskills.io), so your AI coding agent can run the audit for you. Ask *"is my AI setup safe?"* or *"scan my setup"* and the agent will:

1. Run leashscan (offline, read-only)
2. Explain the grade and each finding in plain words, without ever showing a secret
3. Offer specific fixes and apply only the ones you approve
4. Re-scan and show the before and after grade

Hidden text found in scanned files is treated as data, never as instructions, so a poisoned `AGENTS.md` can't hijack the agent doing the audit.

**Claude Code** (plugin, updates with the repo):

```
/plugin install leashscan --marketplace amisellati123/leashscan
```

On Claude Code older than 2.1.275, use two steps: `/plugin marketplace add amisellati123/leashscan`, then `/plugin install leashscan@leashscan`. Run it with `/leashscan:leashscan`, or just ask.

**Cursor, Codex and other Agent Skills tools** (copy the skill folder):

```bash
git clone --depth 1 https://github.com/amisellati123/leashscan /tmp/leashscan
# Cursor (all projects)
mkdir -p ~/.cursor/skills && cp -r /tmp/leashscan/plugins/leashscan/skills/leashscan ~/.cursor/skills/
# Codex (this project)
mkdir -p .agents/skills && cp -r /tmp/leashscan/plugins/leashscan/skills/leashscan .agents/skills/
# Claude Code without the plugin system
mkdir -p ~/.claude/skills && cp -r /tmp/leashscan/plugins/leashscan/skills/leashscan ~/.claude/skills/
```

The skill needs Python 3.9+ so it can run the `leashscan` command (via `uvx`, `pipx` or `pip install leashscan`).

## In your IDE

Works in the integrated terminal of VS Code, Cursor, JetBrains or anything else. For one-click runs, copy [`.vscode/tasks.json`](.vscode/tasks.json) into your project and use **Terminal → Run Task → leashscan**.

## For forward deployed engineers and security reviews

Rolling out AI agents at a customer? The first question from their security team is *"what will this thing be able to touch?"* Run this on day one:

```bash
leashscan ~/client-repos/* --home -f html -o agent-exposure-report.html
```

- **Safe on customer machines:** read-only, fully offline, no telemetry, secrets always redacted
- **Nothing to install** beyond Python 3.9+ (standard library only, easy to vendor or audit, about 1,000 lines)
- **One report for many repos,** with a letter grade, severity counts and a concrete fix for every item
- Re-run after hardening and show the grade going from **F → A**

## Grading

Each finding costs points by severity (critical 30, high 12, medium 4, low 1, with diminishing cost for repeats of the same rule). Any critical finding caps the grade at **D**.
`A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40`

Got an A? Show it off:

```markdown
[![leashscan A](https://img.shields.io/badge/leashscan-A-brightgreen)](https://github.com/amisellati123/leashscan)
```

## Privacy

leashscan never makes a network request, never writes anything except the report file you ask for, and never prints a full secret. Read the source: it is small on purpose.

## Responsible use

Scan machines and repositories you own or are authorized to assess. If you find exposed credentials in someone else's project, report them privately to the maintainers.

## Contributing

New detection rules are the best contribution. Each scanner is a single file in [`src/leashscan/`](src/leashscan/), and tests live in [`tests/`](tests/). Ideas we'd love help with:
- more agent config formats (Zed, Continue, Amp, JetBrains AI)
- a `--fix` mode that applies the safe changes automatically
- a pre-commit hook and an npm wrapper (`npx leashscan`)

```bash
pip install -e . pytest && pytest
```

## License

MIT

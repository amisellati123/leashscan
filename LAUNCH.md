# Launch kit

Post everything on the same day, ideally Tuesday-Thursday, 8-10am US Eastern.
Links already point to github.com/amisellati123/leashscan.

## Checklist (before launch)

- [ ] Repo public, description + topics set: `ai-security`, `mcp`, `claude-code`, `cursor`, `prompt-injection`, `secrets`, `devsecops`, `llm-security`
- [ ] Social preview image uploaded (Settings → Social preview → docs/screenshot.png)
- [ ] Publish to PyPI so `pipx run leashscan` works: `python -m build && twine upload dist/*`
- [ ] Tag `v0.1.0` and `v0` so the GitHub Action works
- [ ] Record a 20-second GIF (`vhs` or `asciinema`) of scanning the demo project, add it to the top of README
- [ ] Run it on your own laptop and post your real grade (people love the honesty)

## Show HN

**Title:** Show HN: Leashscan – see what your AI coding agents and MCP servers can reach

**Text:**
I kept giving Claude Code, Cursor and a pile of MCP servers access to my machine without really knowing what they could see. Secret scanners don't look at agent configs, and agent tools don't look at your secrets, so I wrote a small scanner that does both.

It checks for secrets in the workspace and home folder, MCP configs with plain-text tokens, unpinned npx packages or filesystem access to /, YOLO permission settings (bypassPermissions, Bash(*), Codex danger-full-access, VS Code auto-approve), repo hooks that run on clone, and hidden prompt injection like invisible Unicode tag characters, which it decodes so you can read the hidden message.

Zero dependencies, offline, read-only. It gives a letter grade and a concrete fix per finding. It also outputs SARIF for GitHub code scanning and an HTML report for security reviews.

My own laptop got a D the first time. Curious what others get, and which configs I'm missing.

## Reddit (r/netsec, r/ClaudeAI, r/cursor, r/LocalLLaMA, r/programming)

**Title:** I built a scanner that shows what your AI coding agent can actually reach (secrets, MCP configs, hidden prompt injection). My setup got a D.

**Body:** Short version of the HN text + screenshot. Ask people to post their grade. Reply to every comment in the first 2 hours.

## X / Bluesky thread

1/ Your AI coding agent can probably read your AWS keys, SSH key and every .env on your laptop.

I built a free tool that shows you exactly what it can reach, in one command. 🐕

`pipx run leashscan`

[screenshot]

2/ It checks:
• secrets your agent can read
• MCP servers with plain-text tokens, unpinned packages or access to /
• "auto-approve everything" settings
• repo hooks that run `curl | sh` when you open the folder

3/ My favorite part: it finds invisible Unicode text hidden in AGENTS.md / README files and decodes it.

Humans can't see it. Your agent reads it as instructions.

[screenshot of decoded hidden text]

4/ Offline, zero dependencies, nothing leaves your machine. Gives you a letter grade + the exact fix for each issue.

Works with Claude Code, Cursor, Codex, Copilot, Windsurf, Gemini CLI.

My laptop got a D. What do you get? 👇
github.com/amisellati123/leashscan

## LinkedIn (FDE / security angle)

Before you roll out AI coding agents to a team, answer one question: what will they be able to touch?

I open-sourced leashscan, a zero-dependency scanner that audits a machine and its repos for what Claude Code, Cursor, Codex and MCP servers can reach: exposed credentials, auto-approve settings, risky MCP servers and hidden prompt injection.

It produces a one-page HTML report with a grade and a fix for every finding, so security teams can sign off faster. It runs offline and read-only, so it's safe on customer machines.

If you deploy agents for clients, I'd love feedback on what your security reviewers ask for.

## After launch

- Post your grade going from F → A after fixing things (a second wave of attention)
- Open "good first issue" tickets for new config formats, since contributors bring their own audiences
- Write a short blog post: "I found hidden instructions in X% of popular AGENTS.md files" (only scan public repos, report anything real privately first)

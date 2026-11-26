# Security Policy

## Supported versions

Only the latest release of leashscan on PyPI and the `main` branch receive security fixes.

| Version | Supported |
| ------- | --------- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report them privately through GitHub's private vulnerability reporting:
https://github.com/amisellati123/leashscan/security/advisories/new

Include what you found, how to reproduce it, and which version you used. You should get a reply within 7 days.

## About the test keys in this repository

leashscan detects leaked credentials, so its detection patterns, tests and demo
contain example key formats. All of them are synthetic, are built at runtime where
possible, and have never been valid credentials.

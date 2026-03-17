# Security Policy

## Reporting a vulnerability

If you find a security vulnerability in Jercept — including issues with the IBAC model, injection scanner, scope enforcement, or dashboard — **do not open a public GitHub issue.**

Email: **madhujersey9999**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (if any)

You will receive a response within 48 hours. Critical vulnerabilities will be patched within 7 days.

## Scope

In scope:
- IBAC scope bypass — any input that allows an out-of-scope tool call to execute
- Injection scanner false negatives on known attack patterns
- Dashboard authentication or authorization flaws
- SDK crashes that could be triggered by malicious input

Out of scope:
- Theoretical attacks with no practical exploit
- Social engineering
- Issues in third-party dependencies (report to them directly)

## Supported versions

| Version | Supported |
|---|:-:|
| 0.1.x (current) | ✅ |

## Disclosure policy

We follow responsible disclosure. Once a fix is released, we will publish a security advisory crediting the reporter (unless they request anonymity).

# secmend

> Find leaked secrets in your code — and get an exact, AI-generated remediation playbook to revoke, rotate, and scrub them from git history.

[![CI](https://github.com/jay-tank/secmend/actions/workflows/ci.yml/badge.svg)](https://github.com/jay-tank/secmend/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Most secret scanners stop at **detection** — they tell you a key leaked and leave
you to figure out the fix. But the real gap isn't detection, it's **follow-through**:
studies show a majority of leaked credentials stay *active* for years after exposure,
while an exposed cloud key can be abused within minutes.

`secmend` closes that gap. It detects secrets **and** hands you a concrete,
provider-specific playbook: what to revoke *right now*, how to rotate, the exact
`git`/BFG commands to purge it from history, and how to stop it happening again.

```text
🔑 3 secret(s) detected:
  ● AWS Access Key ID (critical) AKIA************MPLE  config.py:4
  ● GitHub Personal Access Token (critical) ghp_********************************wxyz  config.py:5
  ● Stripe Secret Key (critical) sk_l************************uvwx  config.py:6

🛠  Remediation (critical): Live credentials were committed and must be treated as compromised.

🚨 Immediate actions:
  › Deactivate the AWS key: IAM → Users → Security credentials → Make inactive → Delete.
  › Revoke the GitHub token at github.com/settings/tokens.
  › Roll the Stripe key in the Stripe Dashboard → Developers → API keys.
🔄 Rotate & update:  …
🧹 Scrub from git history:  …
🛡  Prevent recurrence:  …
```

## Why secmend

| | Typical scanner | **secmend** |
| :--- | :--- | :--- |
| Detects secrets | ✅ | ✅ |
| Tells you *how* to fix each one | ❌ | ✅ provider-specific |
| Git-history scrub commands | ❌ | ✅ |
| Prevention guidance | ❌ | ✅ |
| Works with no API key | — | ✅ `--detect-only` / `mock` / local Ollama |
| Never sends the secret to an LLM | — | ✅ only masked metadata leaves your machine |

## Safety first

- **Your secrets never leave your machine.** Only the *type* of each finding (e.g.
  "AWS Access Key ID") is sent to the LLM — never the value. Previews are masked.
- **Read-only.** secmend never edits, commits, or deletes anything. It advises;
  you run the commands.
- **No key required** to get value: `--detect-only` and `--provider mock` are fully
  offline; `--provider ollama` uses a local model.

## Install

```bash
# from source (until published to PyPI)
git clone https://github.com/jay-tank/secmend.git
cd secmend
pip install .
# for the Claude / OpenAI providers:
pip install '.[claude]'   # or '.[openai]'
```

## Usage

```bash
# Scan a file or a whole directory
secmend ./src

# Scan a staged diff (great as a pre-commit / CI gate)
git diff --cached | secmend --stdin

# Check a single value you're worried about
secmend --secret "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Detection only — no LLM, fully offline, exits non-zero if anything is found
secmend ./src --detect-only

# Pick a provider (default: claude). mock needs no key.
secmend ./src --provider mock
secmend ./src --provider ollama
secmend ./src --json
```

**Exit codes:** `0` = clean, `1` = secret(s) found, `2` = usage/read error — so it
drops straight into a CI step or git hook.

## Providers

| Provider | Flag | Needs |
| :--- | :--- | :--- |
| Claude *(default)* | `--provider claude` | `ANTHROPIC_API_KEY` + `pip install '.[claude]'` |
| OpenAI | `--provider openai` | `OPENAI_API_KEY` + `pip install '.[openai]'` |
| Ollama (local) | `--provider ollama` | a running local Ollama |
| Mock (offline) | `--provider mock` | nothing — deterministic demo output |

See [docs/PROVIDERS.md](docs/PROVIDERS.md) for configuration and [docs/USAGE.md](docs/USAGE.md)
for recipes (pre-commit hook, CI gate, JSON piping).

## What it detects

AWS keys, GitHub PATs (classic + fine-grained), GitLab PATs, Stripe keys, OpenAI /
Anthropic / Google / Slack / SendGrid / PyPI tokens, private keys, JWTs, Slack
webhooks, and generic `password/secret/token = …` assignments. Detection is pattern-based
and **best-effort** — it complements, not replaces, a full history scanner like gitleaks.

## Limitations

- Pattern-based detection can miss custom/obfuscated secrets and may flag look-alikes.
  Treat findings as a prioritized starting point.
- Remediation guidance is AI-generated — **read before running** any command,
  especially history rewrites.
- v1 **advises**; it does not call provider APIs to rotate keys for you (by design).

## License

MIT — see [LICENSE](LICENSE).

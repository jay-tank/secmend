# Using secmend

How I actually use it, and the flags worth knowing.

## Pointing it at something

You can give it a file, a whole directory, a piped diff, or a single value:

```bash
# scan a directory (walks it, skips node_modules/.git/etc.)
secmend ./src

# scan a staged diff before you commit
git diff --cached | secmend --stdin

# check one value you're suspicious about
secmend --secret "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## The two ways I run it

Plain run does detection plus the AI remediation playbook. When I just want to know
*what* leaked without any LLM call, I add `--detect-only`. It's fully offline and exits
non-zero if it finds anything, which is exactly what you want in a hook:

```bash
secmend ./src                 # findings + how to fix them
secmend ./src --detect-only   # just the findings, offline, no key
secmend ./src --json          # machine-readable
```

## Using it as a guardrail

This is where it earns its place. Drop it in a pre-commit hook so a secret never gets
committed in the first place:

```bash
# .git/hooks/pre-commit
git diff --cached | secmend --stdin --detect-only || {
  echo "Possible secret in your staged changes. Run 'secmend --stdin' for the fix."
  exit 1
}
```

Or as a CI step:

```bash
secmend . --detect-only
```

## Exit codes

- `0` clean, nothing found
- `1` found at least one secret
- `2` usage / read error

## One thing I care about

The secret value never leaves your machine. Only the *type* of finding (like "AWS Access
Key ID") is sent to the LLM for the remediation advice, and previews are masked before
anything is printed or sent.

## Env vars

- `SECMEND_PROVIDER` — default provider
- `SECMEND_MODEL` — model override
- `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` — provider keys
- `OLLAMA_HOST` — if Ollama isn't on localhost

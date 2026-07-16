# Usage

## Inputs

secmend scans one of:

| Input | Command |
| :--- | :--- |
| A file | `secmend path/to/file` |
| A directory (recursive) | `secmend ./src` |
| A piped stream | `git diff \| secmend --stdin` |
| A single value | `secmend --secret "ghp_…"` |

Directory walks skip `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`,
`dist`, and `build`, and ignore files larger than ~2 MB.

## Modes

- **Full (default):** detect secrets, then ask the LLM for a remediation playbook.
- **`--detect-only`:** detection only — fully offline, no LLM. Exits `1` if anything
  is found. Ideal for a fast pre-commit/CI gate.
- **`--json`:** machine-readable output (`{"findings": [...], "remediation": {...}}`).

## Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | Clean — no secrets found |
| `1` | One or more secrets found |
| `2` | Usage error / could not read input |

## Recipes

### Pre-commit hook
`.git/hooks/pre-commit`:
```bash
#!/usr/bin/env bash
git diff --cached | secmend --stdin --detect-only || {
  echo "❌ Potential secret in staged changes. Run 'secmend --stdin' for guidance."
  exit 1
}
```
```bash
chmod +x .git/hooks/pre-commit
```

### CI gate (GitHub Actions)
```yaml
- name: Scan for secrets
  run: |
    pip install secmend
    secmend . --detect-only
```

### Get the full remediation for something you found
```bash
secmend --secret "AKIA…" --provider claude
```

## Environment variables

| Variable | Purpose |
| :--- | :--- |
| `SECMEND_PROVIDER` | Default provider (else `claude`) |
| `SECMEND_MODEL` | Default model override |
| `ANTHROPIC_API_KEY` | Claude auth |
| `OPENAI_API_KEY` | OpenAI auth |
| `OLLAMA_HOST` | Ollama endpoint (default `http://localhost:11434`) |

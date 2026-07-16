# Providers

secmend is provider-agnostic. The secret **detection** is always local; only the
**remediation** step calls an LLM — and only masked metadata is ever sent.

## Choosing a provider

```bash
secmend ./src --provider claude   # default
secmend ./src --provider openai
secmend ./src --provider ollama   # local, no key
secmend ./src --provider mock     # offline, deterministic
```

Set a default with `SECMEND_PROVIDER`.

## Claude (default)
```bash
pip install 'secmend[claude]'
export ANTHROPIC_API_KEY=...        # your key, from your environment
secmend ./src --provider claude
```
Default model: `claude-opus-4-8`. Override with `--model` or `SECMEND_MODEL`.

## OpenAI
```bash
pip install 'secmend[openai]'
export OPENAI_API_KEY=...
secmend ./src --provider openai
```
Default model: `gpt-4o-mini`.

## Ollama (local, no API key)
```bash
ollama serve
ollama pull llama3
secmend ./src --provider ollama
```
Point at a non-default host with `OLLAMA_HOST`.

## Mock (offline)
Deterministic canned playbook — no network, no key. Used by the test suite and for
demos. `secmend ./src --provider mock`.

## A note on keys
secmend reads API keys **only** from your environment and never logs or transmits
them. If you just want to know *what* leaked without any LLM, use `--detect-only`.

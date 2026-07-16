# Providers

secmend only calls an LLM for one thing: writing the remediation playbook once a secret
is found. The detection itself is fully local. So if you just want to know what leaked,
`--detect-only` needs no provider at all.

When you do want the fix-it advice, pick a provider:

```bash
secmend ./src --provider claude   # what I default to
secmend ./src --provider openai
secmend ./src --provider ollama   # local, no key
secmend ./src --provider mock     # canned output, for demos/tests
```

Worth repeating: the secret value itself never goes to the model. Only the finding type
(like "AWS Access Key ID") is sent so it can tell you how to rotate that kind of key.

## Claude (my default)

```bash
pip install 'secmend[claude]'
export ANTHROPIC_API_KEY=...
```

Defaults to `claude-opus-4-8`. Override with `--model` or `SECMEND_MODEL`.

## OpenAI

```bash
pip install 'secmend[openai]'
export OPENAI_API_KEY=...
```

Defaults to `gpt-4o-mini`.

## Ollama (local, no key)

If you'd rather keep everything on your own machine:

```bash
ollama serve
ollama pull llama3
secmend ./src --provider ollama
```

Set `OLLAMA_HOST` if it's not on the default localhost port.

## mock / --detect-only

`mock` returns a fixed response (used in tests and demos). `--detect-only` skips the LLM
entirely and just reports what it found. Both need zero setup and no key.

Keys are read only from the environment. I don't log them or write them anywhere.

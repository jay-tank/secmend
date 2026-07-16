# Contributing

Thanks for your interest in secmend!

## Dev setup
```bash
git clone https://github.com/jay-tank/secmend.git
cd secmend
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

## Guidelines
- **Tests first.** Every change ships with tests; the suite runs fully offline
  (mock provider + fixtures) — no API key or network required.
- **Never send secret values to an LLM.** Only masked metadata leaves the machine;
  keep it that way. Add a test if you touch that path.
- **Adding a detector?** Add a `Detector` to `secmend/detectors.py` (most-specific
  patterns first) with sensible `provider`/`severity`/`exploitation_window`, and a
  test in `tests/test_detectors.py`.
- Keep the tool **read-only** — it advises, it never mutates the user's repo.
- Match the existing style; keep docs in sync with behavior.

## Reporting issues
Open an issue with a minimal repro. **Never paste a real secret** — use a fake
look-alike (see `tests/fixtures/leaky_config.py`).

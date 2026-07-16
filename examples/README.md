# Examples

Try secmend with no API key using the offline `mock` provider.

```bash
# Scan the test fixture (contains FAKE credentials)
secmend ../tests/fixtures/leaky_config.py --provider mock

# Detection only (no LLM at all)
secmend ../tests/fixtures/leaky_config.py --detect-only

# Check a single value
secmend --secret "ghp_1234567890abcdefghijklmnopqrstuvwxyz" --provider mock

# Use as a staged-diff gate
git diff --cached | secmend --stdin --detect-only
```

> The values in `tests/fixtures/leaky_config.py` are fake, non-functional
> look-alikes used purely to exercise the detectors.

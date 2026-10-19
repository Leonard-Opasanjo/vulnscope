# Contributing

Bug reports, new checks and better remediation text are welcome.

## Set up

```bash
git clone https://github.com/Leonard-Opasanjo/vulnscope.git
cd vulnscope
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

The tests need the `openssl` command (to mint a self-signed certificate) and, for the PDF test, Chromium or
Chrome; that test skips when no browser is present.

## Before you open a pull request

```bash
ruff check .
pytest
bandit -q -c pyproject.toml -r vulnscope
pip-audit
```

## Adding a check

1. Write a pure function in `vulnscope/checks.py` (or `tls.py` for certificate and protocol checks) that takes
   observed data and returns `list[Finding]` or `Finding | None`. Give the finding a stable `key` if the same
   check can fire more than once per target (per cookie, per path).
2. Write the description for someone who is not a security specialist: what it is, why it matters, the exact
   fix for common servers, and a reference.
3. Call it from `Scanner.scan` in `vulnscope/scanner.py`. If it needs a new request, keep the budget in mind;
   the scan should stay around twenty requests.
4. Add unit tests at the thresholds in `tests/test_checks.py` or `tests/test_tls.py`. If the practice target
   should exhibit the weakness, add it to the insecure branch of `vulnscope/target.py`, keep the secure branch
   clean, and update the expectations in `tests/test_scanner.py`.
5. Add the row to the table in `README.md`.

Checks must stay passive: GET, HEAD, OPTIONS and TRACE only, no authentication, no parameters, no payloads.
A proposal that needs anything else belongs in a different tool.

## Style

`ruff` settings in `pyproject.toml` are the style guide. Keep the check functions free of I/O so they stay
testable without a network.

## Security issues

See [SECURITY.md](SECURITY.md).

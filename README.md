# Content Boundary Lab

An independent educational laboratory for security code review and remediation.
It is not affiliated with, endorsed by or sponsored by any company, standards body or product.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

**Status: scaffold.** No security findings and no vulnerable code are implemented yet, and this README makes no security claims.

## Run the tests

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

Python 3.12 or newer is declared in `pyproject.toml`. No claim is made yet about which versions have been tested.

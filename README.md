# Content Boundary Lab

An independent educational laboratory for security code review and remediation.
It is not affiliated with, endorsed by or sponsored by any company, standards body or product.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

**Status: scaffold.** No security findings and no vulnerable code are implemented yet, and this README makes no security claims.

## Run the tests

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pytest -q
```

`requirements.lock` pins every dependency by SHA-256 hash, but only for CPython 3.13 on macOS arm64. Other platforms and Python 3.12 are refused by the hash check until each has its own verified lock. `pyproject.toml` declares Python 3.12 or newer; no wider claim is made.

The build backend (`setuptools==84.2.1`) is version-pinned in `pyproject.toml` and installed by pip into a temporary build environment. It is not covered by the hashes.

Ordinary test runs check that the locked packages are installed at the locked versions and tolerate extra packages. To check that a fresh environment holds exactly the locked set, run `.venv/bin/python -m pytest -m clean_env`.

# Content Boundary Lab

An independent educational laboratory for security code review and remediation.
It is not affiliated with, endorsed by or sponsored by any company, standards body or product.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

**Status: the reference implementation is built through trusted promotion, and its documentation is written.** There is no runnable server yet, no deliberately vulnerable variant and no security finding: those come later. The reference application contains no vulnerable code and no switch that selects any.

The code is organised around three decisions that real failures in this area tend to blur together: who you are (a verified signed token), what you may touch (an engagement looked up on every request, in the production the URL names), and whether the bytes should be trusted (decided from the bytes the server itself read and hashed, never from what the sender declared).

## Documentation

- [Architecture](docs/architecture.md): the pieces, the request flow, the delivery lifecycle, where bytes live, and what the database refuses on its own.
- [Threat model](docs/threat-model.md): actors, trust boundaries, and every threat with its control and the tests for it, or marked as a limitation or out of scope.
- [Claims register](docs/claims.md): every claim made here, each traced to the tests that show it, and the claims that are not made. This README makes no claim that is not in that register.
- [References](docs/references.md): the sources and versions behind every mapping, with retrieval dates.
- [Design decisions](docs/decisions.md): the amendments and assumptions, and the entry point for anyone working on the code.

## What is implemented, simulated and conceptual

| Status | What |
|---|---|
| Implemented | token verification; engagement authorisation; the production-scoped asset read; the delivery workflow from declaration through sealing, acceptance and promotion; the audit trail |
| Simulated | the identity provider (a test token issuer), the scanner (one synthetic marker), the object stores (two local directories) |
| Conceptual | cloud buckets, pre-signed URLs, federation, CSAP components |

The lab's scanner detects one synthetic marker. It provides no malware protection, and `no_detection` says nothing about whether a file is safe.

## Run the tests

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pytest -q
```

`requirements.lock` pins all 23 distributions, direct and transitive, by SHA-256 hash with one wheel file each, and the install command above accepts wheels only. It was last verified on 2026-11-03 for one environment: CPython 3.13.7 on macOS arm64. `cryptography`, `cffi` and `pydantic_core` ship compiled code, so those three wheels are specific to that platform. Other platforms and Python 3.12 are refused by the hash check until each has its own verified lock. `pyproject.toml` declares Python 3.12 or newer; no wider claim is made.

The direct runtime dependencies are `fastapi`, `PyJWT` and `cryptography`; `cffi` and `pycparser` are installed only because `cryptography` needs them. `PyJWT` and `cryptography` verify the signed tokens (`identity.py`), against public keys from trusted configuration only; nothing in the source tree can mint a token or hold a private key.

The build backend (`setuptools==84.2.1`) is version-pinned in `pyproject.toml` and installed by pip into a temporary build environment. It is not covered by the hashes.

Ordinary test runs check that the locked packages are installed at the locked versions and tolerate extra packages. To check that a fresh environment holds exactly the locked set, run `.venv/bin/python -m pytest -m clean_env`.

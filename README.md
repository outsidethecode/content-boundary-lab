# Content Boundary Lab

An independent educational laboratory for security code review and remediation.
It is not affiliated with, endorsed by or sponsored by any company, standards body or product.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

**Status: the reference implementation is built, composed by a runner, documented, and has been served by a real local `uvicorn` on `127.0.0.1`.** The workflow runs and is tested in-process, and an opt-in set of tests drives the real server over TCP on this one machine with synthetic data. Four seeded findings are written and reproducible (below). `labs/` contains intentionally vulnerable code; the default application does not, and no switch, option or setting selects any of it.

The code is organised around three decisions that real failures in this area tend to blur together: who you are (a verified signed token), what you may touch (an engagement looked up on every request, in the production the URL names), and whether the bytes should be trusted (decided from the bytes the server itself read and hashed, never from what the sender declared).

## The findings

Each finding is one function in the reference application and a seeded twin of it under [labs/](labs/README.md). The same attacker's steps run against the reference and against the reference with only that function swapped; the seeded variant is exploited and the reference refuses. Passing tests show that the seeded defect is reproducible and that the corrected code blocks it under the stated assumptions; they show nothing more.

| Finding | Boundary | Severity (in-scenario, educational) | CWE | ASVS 5.0.0 | Write-up | Reproduce |
|---|---|---|---|---|---|---|
| F-02 Object access checks the parent, not the child | TB3 | High | 639 | 8.2.2, 8.4.1 | [F-02](docs/findings/F-02-object-access-checks-the-parent.md) | `python -m labs.f02_parent_check` |
| F-03 Caller-declared checksum used as content identity | TB5 | High | 807 | 5.4.3, 2.2.2, 16.5.3 | [F-03](docs/findings/F-03-declared-checksum-used-as-content-identity.md) | `python -m labs.f03_declared_identity` |
| F-04 Promotion trusts a mutable reference, not the accepted bytes | TB4 | High if something else can write quarantine after the seal | 367 | 15.4.2, 2.3.1, 2.3.3 | [F-04](docs/findings/F-04-promotion-trusts-a-mutable-reference.md) | `python -m labs.f04_unverified_promotion` |
| F-06 Authorisation snapshot in a long-lived token | TB3 | Medium | 863 | 8.3.2, 7.4.2 | [F-06](docs/findings/F-06-authorisation-snapshot-in-a-long-lived-token.md) | `python -m labs.f06_stale_authorisation` |

`python -m labs.matrix` runs the remediation matrix of each finding (the original exploit, the behaviour that must keep working, the alternate and boundary attempts) against the reference, the seeded variant and the partial fixes that look like fixes and are not; it prints `yes` where the required outcome holds and `NO` where it does not. `python -m labs` runs all four demonstrations and ends with `4 exploits reproduced against the seeded variants; 4 blocked by the reference (4 findings).` Output of each run, with the date, command, commit and versions, is in [docs/evidence](docs/evidence/f02.txt). `pytest tests/findings -v` runs the same scenarios as tests with the isolation proof; `pytest -m packaging` shows that neither the wheel nor the sdist holds anything from `labs/`. F-01 and F-05 are optional in the design and are not built. The scanner is the lab's synthetic marker scanner and provides no malware protection.

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
| Simulated | the identity provider (a development token issuer under `tools/`, and an in-memory one in the tests), the scanner (one synthetic marker), the object stores (two local directories) |
| Conceptual | cloud buckets, pre-signed URLs, federation, CSAP components |

The lab's scanner detects one synthetic marker. It provides no malware protection, and `no_detection` says nothing about whether a file is safe.

## Run the lab locally

For local study only: it listens on `127.0.0.1` and nowhere else, with no TLS, and nothing in it is meant to face a network. Every value the lab trusts is named on the command line or fixed in the runner's code: there is no environment variable and no default, and the runner refuses to start without a loadable key set, a database of the lab's own schema, and two storage directories that are its own and not writable by anyone else. The scanner is the synthetic one, and the start-up banner says so. Install the locked environment first, as under "Run the tests" below, and use that environment's `python`.

```bash
python tools/dev_token_issuer.py setup                       # a throwaway key, the trusted settings and two private directories in .dev/
python -m content_boundary_lab.runner init --database .dev/lab.sqlite3 --trusted-root .dev/trusted --quarantine-root .dev/quarantine
python -m content_boundary_lab.runner seed-demo --settings .dev/settings.toml --database .dev/lab.sqlite3
python tools/dev_token_issuer.py mint --subject dev-vendor-a       # a token for a vendor of the first synthetic production
python -m content_boundary_lab.runner serve --settings .dev/settings.toml --database .dev/lab.sqlite3 --trusted-root .dev/trusted --quarantine-root .dev/quarantine --max-upload-bytes 1048576 --port 8000
```

`serve` runs `uvicorn` as a library with one worker, no reload and no proxy headers, whatever the server's environment variables say (Python's own, such as `PYTHONPATH`, are the operator's: the tests start the runner with `python -I`). `promote`, `rescan` and `reconcile` are the lab's own jobs, run by the operator, and `reconcile` refuses to start while a server, a promotion or a rescan is running on the same directories. [Architecture](docs/architecture.md) section 14 describes each command and what it does to the lab. A delivery stranded in `SEALING` is listed by `reconcile` and nothing moves it: an operator investigates it (A-J7, a known availability limit).

To see the real server work, run `.venv/bin/python -m pytest -m real_server -s`: it starts `serve` on a random loopback port, speaks HTTP to it with synthetic data, and stops it. It needs `lsof` and is left out of the ordinary run.

## Run the tests

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pytest -q
```

`requirements.lock` pins all 25 distributions, direct and transitive, by SHA-256 hash with one wheel file each, and the install command above accepts wheels only. It was last verified on 2026-11-04 for one environment: CPython 3.13.7 on macOS arm64. `cryptography`, `cffi` and `pydantic_core` ship compiled code, so those three wheels are specific to that platform. Other platforms and Python 3.12 are refused by the hash check until each has its own verified lock. `pyproject.toml` declares Python 3.12 or newer; no wider claim is made.

The direct runtime dependencies are `fastapi`, `PyJWT`, `cryptography` and `uvicorn` (the minimal install, not its `standard` extra); `cffi` and `pycparser` are installed only because `cryptography` needs them, and `click` only because `uvicorn` does. `PyJWT` and `cryptography` verify the signed tokens (`identity.py`), against public keys from trusted configuration only; nothing in the source tree can mint a token or hold a private key.

The build backend (`setuptools==84.2.1`) is version-pinned in `pyproject.toml` and installed by pip into a temporary build environment. It is not covered by the hashes.

`pip` itself is not in the lock. The one that ships with CPython 3.13.7 (25.2) has six published advisories, the latest fixed in 26.2; the hashes limit what it can install to the 25 locked wheels, but if you want a current installer, run `.venv/bin/python -m pip install --upgrade pip` before the install above (that one step is not covered by the hashes). The dependency audit is in [docs/review/static-analysis.md](docs/review/static-analysis.md).

Ordinary test runs check that the locked packages are installed at the locked versions and tolerate extra packages. To check that a fresh environment holds exactly the locked set, run `.venv/bin/python -m pytest -m clean_env`.

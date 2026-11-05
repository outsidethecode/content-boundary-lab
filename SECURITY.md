# Security policy

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

Content Boundary Lab is a teaching lab. Part of it is **vulnerable on purpose**, so the first question for any report is
whether the thing you found is one of the lab's own exhibits or a defect in the part that is meant to be correct. This page
separates the two.

## What is intentional: please do not report these as bugs

- **Everything under [`labs/`](labs/README.md).** The four seeded flaws (F-02, F-03, F-04 and F-06), their partial fixes
  (`naive.py`, banner-marked "NAIVE FIX, INCOMPLETE") and the scenarios that exploit them are the exhibits. They are
  supposed to fail the way the write-ups in [`docs/findings/`](docs/findings/) say.
- **The limitations the project already states.** Every row marked *Limitation* or *Out of scope* in the
  [threat model](docs/threat-model.md), and every finding the [M4 register](docs/review/m4-findings.md) records as accepted
  or documented, for example that promotion does not look at anything that happened after an acceptance (M4-01), that the
  verdict cache is shared across productions (M4-10), and that the lab makes no confidentiality claim against another
  local account or any defence against a party who can write its storage directories.
- **The synthetic parts.** The scanner detects one made-up marker and provides no malware protection. The identity
  provider is a development token issuer. The server listens on `127.0.0.1` only, with no TLS, and is for local study.
- **Denial of service** (resource exhaustion, a flood of requests, an upload that never ends) beyond the documented
  per-request size limit. [Threat model](docs/threat-model.md), section 5.
- **Anything that needs write access to the database, the key set or the two storage directories**, or a privileged local
  user. The lab assumes the operator controls them.

## What to report

- **A way to make one of the four seeded behaviours happen through the reference application in `src/`**: reading another
  production's asset, a verdict applied to bytes that were not scanned, bytes other than the accepted ones published, or an
  action authorised after its engagement was revoked or ended. If the exploit in a write-up succeeds against the reference,
  that is a bug in the reference.
- **Any other defect in `src/` or `tools/`** that the documents do not already state: a route that answers without a verified
  token, access across productions, a decision with no audit event, a file written outside its directory, an error that
  discloses a path, a digest or a key.
- **A way for vulnerable code to reach the package**: anything from `labs/` importable from `src/`, selectable by an option,
  or present in the built wheel or source distribution.
- **A claim that its evidence does not support**: a sentence in the README or in [`docs/claims.md`](docs/claims.md) that
  the cited test does not show.
- **A real secret or real personal data** anywhere in the repository or its history. All data here is meant to be synthetic.
- **A known advisory for a pinned dependency** in [`requirements.lock`](requirements.lock).

## How to report

For a defect in the reference application, use GitHub's private vulnerability reporting for this repository (the Security
tab, "Report a vulnerability"). For a documentation error, a failing test or anything not sensitive, open an ordinary issue.
Please give the commit, the steps, what you expected and what happened. A short script that reproduces it is the most useful
thing you can send.

This is a one-person educational project: reports are read on a best-effort basis, with no response-time commitment, no bounty
and no promise of a fix. Please test only against your own copy of the lab, which uses synthetic data, and not against any
system you do not own.

## Supported versions

Only the latest commit on the default branch. There are no releases.

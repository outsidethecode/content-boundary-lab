# labs/: intentionally vulnerable code

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

**`labs/` contains intentionally vulnerable code. The default application does not.** Nothing under `src/` imports this
directory, it is outside package discovery and is never packaged, and nothing in the runner, in the dependencies the runner
builds, or in any option, setting or environment variable can select anything in it.

## What a finding is

A **seam** is one function that makes one security decision. A finding is that function's seeded twin, in a package of its
own, and nothing else: the application, its routes, its storage and the rest of its decisions are the reference. `labs.seam`
swaps the one module attribute for the length of a `with` block and puts the reference back when the block ends, however it
ends. There is no flag, no persistent patch and no second seam.

| Finding | Title | Seam (reference) | Seeded twin | Write-up |
|---|---|---|---|---|
| F-02 | Object access checks the parent, not the child | `assets.get_asset_in_scope` | [f02_parent_check](f02_parent_check/vulnerable.py) | [F-02](../docs/findings/F-02-object-access-checks-the-parent.md) |
| F-03 | Caller-declared checksum used as content identity | `trust.content_identity` | [f03_declared_identity](f03_declared_identity/vulnerable.py) | [F-03](../docs/findings/F-03-declared-checksum-used-as-content-identity.md) |
| F-04 | Promotion trusts a mutable reference, not the accepted bytes | `promotion.copy_verified` | [f04_unverified_promotion](f04_unverified_promotion/vulnerable.py) | [F-04](../docs/findings/F-04-promotion-trusts-a-mutable-reference.md) |
| F-06 | Authorisation snapshot in a long-lived token | `authz.authorize_engagement` | [f06_stale_authorisation](f06_stale_authorisation/vulnerable.py) | [F-06](../docs/findings/F-06-authorisation-snapshot-in-a-long-lived-token.md) |

Each finding package also holds the **partial fixes** that M3 shows to be incomplete (`naive.py`, banner-marked
"NAIVE FIX, INCOMPLETE") and `matrix.py`, the remediation matrix that runs the original exploit, the behaviour that must keep
working and the alternate and boundary attempts against the reference, the seeded variant, those partial fixes and, for F-02,
a different complete fix. A partial fix is applied only for the length of one row, exactly as a seeded twin is.

F-01 and F-05 are optional in the design and are not built.

## Run a finding

Each command builds a throwaway synthetic world in a temporary directory, runs the attacker's steps against the reference and
against the reference with only the seam swapped, prints both, and exits 0 only if the seeded variant was exploited and the
reference blocked it.

```bash
python -m labs                      # all four, and a summary
python -m labs.f02_parent_check     # one finding
python -m labs --evidence docs/evidence   # also write docs/evidence/fNN.txt under a header (date, command, commit, versions)
python -m labs.matrix               # the four remediation matrices (M3); --evidence docs/evidence writes fNN-matrix.txt
pytest tests/findings -v            # the same scenarios as tests, plus the isolation proof
```

## Rules for everything in here

- One seam per finding, and only the seam is vulnerable. Plumbing and scenarios are reference code: [carrier.py](carrier.py)
  copies a token's claims for F-06 and decides nothing, and a scenario is a client.
- Synthetic identities, content and keys only; the issuer and audience are reserved `.example` names, the key is made in
  memory, and nothing is read from or sent to a network.
- No finding depends on another: each exploit is blocked while any other seam is applied
  ([test_labs_isolation.py](../tests/findings/test_labs_isolation.py)).
- The scanner is the lab's synthetic marker scanner. It provides no malware protection.
- Never import this package from `src/`, never run these over a socket, and never copy one into a real system.

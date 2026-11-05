# Walkthrough

For an operator who wants to run the lab and a reviewer who wants to read it. It takes about fifteen minutes, everything runs
on your own machine, and all data is synthetic. Every command below was run, from a clean checkout, on the platform the lock
is verified for: CPython 3.13 on macOS arm64. Other platforms are not verified ([publication.md](publication.md)).

## 1. Install

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
```

The lock pins 25 wheels by SHA-256, so the install refuses anything else. The second command is the only one that reaches the
network, and it fetches from PyPI. `pip` itself is not in the lock; the [README](../README.md) says what to do about that.

## 2. See the four findings

```bash
.venv/bin/python -m labs
```

Each finding runs twice in a throwaway synthetic world: once against the reference application, and once against the
reference with a single function replaced by its seeded twin. The attacker's steps are the same code both times. The output
lists each step and what came back, for both variants, so you can read the difference. For F-02, a vendor engaged only in
ALPHA asks for BRAVO's asset through ALPHA's URL (lines from [the evidence file](evidence/f02.txt)):

<!-- evidence: docs/evidence/f02.txt -->
```text
== REFERENCE
  2. the same vendor asks for BRAVO's asset through the ALPHA url
       -> 404 {"detail":"Not found"}
== SEEDED VARIANT (only the seam above is swapped)
  2. the same vendor asks for BRAVO's asset through the ALPHA url
       -> 200, 3500 bytes: exactly BRAVO's asset
```

The command exits 0 only if every seeded variant was exploited and the reference blocked it. Run one finding with
`.venv/bin/python -m labs.f02_parent_check`.

## 3. See that the fixes are fixes

A fix that stops the exploit you were shown is not necessarily a fix. The remediation matrices run, for each finding, the
original exploit, the behaviour that must keep working, and the alternate and boundary attempts, against the reference, the
seeded variant and the partial fixes that look right and are not:

```bash
.venv/bin/python -m labs.matrix
```

For F-04 the first partial fix (N1) is the check that looks sufficient. Read the row `X1` and the line `N1  fails: …` of
[the F-04 matrix](evidence/f04-matrix.txt): the table shows which rows each variant fails, and the last line says whether that
is what was expected.

<!-- evidence: docs/evidence/f04-matrix.txt -->
```text
N1  fails: X1  [as expected]
```

## 4. Read one finding, from write-up to code

F-04 is a good first read, because the flaw is four lines and the reference is the interesting part.

1. The write-up, [F-04](findings/F-04-promotion-trusts-a-mutable-reference.md): context, boundary, root cause, exploit, fix,
   results and residual risk.
2. The seeded twin, [the whole function](../labs/f04_unverified_promotion/vulnerable.py).
3. The reference, [`promotion.copy_verified`](../src/content_boundary_lab/promotion.py), and the module's header, which
   explains why a filesystem rename and a database transaction are not one act and what the code does about it.
4. The scenario, [scenario.py](../labs/f04_unverified_promotion/scenario.py), which is the same code for both variants.
5. The tests, [test_f04_unverified_promotion.py](../tests/findings/test_f04_unverified_promotion.py), and the partial fixes in
   [naive.py](../labs/f04_unverified_promotion/naive.py).

The other three finding pages follow the same seven headings.

## 5. Walk one delivery through a real local server

This is the whole workflow with `curl`: a vendor declares, uploads and seals a file, a coordinator accepts exactly its
digest, the operator runs the promotion job, and the coordinator downloads the asset. It starts the real server on
`127.0.0.1:8000`, makes a throwaway key and database in `.dev/` (git-ignored), and stops the server at the end. It needs
`curl` and `shasum`, and nothing else running on port 8000. Paste it into one shell session at the repository root.

<!-- run: this block was run as written, from a fresh clone -->
```bash
PY=.venv/bin/python
$PY tools/dev_token_issuer.py setup > /dev/null       # a throwaway key, the trusted settings and two private directories
$PY -m content_boundary_lab.runner init --database .dev/lab.sqlite3 --trusted-root .dev/trusted --quarantine-root .dev/quarantine
$PY -m content_boundary_lab.runner seed-demo --settings .dev/settings.toml --database .dev/lab.sqlite3 > .dev/seed.json
PRODUCTION=$($PY -c 'import json; print(json.load(open(".dev/seed.json"))["productions"]["a"])')
$PY -m content_boundary_lab.runner serve --settings .dev/settings.toml --database .dev/lab.sqlite3 --trusted-root .dev/trusted --quarantine-root .dev/quarantine --max-upload-bytes 1048576 --port 8000 &
SERVER=$!
until curl -s -o /dev/null http://127.0.0.1:8000/; do sleep 1; done
VENDOR=$($PY tools/dev_token_issuer.py mint --subject dev-vendor-a)
COORDINATOR=$($PY tools/dev_token_issuer.py mint --subject dev-coordinator-a)
printf '\x89PNG\r\n\x1a\nsynthetic image payload\n' > .dev/shot.png
SIZE=$(wc -c < .dev/shot.png | tr -d ' ')
SHA=$(shasum -a 256 .dev/shot.png | cut -d' ' -f1)
BASE=http://127.0.0.1:8000/productions/$PRODUCTION
DELIVERY=$(curl -s -X POST $BASE/deliveries -H "Authorization: Bearer $VENDOR" -H 'Content-Type: application/json' -d "{\"display_name\":\"shot-020.png\",\"declared_media_type\":\"image/png\",\"declared_size\":$SIZE,\"declared_sha256\":\"$SHA\"}" | $PY -c 'import json,sys; print(json.load(sys.stdin)["delivery_id"])')
curl -s -X PUT $BASE/deliveries/$DELIVERY/content -H "Authorization: Bearer $VENDOR" --data-binary @.dev/shot.png; echo
curl -s -X POST $BASE/deliveries/$DELIVERY/seal -H "Authorization: Bearer $VENDOR"; echo
curl -s -X POST $BASE/deliveries/$DELIVERY/accept -H "Authorization: Bearer $COORDINATOR" -H 'Content-Type: application/json' -d "{\"sealed_sha256\":\"$SHA\"}"; echo
$PY -m content_boundary_lab.runner promote --database .dev/lab.sqlite3 --trusted-root .dev/trusted --quarantine-root .dev/quarantine --production-id $PRODUCTION --delivery-id $DELIVERY | tee .dev/promoted.json
ASSET=$($PY -c 'import json; print(json.load(open(".dev/promoted.json"))["asset_id"])')
curl -s $BASE/assets/$ASSET -H "Authorization: Bearer $COORDINATOR" -o .dev/downloaded.png
cmp .dev/shot.png .dev/downloaded.png && echo "the downloaded bytes are the uploaded bytes"
$PY -c 'import sqlite3; [print(*row) for row in sqlite3.connect(".dev/lab.sqlite3").execute("SELECT action, outcome, COALESCE(reason, \"-\") FROM audit_events ORDER BY seq")]'
kill $SERVER
```

What to look at in the output:

- Each `curl` answer names the delivery's state: `UPLOADED`, then `SCAN_PASSED` with the digest the **server** computed (`sealed_sha256`),
  then `ACCEPTED` for exactly that digest. The vendor's declaration was only compared with it.
- `promote` prints `PROMOTED` and the asset's id. The server was running while it ran: promotion is the operator's job and has
  no route.
- The last line before the audit listing says the bytes you downloaded are the bytes you uploaded.
- The audit listing has one row per decision, in order, each with an outcome and, when something was refused, a reason from a
  closed list. There is no row for anything the system did not decide.

To see a refusal, run the block again with a second vendor's token (`--subject dev-vendor-b`) against the first production's
URL: the answer is the same 403 as for a missing production, and the audit row says why.

To start again from nothing, delete `.dev/`.

## 6. Check the documents and the evidence

```bash
.venv/bin/python tools/check_docs.py
```

It follows every relative link and anchor in the README, [SECURITY.md](../SECURITY.md), `labs/` and `docs/`, compares each
code block marked as a snippet with the function it quotes, and checks that each block marked as evidence quotes only lines
its evidence file holds. It also reads the header of each file in `docs/evidence`, which records the date, the command, the
commit, the Python and the pinned versions, and says `FINAL` only if the files were made from a clean committed tree.

```bash
.venv/bin/python tools/check_docs.py --final
```

adds the requirement that the evidence is `FINAL`, that its commit is in your history, and that `src/`, `labs/`,
`requirements.lock` and `pyproject.toml` have not changed since that commit. To regenerate the evidence, from a clean
checkout:

```bash
.venv/bin/python -m labs --evidence docs/evidence
.venv/bin/python -m labs.matrix --evidence docs/evidence
```

Regenerating changes the header lines of each file (the date and the commit) and, if the code behaves differently, the body.

## 7. If you are reviewing

Start with the source, not the documents. [REVIEW-PACKAGE.md](review/REVIEW-PACKAGE.md) is written for a reviewer who has not
seen the project: what it is for, the contracts to attack, the commands, how to report. It points at the earlier reviews only in
its last section, so that you can form a view first. No human reviewer has read this code yet (decision D10); the earlier
reviews are by AI models of the same family as the author and are an internal check.

The things a reader most often asks about are in [SECURITY.md](../SECURITY.md) (what is intentional and what to report), in the
[register](review/m4-findings.md) (every item found, and how it was decided) and in [the claims register](claims.md) (every
claim, and the tests behind it).

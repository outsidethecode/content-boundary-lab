# Follow-up to the fresh assessment of 2026-11-05

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

A fresh Claude Code session (Opus 5.5, the same model family as the author) assessed the finished portfolio on 2026-11-05 and
reported no confirmed critical or high defect in the reference within its threat model, two runner problems, an understated
impact in the F-06 demonstration and several claims that were worded too strongly. It is **not** the independent human review
of M0 D10, which is still pending. This record says what happened to each item the owner asked to have looked at. Each
proposed correction was checked against the code and reproduced before anything was edited; the reviewer's conclusions were not
taken as given, and where the evidence differed this record says so.

The development freeze was reopened for targeted security corrections and accurate finding documentation only. No feature, no
optional finding, no change to the M0 lifecycle and no broad mutation campaign was added.

## 1. Outcome by item

| Item | Reviewer's rating | Reproduced here | Decision | Where |
|---|---|---|---|---|
| IR-01 (the same as M4-01 and TM-38): trust is not rechecked at promotion | Medium | Not re-run (a recorded, accepted limitation) | **Unchanged.** Stays open and documented | [TM-38](threat-model.md), [M4-01](review/m4-findings.md) |
| IR-02: the operator jobs skip the root-separation rule | Low | Yes: `promote` with one directory for both roots exits 0 and publishes into quarantine | **Fixed.** One shared check, applied to `init`, `serve`, `promote` and `reconcile`; `rescan` is given one root and has no pair to confuse. The check also refuses two spellings of one directory that differ only in letter case, which the old check in `serve` did not (found while reproducing) | `app.check_separate_roots`; [TM-29](threat-model.md); C-22 |
| IR-03: a mistyped quarantine root ends in a final `INTEGRITY_FAILED` | Low | Yes, for `promote` and for `reconcile` (and `rescan` strands the delivery in `SEALING`) | **Documented, not changed.** No reliable preflight exists without persisting the root's identity, which is a new contract (section 3) | [TM-41](threat-model.md); README "Run the lab locally"; C-11 |
| IR-04: the settings file and the key set get no owner, mode or link check | Low | Yes: both at mode 0666 are accepted and `serve` starts | **Fixed** in the loader, on the descriptor that is read | `settings._read_bounded`; [TM-29](threat-model.md); C-22 |
| IR-05: the file-type gate is decoupled from the download's name | Low | Yes: a PNG signature named `shot-031.html` is accepted and downloaded under that name | **Documented, not changed.** The download is an octet-stream that a browser is told not to sniff and is offered as an attachment; no cross-site scripting exists or is claimed | [TM-40](threat-model.md); C-6 |
| IR-06 (M4-10): the shared verdict cache is a cross-production confirmation oracle | Low | Not re-run | **Unchanged.** Accepted and documented | [TM-34](threat-model.md) |
| IR-07: the cache ignores a newer `detection` for the same key | Informational | Not run (no reachable case with the synthetic scanner) | Not changed; outside this pass | n/a |
| IR-08: change detection depends on timestamp granularity | Informational | Not run (needs a coarse-timestamp filesystem; Linux is unverified) | Not changed. A precondition for any future Linux claim | n/a |
| IR-09: `seed-demo` writes engagements with no audit event | Informational | Yes (documented as A-M4) | **Wording qualified**: the one-event claim is about the audited decisions | README; C-13 |
| IR-10: unauthenticated requests take the writer lock | Informational | Not re-run | Unchanged (denial of service, out of scope; TM-35) | [TM-35](threat-model.md) |
| IR-11: the F-06 demonstration understates the coordinator path | Reported as the most important | Yes (the reviewer's script, run against this tree, then rebuilt as a lab scenario) | **Demonstration strengthened** with the same single seam; the finding page, the README and the claims corrected | [F-06](findings/F-06-authorisation-snapshot-in-a-long-lived-token.md); C-26; C-28 |
| IR-12: provenance of `httpx2` | Informational | Not examined (needs the network) | Unchanged | n/a |

## 2. What changed in `src/`

Three small changes, each preceded by failing tests.

- **`settings._read_bounded`** opens the file once with `O_NOFOLLOW` and `O_NONBLOCK`, and judges the descriptor it read from: a
  regular file, owned by the effective user, not writable by its group or by others. The bytes that are read are the bytes that
  were judged, whatever happens to the name afterwards, so there is no gap between a check and a use, and a FIFO can no longer
  hang the loader. The check is in the loader, so it covers `serve` and `seed-demo` before they bind or write anything. Read
  permission is not examined: public keys are not secret, and what matters is that nobody else can change them. The directories
  above the files are not examined (the same assumption the runner makes for every other configured path).
- **`app.check_separate_roots`** is the existing rule of `Dependencies`, moved into one function with one addition: it now
  also compares directories by identity, which catches letter-case aliases on a case-insensitive filesystem (macOS by default).
  `Dependencies` calls it, and the runner calls the same function for `init`, `promote` and `reconcile` before taking a lock or
  touching the database. A rejected pair creates no asset, performs no recovery and changes no delivery.
- **`runner.py`** wires the two checks in (`check_roots`, and `_ready` for the commands given both roots).

## 3. IR-03: the decision, and why

M0 and AM-25 (A-K3) decide that a source file that is missing, a link or not a regular file is an integrity failure, and
`tests/test_promotion.py` pins it. A preflight before P1 could reject a mistyped root only by treating "the delivery's file is
not in this directory" as a configuration error, and that is exactly what a genuinely deleted file looks like too. Of the
candidates:

- **Refuse when the file is not at the root.** Reliable as an observation, but it would change M0's answer for genuinely missing
  content from a final `INTEGRITY_FAILED` with an audit event to a silent refusal that leaves the delivery `ACCEPTED`.
- **Refuse when the root does not look like the lab's** (it has no `.incoming`, holds none of the keys the database names).
  A heuristic: an empty directory is a valid new root, and an attacker who deleted everything would look like a typo.
- **Persist the root's identity** (a marker file with a random id also held in the database, or the device and inode). Reliable,
  but it is a new persisted contract and a new lifecycle rule for a root that fails the check, which this pass was told not to
  invent.

None was added. The risk is operational and is documented where an operator will read it (README "Run the lab locally", with
the check to make before a job: read the delivery's storage key from the database and look for it in the root you are about to
name). `tests/test_runner_maintenance.py` has two tests that state the behaviour so that any later change to it is deliberate.
`rescan` gets the same exposure in a milder form (the delivery stays in `SEALING`, A-J7).

## 4. IR-05: what was verified

The actual download headers for the PNG-signature, `.html`-name case are `Content-Type: application/octet-stream`,
`X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and `Content-Disposition: attachment; filename="shot-031.html"; filename*=UTF-8''shot-031.html`. A
browser is not offered the bytes to interpret, so no active-content or cross-site-scripting claim is made and none was found.
What remains is a misleading display name: the vendor chooses the extension the recipient's system will use to pick a program,
the gate compares only the leading signature, and the coordinator's inspection does not show the name. M0 section 5 named an
extension allowlist beside the signature allowlist (ASVS 5.2.2); only the signature half was built. The supported media-type
contract was not changed. Two tests pin the headers and the inspection response.

## 5. IR-11: the F-06 coordinator path

Reproduced with the reviewer's script and again as a lab scenario. A coordinator is revoked while its token is still good. With
that token, under the seeded function for that one request, it makes a 90-day ALPHA coordinator engagement for another
subject. With the reference back in force the old token is refused while it is good and is a 401 once it has expired, and the
other subject, on a fresh token, is a coordinator of ALPHA by the database's own record and reads ALPHA's unreleased asset. The
window is at most ten minutes; the grant it leaves is up to ninety days. The reference was not changed to make this work. The
only addition outside the finding's own files is `labs.seam.restored`, which puts the reference function back for the
follow-up steps and installs nothing else. The vendor and the coordinator cases are separated in the finding page, the README
and claim C-26, and the severity is stated for both roles. The owner accepted both severity judgements on 2026-11-09, with the
coordinator path put first for F-06, and F-03 stated as a scan-boundary bypass whose trusted-storage impact the independent
promotion control prevents, with no rating for a system that lacks that control.

## 6. Evidence

Any change to `src/`, `labs/` or `tests/` means the FINAL evidence in `docs/evidence/` no longer describes the code in the
checkout, and `python tools/check_docs.py --final` will say so once the change is committed. This pass regenerated **two** files
so that the finding page quotes real output, and they say `PROVISIONAL`: `f06.txt` and `f06-matrix.txt` (their content
changed). The other seven (`f02.txt`, `f03.txt`, `f04.txt`, `f02-matrix.txt`, `f03-matrix.txt`, `f04-matrix.txt`,
`summary.txt`) are byte-for-byte what they were; they still name the older commit `7f90139` and are stale as FINAL evidence
for the changed tree. Regenerate all nine from a clean committed tree (`python -m labs --evidence docs/evidence` and
`python -m labs.matrix --evidence docs/evidence`) after the implementation is committed, then run `check_docs.py --final`.

## 7. Not applied

The reviewer's proposed wording for claim C-24 (the mutable trusted filesystem), the REVIEW-PACKAGE section 6 qualification and
a future Linux note were outside the corrections the owner listed and were left for a later decision. M4-01 stays open and
acceptance withdrawal was not added. No optional finding was created.

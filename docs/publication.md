# Publication record (M5)

What the publication step (M0 section 9, M5) asked for, what was done, and what is still open.
**Published to GitHub `main` on 2026-11-09.** The owner approved the push in writing. Commit `947358b` (now `bf9e215`; section 6, item 7) was pushed to `main` as a
normal fast-forward from `fb8be8e` (33 commits, no merge, no force, no tag); the development branch name was not published.
No release has been made. Later the same day the history was rewritten to remove one commit trailer and `main` was force-pushed
(section 6, item 7), and after that the repository was deleted and recreated with the same history (section 6, item 8). The first
repository of this name was public from 2026-11-03, the recreated one from 2026-11-09, and its description was set at publication
(section 6, item 5). Sections 1 to 4 describe the checks made before the push, as they stood on that day; section 5 is the
register of what is settled and what is still open, with who resolves each item; section 6 says what was done for the evidence,
the audit and the publication.

## 1. The deliverables

| M0 deliverable | State | Where |
|---|---|---|
| The final README and finding pages | Done. The README follows M0 section 8: purpose, the three questions, a diagram with the finding tags, the findings table with links to the twin, the fix, the tests and the evidence, a quick start with its expected last line, the implemented/simulated/conceptual table, a card per finding, trade-offs and limits. Each finding page quotes its results and its matrix from the evidence files, and the checker verifies that | [README.md](../README.md), [docs/findings/](findings/F-02-object-access-checks-the-parent.md) |
| A CI workflow | Done, and it has run once on GitHub (section 6, item 5): it passed. One job on macOS arm64, because the lock is verified for that platform only. A guard test holds what the file may say | [ci.yml](../.github/workflows/ci.yml), [test_workflow.py](../tests/guards/test_workflow.py) |
| LICENSE and SECURITY.md | Done. The owner confirmed the licences on 2026-11-09 (section 5). SECURITY.md separates "report a bug in the reference" from "this is intentional", and the private reporting channel it names is enabled | [LICENSE](../LICENSE), [SECURITY.md](../SECURITY.md) |
| A fresh-clone reproduction on macOS and Linux | macOS done; Linux not done (section 3) | section 3 |
| A naming and trademark sweep | Done (section 4), with its limits | section 4 |
| The link and snippet checker (M0 section 7) | Done | [tools/check_docs.py](../tools/check_docs.py), [test_check_docs.py](../tests/test_check_docs.py) |
| Evidence regenerated from a clean tree (Addendum A11) | Done at M5, redone after the corrections of AM-32, and redone once more after the publication corrections (section 6, items 2, 4 and 6). Each round is two commits: the change, which carries evidence that is `PROVISIONAL` or stale because the commit it describes did not exist when the evidence was made; and after it a commit that changes nothing but the files of `docs/evidence/`, holding the evidence regenerated from the first commit: `FINAL`, and naming it | [docs/evidence/](evidence/summary.txt) |

## 2. The acceptance criteria

| Criterion | Result |
|---|---|
| The link and snippet checker passes | `python tools/check_docs.py` reports no problem. It follows every relative link and anchor, compares the four snippets in the README with their source and the 16 evidence blocks of the README, the walkthrough and the finding pages with their evidence files. `--final` also requires the evidence to be marked `FINAL` and to name a commit in the history whose `src/`, `labs/`, `tests/`, `requirements.lock` and `pyproject.toml` are those of HEAD; that commit need not be HEAD, so evidence can be committed after the commit it describes (section 6) |
| A cold reader can state the project's purpose and the findings in about 90 seconds | **Not shown.** The part of the README above its quick start (the purpose, the three questions, the diagram and the findings table) is short enough for that, and a test keeps it short, but no person who has not seen the project has read it. That is a measure of length and not of understanding |
| Nothing is pushed or published without approval | Met. The first push (`947358b`, now `bf9e215`, to `main`, 2026-11-09), the second push, the force push of the rewritten history and the recreation of the repository (section 6, items 6 to 8) were each made on the owner's explicit written approval; each later push needs its own |

## 3. The fresh-clone reproduction

**macOS arm64, CPython 3.13.7: done.** A clone of the committed project (`dd4c006`) was made, the M5 working tree was laid over it
and committed in that scratch clone only (the real repository was not touched), and the documented commands were run there, in a
new virtual environment built by the README's three commands. On 2026-11-05:

- 25 packages were installed by hash, and `pip check` was clean.
- `python -m labs` ended with the summary line, and `python -m labs.matrix` reported all 15 variant rows as expected.
- The ordinary suite with `-W error`, the guards, the findings, and the opt-in `clean_env`, `real_server` and `packaging` runs
  passed. The one failure in the first run was this record's own unfinished placeholders, which a test caught.
- Evidence regenerated in the clone was `FINAL` and named the scratch commit; `check_docs.py` and `check_docs.py --final`
  reported no problem; and every regenerated evidence body equalled the body in the working tree (only the date, commit and
  status lines differ).
- The block in section 5 of the [walkthrough](walkthrough.md), extracted from the page and run as written, took a delivery from
  declaration to a download that equalled the upload, with one audit row per decision. A vendor of the other production got
  the same 403 and the same audit row (`access.denied`, `no_engagement`) for the first production as for one that does not exist.

The scratch snapshot did not contain this section.

**Linux: not done.** Docker is installed on this machine, but it holds other projects' images and no Python image, so a Linux run
would have meant pulling an image from a registry or borrowing another project's, and neither was authorised. A run would also
be refused at the hash check: `requirements.lock` holds the hashes of macOS arm64 wheels for the three packages that ship
compiled code (`cryptography`, `cffi`, `pydantic_core`), so Linux needs its own hash-pinned lock, which is a change to the
dependency lock and needs your approval of the exact artefacts. The workflow therefore has no Linux job, and no sentence in the
README, the walkthrough or the lock claims Linux, and nothing here is cross-platform verified. The steps to finish it are
prepared below and have not been run.

### Linux reproduction steps (prepared, not run)

You need a Linux host you control (x86_64 or aarch64, glibc), CPython 3.13.x with `venv`, `git` and access to PyPI.

**What is expected to fail, and why.** Only three of the 25 locked wheels are platform-specific; their `WHEEL` files in the
macOS environment say `cffi 2.1.1` is `cp313-cp313-macosx_11_0_arm64`, `cryptography 50.0.2` is
`cp311-abi3-macosx_11_0_arm64` and `pydantic_core 2.46.4` is `cp313-cp313-macosx_11_0_arm64`. The other 22 are
`py3-none-any` wheels, whose hashes do not depend on the platform. Each lock entry holds one hash, so on Linux pip would pick
a Linux wheel of those three, find its hash is not in the lock, and refuse it (`THESE PACKAGES DO NOT MATCH THE HASHES`).

1. Clone the repository, check out the commit under test, and make an environment:
   `python3.13 -m venv .venv`, then `.venv/bin/python -m pip install --upgrade pip` (26.2 or later; see
   [static-analysis.md](review/static-analysis.md) TF-12).
2. Run the documented install, `.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock`.
   Expected today: refused at the hash check for `cffi`, `cryptography` and `pydantic_core`. That refusal is the check working,
   and is the evidence that Linux needs its own lock.
3. Make a candidate lock, which needs your approval before it is used or merged. In an empty directory run
   `python -m pip download --only-binary=:all: --no-deps -d wheels cffi==2.1.1 cryptography==50.0.2 pydantic_core==2.46.4`,
   then `python -m pip hash wheels/*.whl`, and compare each digest with the SHA-256 that PyPI publishes for that file name
   (`https://pypi.org/pypi/<name>/<version>/json`, field `digests.sha256`), as was done for the two packages added at M1M.
4. Choose one of two shapes, and approve it: a separate file (for example `requirements-linux-x86_64.lock`) made of the 22
   unchanged entries and the three new hashes, which changes no existing pin; or a second `--hash` on the three entries of
   `requirements.lock`, which gives one lock for both platforms but changes the lock, its header comment and what
   `tests/test_environment.py` must accept. Each architecture and C library (manylinux x86_64, manylinux aarch64, musllinux)
   has different files and hashes, and CPython 3.12 would need `cp312` files of `cffi` and `pydantic_core`.
5. With an approved lock: install it, `pip install --no-deps -e .`, `pip check`, then run what the macOS run ran:
   `python -m pytest -q -W error`, `python -m pytest -q -m clean_env`, `-m real_server`, `-m packaging`, `python -m labs`,
   `python -m labs.matrix` and `python tools/check_docs.py`.
6. Keep the failures as well as the passes. These differ between macOS and Linux and no run has examined them here: hard
   links, `O_NOFOLLOW`, `O_DIRECTORY` and inode comparison in the no-clobber placement and the root checks, `flock` between
   the lab's processes, the length limit of a UNIX-domain socket path (104 bytes on macOS, 108 on Linux) in the tests that
   use one, case-sensitive file names, the default umask, and the SQLite version.
7. Only a passing Linux run allows a sentence about Linux in the README and a Linux job in the workflow. Until then neither
   exists.

## 4. The naming and trademark sweep

- **The name.** A web search for "Content Boundary Lab" found no project, product or company of that name; it found a phrase in
  an unrelated pull-request review tool's release notes ("third-party content boundary") and unrelated "content lab"
  organisations. A search of a trademark register was **not** made, and this is not a clearance: if the name matters to you
  legally, check a register before publishing.
- **Names of others in the repository.** A search of the tracked files for the names of studios, streaming services, standards
  programmes and cloud and identity products found only MovieLabs and its CSAP specification (named as the source of an
  analogy, in the architecture and references), and the open-source dependencies and standards the references list
  (FastAPI, Starlette, PyJWT, `cryptography`, `uvicorn`, SQLite, OWASP, MITRE CWE). They are named to say what they are. The
  README, the references and the licence section say the lab is independent and not affiliated with, endorsed by or
  sponsored by any of them. No logo, wordmark or text of any of them is reproduced.
- **People and data.** All identities, content and keys in the repository are synthetic. The secret scan of M4 found no
  private key or credential in the tracked files, the history or the built distributions (it is repeated in section 6).
- **Quoted standards text.** The documents cite requirement and weakness numbers and paraphrase them in a few words; they do
  not reproduce the text of OWASP ASVS (CC BY-SA 4.0) or of the MITRE CWE catalogue. The retrieval dates are in
  [references.md](references.md).
- **Licence provenance (2026-11-09).** A technical review, made by searching the tracked files and the history, and not a legal
  certification of ownership. It found no licence header, copied or vendored source, or third-party asset (every tracked file
  is text, and no file was ever deleted from the history); no employer or client name, data or code (the scenario uses
  `.example` domains and fictional production names); and no reproduction of the MovieLabs CSAP document, which is cited and
  paraphrased only. The 25 locked packages declare permissive licences (MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, PSF-2.0, and
  Apache-2.0 or BSD for `cryptography` and `packaging`); none is copyleft, and none is bundled in the wheel or the source
  distribution, so each keeps its own licence. `httpx2` and `httpcore2` are the `pydantic/httpx2` project (BSD-3-Clause),
  checked on PyPI and GitHub. Not done: a licence scanner, a read of each dependency's licence file, and a legal review. The
  licence of the generated output, and whether purely machine-generated text attracts copyright, depend on the law and on the
  terms the owner accepted; this record does not decide either.

## 5. The register of what is settled and what is still open

None of these is solved by a code change. **Settled** means the owner decided it on 2026-11-09; everything else is open and is
not claimed anywhere as done. "Resolves" is who has to act.

| Item | State today | What the repository says about it | Resolves |
|---|---|---|---|
| **Linux reproduction** (M0 required it) | **Outstanding.** Only macOS arm64, CPython 3.13.7, was run. The lock holds macOS arm64 hashes for `cffi`, `cryptography` and `pydantic_core`, so a Linux install by hash is refused | Not cross-platform verified; the README, claims register and threat model say one tested platform. Exact steps and the lock adjustments that may be needed are in section 3 | You: approve a Linux lock (the exact artefacts) and a Linux host, a VM or an image pull |
| **Licence (D8)** | **Settled.** The owner approved MIT for the code (`LICENSE`, `Copyright (c) 2026 outsidethecode`) and CC BY 4.0 for the documents, with `outsidethecode` as the publishing and copyright identity, and stated that they have the rights to publish and that no employer or client holds rights in the work. `outsidethecode` is a handle, not a legal name, and this record cannot verify ownership; the claims register makes no claim about it. The project name is not cleared (see Name check) | A technical provenance review on 2026-11-09 (not a legal certification, and no licence scanner was run) found no copied or vendored third-party source, no third-party asset, no employer or client material, and no copyleft dependency among the 25 locked packages (declared metadata; nothing is bundled). Section 4 has the details | Done; the owner can change the holder name later |
| **GitHub workflow** | **Ran once and passed (2026-11-09).** The run in this repository, on the push of `02b387d` at its recreation (section 6, item 8; two earlier runs in the deleted first repository had the same result), used the `macos-26-arm64` image and CPython 3.13.17 and passed every step (section 6, item 5). A guard test also reads its text (SHA-pinned actions, read-only token, no `pull_request_target`, no event data in a script, the locked install by hash). It is one run on one runner, on a newer patch release than the 3.13.7 of the local runs; nothing is shown for a pull-request run, for Linux or for Python 3.12 | The README and C-30 say one run, on one platform; a local run is not described as a CI result | You: read the next runs; the next push will start one |
| **Private vulnerability reporting** | **Enabled on 2026-11-09 and read back as enabled through the GitHub API; enabled again when the repository was recreated (section 6, item 8).** It is a repository setting. No test report has been sent, so that the channel delivers a report to the owner is not shown | SECURITY.md names it as the way to report, and no document says more than that it is switched on | You, if you want it shown: send yourself a test report |
| **History (D9)** | **Settled (Option A).** The root commit's author address (the only commit whose author address is not the noreply address) is on a company domain, and the repository was public from 2026-11-03, before this push. The owner decided on 2026-11-09 to keep it | The root commit was never rewritten, and the recreated repository holds it unchanged; the commits after it were rewritten for another reason (section 6, item 7). A first repository holding the same root commit was public from 2026-11-03 until it was deleted on 2026-11-09, and copies made in that time are outside the owner's control | Done. Rewriting later would change every commit hash and break the commit references in these documents |
| **Human reviewer (D10)** | **D10 is still pending.** No human has read the code or the claims | The three AI reviews in [review/](review/m4-findings.md) are internal checks by the author's own model family; the README, claims register and M4 register say so | You: find a reviewer; [REVIEW-PACKAGE.md](review/REVIEW-PACKAGE.md) is written for one who has not seen the project |
| **Cold read** | **Not shown.** The part of the README above the quick start is about 310 words and a test keeps it at 360 or fewer, which is compatible with a quick introduction | A measure of length, not of understanding; no one who had not seen the project has read it | A person who has not seen the project, with a clock |
| **Name check** | **Not a clearance.** A web search found no project of the same name; no trademark register was searched | Section 4 says so | You, if the name matters legally |
| **Python 3.12** | Not verified, for the same reason as Linux | README: one tested platform | You, with the Linux lock |

Settled in M5 and unchanged: the evidence (section 6), the repeated dependency audit and secret scan (section 6), and
M4-01, which stays a documented medium-severity limitation that is open ([m4-findings.md](review/m4-findings.md), TM-38).

## 6. What was done for the evidence and the audit, and what comes next

1. **Implementation commit.** The M5 files were committed locally after the review of 2026-11-05. Its evidence is
   `PROVISIONAL`, which `check_docs.py` reports as a note.
2. **Evidence commit.** From a clean checkout of that commit, `python -m labs --evidence docs/evidence` and
   `python -m labs.matrix --evidence docs/evidence` regenerated the nine evidence files. They say `FINAL`, carry the date,
   command, Python and pins, and name the implementation commit as the tested source revision. They cannot name the evidence
   commit itself (its hash does not exist until it is made), and `python tools/check_docs.py --final` accepts that: it
   requires the named commit to be in the history and `src/`, `labs/`, `tests/`, `requirements.lock` and `pyproject.toml` to be
   those of that commit, not for it to be HEAD. The evidence commit changed only files in `docs/evidence/`.
3. **The audit, repeated on 2026-11-05** on the same tree as the implementation commit ([static-analysis.md](review/static-analysis.md)
   section 7): `pip-audit` found no known vulnerability in the 25 locked distributions or the pinned build backend (the
   `pip` in the test environment has the six advisories already recorded as TF-12), the secret scan found nothing new in 153
   files or in the 28 commits that existed before the M5 commit (all refs), and the built wheel and source distribution contain no `labs/`, no vulnerable
   module and no key or database file.
4. **Evidence after AM-32 (2026-11-09).** Corrections were made to `src/`, `labs/` and `tests/` after the evidence commit
   above ([fresh-assessment-followup.md](fresh-assessment-followup.md)), so the `FINAL` files of step 2 described the tree
   they were made from and not the corrected code. The AM-32 implementation commit carries all nine files as `PROVISIONAL`,
   because they were regenerated from its uncommitted tree. The evidence commit after it regenerates all nine from that clean
   implementation commit, names it as the tested source revision and says `FINAL`; `check_docs.py --final` accepts them on
   the same terms as step 2, and that commit changes only files in `docs/evidence/`. `pip-audit` and the full secret scan
   above were not repeated for AM-32 (the lock, the workflow and the build are unchanged). A text search of the tracked files
   for local paths, personal addresses and key markers was repeated on 2026-11-09: its one hit is a probe string in a test
   that checks the audit output contains no path.
5. **First publication (2026-11-09; hashes as they were then, mapped in item 7).** With the owner's explicit written approval, after the checks of that day (the working tree
   was clean at `947358b`; remote `main` was still `fb8be8e`, an ancestor of it; 33 commits, no merge, no tag), `947358b` was
   pushed to `main` as a normal fast-forward. Afterwards the remote held `main` and nothing else, and the repository description
   was set. The push started the workflow's first run (GitHub Actions, event `push`, job `tests`, 3 minutes 38 seconds): image
   `macos-26-arm64`, CPython 3.13.17 from `actions/setup-python`, the locked install by hash, then 4063 tests passed in the
   ordinary run (27 deselected) and 1, 24 and 2 in the `clean_env`, `real_server` and `packaging` runs, `python -m labs` ended
   with its summary line, `python -m labs.matrix` ran, `check_docs.py` reported 0 problems (without `--final`), and `pip check`
   was clean. That is a result on a newer patch release than the local runs and on one runner image.
6. **Corrections after the push.** The statements that said nothing was pushed or that the workflow had never run, and the
   licence rows that called the licence a default, were corrected in the README, this record, the claims register (C-30), the
   threat model (TM-39), the workflow's header comment and the docstring of the workflow guard test. In
   `tests/test_docs.py` the test of this record now asserts the published state, keeps its earlier checks (no placeholder,
   D10 still pending) and adds two (the old sentence is gone, and the licence is no longer called provisional). No assertion
   was removed or loosened. `tests/` is part of what the evidence describes, so the nine evidence files were regenerated from
   the clean commit that holds these changes and committed after it; `check_docs.py --final` accepts them on the terms of
   step 2. `pip-audit` has not been repeated since 2026-11-05, so an advisory published after that date is not covered.
   These two commits (then `7a149be` and `f1b4d88`) were pushed as the second push, a normal fast-forward of `main` from
   `947358b`, on the owner's written approval. Its Actions run passed in 3 minutes 2 seconds on the same image and Python, with
   the same steps and results (4063, 1, 24 and 2 tests passed; `check_docs.py` 0 problems; `pip check` clean).
7. **History rewritten (2026-11-09).** GitHub listed the Claude account as a contributor, because 35 of the 36 commits ended with a
   `Co-Authored-By: Claude` trailer. At the owner's request the trailer was removed from the commit messages. The 35 commits
   after the root were rewritten with identical trees, authors, committers and dates; only the message changed (the trailer
   line, and a commit hash cited in a message was followed to the rewritten commit). The root commit `fb8be8e` is unchanged, so
   the decision to keep its author address (section 5, D9) is unaffected. Every other hash changed: `947358b` is now `bf9e215`,
   `7a149be` is `dbcd095`, and the old tip `f1b4d88` is `de8df9a`, where the rewrite ended. The commit hashes cited in these
   documents were updated to the new ones in the commit after it, and the nine evidence files were regenerated from the clean
   commit that follows. The owner approved the force push that replaced `main`. Item 8 says what happened to the
   repository afterwards. These documents still say that the implementation was written with an AI model; only the trailer was removed.
8. **Repository recreated (2026-11-09).** After the force push the Contributors panel still listed the Claude account, and the old
   commits still resolved by their hashes. The owner deleted the repository in the hosting service's settings and asked for it to
   be recreated under the same name. It was created public and empty with the same description, and the history was pushed
   unchanged (tip `02b387d`, 38 commits, root `fb8be8e`) as an ordinary first push: no force, no tag, and `main` is the only
   branch. Private vulnerability reporting was switched on again, and secret scanning, push protection and the read-only workflow
   token were found as before. The first repository's three Actions runs and its commit pages are gone: the old hashes
   (`f1b4d88`, `947358b` and `7a149be` were tried) no longer resolve, and the Contributors panel lists only `outsidethecode`.
   The first run of the new repository, on `02b387d`, passed in 3 minutes 19 seconds on `macos-26-arm64` with CPython 3.13.17:
   4063 tests passed in the ordinary run (27 deselected) and 1, 24 and 2 in the `clean_env`, `real_server` and `packaging`
   runs, `python -m labs` reproduced the four exploits, `python -m labs.matrix` reported every variant failing exactly its
   expected rows, `check_docs.py` reported 0 problems (without `--final`) and `pip check` was clean. Clones and archives made
   while the first repository was public (2026-11-03 to 2026-11-09) are outside this record's reach, and none was checked.
9. **Next, all yours:** the open items of section 5, and each later push with your explicit approval.

"""The documentation is held to what the code and the tests are (M0 §6 M1L: every threat row maps to a control and a test,
or to "out of scope"; M0 §5.3: the vocabulary is checked; the README contract: a claim without a test is deleted).

Standard library only. These tests read the documents as text and check them against the repository:

- every relative link resolves, and every code block fence is closed;
- every test a document cites exists, as a test function in the file it names;
- every row of the threat model and of the claims register has what it must have, and none of the rows of M0 §3 is lost;
- the lifecycle and the route table in the architecture are the ones the schema and the application have;
- the words the lab promises not to use are not used, in the README, the documents, the OpenAPI schema or any closed
  vocabulary of the code.

They cannot show that a cited test shows what its row says it does; that is for a reader. They show that nothing the
documents point at has gone away.
"""

import argparse
import ast
import json
import re
from pathlib import Path

import pytest
from support.http_lab import make_lab
from support.scanners import CountingScanner

from content_boundary_lab import audit, runner, scanner, store

ROOT = Path(__file__).resolve().parents[1]
FINDING_PAGES = sorted((ROOT / "docs" / "findings").glob("F-*.md"))  # M2: one page per seeded finding
EVIDENCE = sorted((ROOT / "docs" / "evidence").glob("f??.txt"))  # one run of a scenario against both variants
MATRIX_EVIDENCE = sorted((ROOT / "docs" / "evidence").glob("f??-matrix.txt"))  # M3: one remediation matrix
REVIEW_PAGES = sorted((ROOT / "docs" / "review").glob("*.md"))  # M4: the review package, the scan report, the audit, the register
LABS_README = ROOT / "labs" / "README.md"
DOCS = [ROOT / "docs" / name for name in ("architecture.md", "threat-model.md", "references.md", "claims.md")] + FINDING_PAGES + REVIEW_PAGES
README = ROOT / "README.md"
PAGES = [README, LABS_README, *DOCS]
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
CLAIMS = ROOT / "docs" / "claims.md"
ARCHITECTURE = ROOT / "docs" / "architecture.md"
M0 = ROOT / "docs" / "milestones" / "M0.md"

CITED_TEST = re.compile(r"tests/[\w/]+\.py::(\w+)")
LINK = re.compile(r"\]\(([^)\s]+)\)")
BANNED = re.compile(r"\b(secure|safe|protected|production-ready)\b", re.IGNORECASE)
# M0 Addendum §5.3 prescribes this sentence for the README verbatim. It names the words to deny that they apply.
README_SENTENCE = "The lab's scanner detects one synthetic marker. It provides no malware protection, and `no_detection` says nothing about whether a file is safe."


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def rows(path: Path, prefix: str) -> list[list[str]]:
    """The cells of every table row whose first cell starts with `prefix`."""
    found = []
    for line in text(path).splitlines():
        if line.startswith(f"| {prefix}"):
            found.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return found


_FUNCTIONS: dict[Path, set[str]] = {}


def functions_defined(relative: str) -> set[str]:
    path = ROOT / relative
    if path not in _FUNCTIONS:
        tree = ast.parse(text(path))
        _FUNCTIONS[path] = {node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")}
    return _FUNCTIONS[path]


def cited(cell: str) -> list[tuple[str, str]]:
    return [(match.group(0).split("::")[0], match.group(1)) for match in CITED_TEST.finditer(cell)]


def missing(citations: list[tuple[str, str]]) -> list[str]:
    return [f"{file}::{name}" for file, name in citations if not (ROOT / file).is_file() or name not in functions_defined(file)]


# --- links and fences ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_every_relative_link_resolves(page):
    broken = []
    for target in LINK.findall(text(page)):
        if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            continue  # an external link or an anchor in the same page
        if not (page.parent / target.split("#")[0]).exists():
            broken.append(target)
    assert broken == []


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_every_code_fence_is_closed(page):
    assert sum(1 for line in text(page).splitlines() if line.startswith("```")) % 2 == 0


@pytest.mark.parametrize("page", DOCS, ids=lambda page: page.name)
def test_every_test_a_document_cites_exists(page):
    assert missing(cited(text(page))) == []


def test_the_readme_points_at_the_register_and_the_other_documents():
    page = text(README)
    for name in ("docs/architecture.md", "docs/threat-model.md", "docs/claims.md", "docs/references.md", "docs/decisions.md"):
        assert f"]({name})" in page
    assert README_SENTENCE in page


# --- the threat model --------------------------------------------------------------------------------------------------------


def test_the_threat_rows_are_numbered_once_each_in_order():
    ids = [row[0] for row in rows(THREAT_MODEL, "TM-")]
    assert ids == [f"TM-{number}" for number in range(1, len(ids) + 1)] and len(ids) >= 27


def test_every_implemented_threat_row_cites_a_control_and_tests_that_exist():
    problems = []
    for row in rows(THREAT_MODEL, "TM-"):
        assert len(row) == 8, row[0]
        identifier, boundary, threat, attacker, control, tests, finding, status = row
        found = cited(tests)
        if status not in {"Implemented", "Limitation", "Out of scope"}:
            problems.append(f"{identifier}: status {status!r}")
        if len(control) < 20:
            problems.append(f"{identifier}: no control, or no statement of what is done")
        if status == "Implemented" and not found:
            problems.append(f"{identifier}: an implemented control with no test")
        problems += [f"{identifier}: {name} does not exist" for name in missing(found)]
    assert problems == []


def test_the_threat_model_keeps_every_row_of_the_design():
    """M0 §3 lists nine threats; the threat model may add rows and may not drop or reword one."""
    lines = text(M0).splitlines()
    header = next(i for i, line in enumerate(lines) if line.startswith("| Boundary | Threat | Attacker | Reference control | Finding |"))
    design = []
    for line in lines[header + 2 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        design.append((cells[0], cells[1]))
    assert len(design) == 9
    ours = {(row[1], row[2]) for row in rows(THREAT_MODEL, "TM-")}
    assert [pair for pair in design if pair not in ours] == []


def test_the_exclusions_of_the_design_are_listed_as_out_of_scope():
    section = text(THREAT_MODEL).split("## 5. Out of scope")[1].split("## 6.")[0].lower()
    for item in ("studio administrator", "identity provider or signing key", "infrastructure compromise", "screen capture", "denial of service", "platform operator"):
        assert item in section


# --- the claims register -----------------------------------------------------------------------------------------------------


def test_every_claim_cites_tests_that_exist():
    claims = rows(CLAIMS, "C-")
    ids = [row[0] for row in claims]
    assert ids == [f"C-{number}" for number in range(1, len(ids) + 1)] and len(ids) >= 20
    threats = {row[0] for row in rows(THREAT_MODEL, "TM-")}
    problems = []
    for identifier, claim, threat, tests in (tuple(row) for row in claims):
        found = cited(tests)
        if not found:
            problems.append(f"{identifier}: a claim with no test")
        problems += [f"{identifier}: {name} does not exist" for name in missing(found)]
        named = set(re.findall(r"TM-\d+", threat))
        if named - threats:
            problems.append(f"{identifier}: {sorted(named - threats)} is not in the threat model")
        if not named and threat not in {"n/a", "all"}:
            problems.append(f"{identifier}: names no threat")
        if len(claim) < 40:
            problems.append(f"{identifier}: too short to be a claim")
    assert problems == []


def test_the_claims_register_states_what_it_does_not_claim():
    section = text(CLAIMS).split("## 2. Claims this repository does not make")[1].lower()
    for item in ("conformance", "malware", "tamper-evident", "atomic", "durability", "performance"):
        assert item in section


# --- the architecture -------------------------------------------------------------------------------------------------------


def test_the_lifecycle_in_the_architecture_is_the_lifecycle_the_database_enforces():
    diagram = text(ARCHITECTURE).split("stateDiagram-v2")[1].split("```")[0]
    drawn = {(a, b) for a, b in re.findall(r"^\s*(\w+) --> (\w+)", diagram, re.MULTILINE) if a != "[*]" and b != "[*]"}
    enforced = {(a.value, b.value) for a, b in store.DELIVERY_TRANSITIONS}
    assert drawn == enforced and len(drawn) == 12


def test_the_route_table_in_the_architecture_is_the_set_of_routes_the_application_serves(make_lab):
    lab = make_lab("docs", CountingScanner())
    served = set()
    for route in lab.app.routes:
        if hasattr(route, "methods"):
            path = re.sub(r"\{(\w+):path\}", r"{\1}", route.path).removeprefix("/productions/{production_id}")
            served |= {(method, path or "") for method in route.methods}
    section = text(ARCHITECTURE).split("## 4.")[1].split("## 5.")[0]
    documented = set(re.findall(r"\| `([A-Z]+) (/[^`]*)`", section))
    assert documented == served and len(served) == 9


def test_the_commands_in_the_architecture_are_the_commands_the_runner_has():
    section = text(ARCHITECTURE).split("## 14.")[1]
    documented = set(re.findall(r"^\| `([a-z-]+)` \|", section, re.MULTILINE))
    # The parser is the list of commands; it is reached through its private builder on purpose, as there is no other list.
    commands = next(a for a in runner._parser()._actions if isinstance(a, argparse._SubParsersAction)).choices
    assert documented == set(commands) and len(documented) == 6


def test_every_audit_event_the_architecture_names_is_in_the_audit_vocabulary():
    names = set(re.findall(r"`(delivery\.\w+)`", text(ARCHITECTURE)))
    assert names and names <= {action.value for action in audit.AuditAction}


def test_every_system_actor_the_architecture_names_exists():
    page = text(ARCHITECTURE)
    for actor in audit.SYSTEM_ACTORS:
        assert f"`{actor.issuer}` / `{actor.subject}`" in page or f"`{actor.subject}`" in page


# --- the findings (M2) ---------------------------------------------------------------------------------------------------------

HEADINGS = (
    "Context",
    "Boundary",
    "Vulnerable code and root cause",
    "Exploitation scenario",
    "Corrected code",
    "Before and after results",
    "Residual risk and assumptions",
)
FIXED_SENTENCE = "Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system."


def test_there_is_one_page_and_one_evidence_file_for_each_of_the_four_findings():
    assert [page.name.split("-")[1] for page in FINDING_PAGES] == ["02", "03", "04", "06"]
    assert [path.name for path in EVIDENCE] == ["f02.txt", "f03.txt", "f04.txt", "f06.txt"]
    assert [path.name for path in MATRIX_EVIDENCE] == ["f02-matrix.txt", "f03-matrix.txt", "f04-matrix.txt", "f06-matrix.txt"]


@pytest.mark.parametrize("page", FINDING_PAGES, ids=lambda page: page.name[:4])
def test_a_finding_page_has_the_seven_headings_in_order_and_the_fixed_sentence(page):
    body = text(page)
    found = re.findall(r"^## \d\. (.+)$", body, re.MULTILINE)
    assert tuple(found) == HEADINGS
    assert FIXED_SENTENCE in body


@pytest.mark.parametrize("page", FINDING_PAGES, ids=lambda page: page.name[:4])
def test_a_finding_page_names_a_command_and_an_evidence_file_that_exist(page):
    body = text(page)
    command = re.search(r"`python -m (labs\.f\d\d_\w+)`", body)
    assert command and (ROOT / command.group(1).replace(".", "/") / "__main__.py").is_file()
    evidence = re.search(r"\]\(\.\./evidence/(f\d\d\.txt)\)", body)
    assert evidence and (ROOT / "docs" / "evidence" / evidence.group(1)).is_file()
    seam = re.search(r"\| Seam \| `([\w.]+)`", body).group(1)
    module, _, name = seam.partition(".")
    assert re.search(rf"^def {name}\(", text(ROOT / "src" / "content_boundary_lab" / f"{module}.py"), re.MULTILINE)  # the seam really is there


@pytest.mark.parametrize("page", FINDING_PAGES, ids=lambda page: page.name[:4])
def test_the_results_in_a_finding_page_are_lines_of_its_evidence_file(page):
    evidence_name = re.search(r"\]\(\.\./evidence/(f\d\d\.txt)\)", text(page)).group(1)
    evidence = {line for line in text(ROOT / "docs" / "evidence" / evidence_name).splitlines()}
    results = text(page).split("## 6. Before and after results")[1].split("## 7.")[0]
    block = results.split("```text")[1].split("```")[0]
    quoted = [line for line in block.splitlines() if line.strip() and line != "…"]
    assert len(quoted) >= 8 and [line for line in quoted if line not in evidence] == []


@pytest.mark.parametrize("path", [*EVIDENCE, *MATRIX_EVIDENCE], ids=lambda path: path.name)
def test_an_evidence_file_records_when_how_and_on_what_it_was_made_and_ends_with_the_result(path):
    body = text(path)
    for field in ("date     ", "command  ", "commit   ", "python   ", "pinned   ", "status   PROVISIONAL", "note     "):
        assert re.search(rf"^{field}", body, re.MULTILINE), field
    assert "pinned   fastapi==" in body and FIXED_SENTENCE in body
    ending = (
        "RESULT     every variant fails exactly the rows it is expected to: YES"
        if path in MATRIX_EVIDENCE
        else "RESULT     seeded variant exploited: YES   reference blocked: YES"
    )
    assert body.rstrip().endswith(ending)


@pytest.mark.parametrize("page", FINDING_PAGES, ids=lambda page: page.name[:4])
def test_the_matrix_in_a_finding_page_is_lines_of_its_matrix_evidence_and_names_the_naive_fix(page):
    body = text(page)
    number = re.search(r"\]\(\.\./evidence/(f\d\d)\.txt\)", body).group(1)
    evidence = set(text(ROOT / "docs" / "evidence" / f"{number}-matrix.txt").splitlines())
    corrected = body.split("## 5. Corrected code")[1].split("## 6.")[0]
    assert "### Remediation matrix" in corrected and f"{number}-matrix.txt" in corrected
    quoted = [line for line in corrected.split("```text")[1].split("```")[0].splitlines() if line.strip()]
    assert len(quoted) >= 8 and [line for line in quoted if line not in evidence] == []
    assert re.search(r"\bN1\b", corrected) and "fails" in corrected  # a naive fix, and the rows it fails, are named


def test_the_labs_readme_lists_exactly_the_labs_that_exist_each_with_its_write_up():
    present = sorted(path.parent.name for path in (ROOT / "labs").glob("f*/vulnerable.py"))
    listed = sorted(re.findall(r"\[(f\d\d_\w+)\]\(\1/vulnerable\.py\)", text(LABS_README)))
    assert present == listed and len(present) == 4
    assert "intentionally vulnerable code. The default application does not." in text(LABS_README)


# --- the M4 review documents ---------------------------------------------------------------------------------------------------

REVIEW_DIR = ROOT / "docs" / "review"
CLAIM_CLASSES = {"Demonstrated", "Supported, subject to an assumption", "Not yet demonstrated", "Out of scope"}
SEVERITIES = {"High", "Medium", "Low", "Informational"}
TRIAGE = ("Fixed", "Accepted", "Documented")  # M0 M4: every review item is fixed, accepted with a rationale, or documented
AFFECTS = {"reference", "labs", "packaging", "tests", "docs"}


def test_the_review_folder_holds_the_package_the_review_the_scans_the_audit_and_the_register():
    names = sorted(page.name for page in REVIEW_PAGES)
    assert names == ["REVIEW-PACKAGE.md", "claims-audit.md", "fresh-context-review.md", "m4-findings.md", "static-analysis.md"]


def test_the_claims_audit_classifies_every_claim_of_the_register_exactly_once():
    section = text(REVIEW_DIR / "claims-audit.md").split("## 1. Classification")[1].split("## 2.")[0]
    classified: dict[str, list[str]] = {}
    for line in section.splitlines():
        if line.startswith("| C-"):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            assert len(cells) == 4, line[:40]
            classified.setdefault(cells[0], []).append(cells[1])
    claims = [row[0] for row in rows(CLAIMS, "C-")]
    assert sorted(classified) == sorted(claims)
    assert all(len(found) == 1 and found[0] in CLAIM_CLASSES for found in classified.values())


def test_every_finding_of_the_register_is_numbered_in_order_and_triaged_with_all_its_fields():
    register = REVIEW_DIR / "m4-findings.md"
    found = rows(register, "M4-")
    assert [row[0] for row in found] == [f"M4-{number:02d}" for number in range(1, len(found) + 1)] and len(found) >= 30
    problems = []
    for row in found:
        if len(row) != 7:
            problems.append(f"{row[0]}: {len(row)} cells")
            continue
        identifier, impact, where, evidence, affects, remediation, status = row
        if not re.match(r"\**(High|Medium|Low|Informational)\b", impact):
            problems.append(f"{identifier}: no severity")
        if not status.startswith(TRIAGE):
            problems.append(f"{identifier}: not triaged ({status!r})")
        if not all(len(cell) >= 5 for cell in (impact, where, evidence, remediation)):
            problems.append(f"{identifier}: an empty field")
        if not {part.strip().split(" ")[0] for part in affects.split(",")} <= AFFECTS:
            problems.append(f"{identifier}: affects {affects!r}")
        problems += [f"{identifier}: {name} does not exist" for name in missing(cited(evidence))]
    assert problems == []


def test_every_register_entry_the_other_review_documents_cite_exists():
    register = {row[0] for row in rows(REVIEW_DIR / "m4-findings.md", "M4-")}
    cited_ids = set()
    for page in REVIEW_PAGES:
        cited_ids |= set(re.findall(r"M4-\d\d", text(page)))
    assert cited_ids - register == set()


# --- the vocabulary------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.name)
def test_the_words_the_lab_promises_not_to_use_are_not_used(page):
    body = text(page).replace(README_SENTENCE, "")
    assert BANNED.findall(body) == []


def test_the_openapi_schema_and_every_closed_vocabulary_avoid_the_same_words(make_lab):
    lab = make_lab("vocabulary", CountingScanner())
    vocabulary = [json.dumps(lab.app.openapi())]
    for enum in (store.DeliveryState, audit.AuditAction, audit.AuditReason, audit.ObjectType, audit.Outcome, audit.EngineKind, scanner.Verdict):
        vocabulary += [member.value for member in enum]
    flagged = [word for word in vocabulary if BANNED.search(word) or re.search(r"\bclean\b", word, re.IGNORECASE)]
    assert flagged == []

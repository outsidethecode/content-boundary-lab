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
DOCS = [ROOT / "docs" / name for name in ("architecture.md", "threat-model.md", "references.md", "claims.md")]
README = ROOT / "README.md"
PAGES = [README, *DOCS]
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


# --- the vocabulary ------------------------------------------------------------------------------------------------------------


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

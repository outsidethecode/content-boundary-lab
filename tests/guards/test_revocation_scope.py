"""Source guard: no production module outside store.py uses the unscoped `revoke_engagement`.

`store.revoke_engagement(conn, clock, engagement_id)` names no production, so it can revoke an engagement of any
production. It stays for seeding and tests until their call sites are migrated, and request code must use
`store.revoke_engagement_in_production`, which binds the production into the same UPDATE. Like the other guards this
catches accidents and drift; it does not read dynamically built names and is not a general static analyser.
"""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "content_boundary_lab"
APPROVED = Path("store.py")  # where the function is defined
UNSCOPED = "revoke_engagement"
SCOPED = "revoke_engagement_in_production"


def _unscoped_uses(source: str) -> list[tuple[int, str]]:
    """(line, what) for each way the source can reach the unscoped function.

    Flags the name as an attribute (`store.revoke_engagement`), as a bare name, as an imported or aliased name, a star
    import from a module called store, and the name written as a string (`getattr(store, "revoke_engagement")`).
    The scoped function's name is a different identifier and is not flagged.
    """
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr == UNSCOPED:
            found.append((node.lineno, f"attribute .{UNSCOPED}"))
        elif isinstance(node, ast.Name) and node.id == UNSCOPED:
            found.append((node.lineno, f"name {UNSCOPED}"))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == UNSCOPED:
                    found.append((node.lineno, f"import of {UNSCOPED}"))
                elif alias.name == "*" and (node.module or "").split(".")[-1] == "store":
                    found.append((node.lineno, "star import from store"))
        elif isinstance(node, ast.Constant) and node.value == UNSCOPED:
            found.append((node.lineno, f"string {UNSCOPED!r}"))
    return sorted(found)


BAD_SAMPLES = {
    "attribute call": "from content_boundary_lab import store\nstore.revoke_engagement(conn, clock, eid)",
    "aliased module": "from content_boundary_lab import store as s\ns.revoke_engagement(conn, clock, eid)",
    "module path": "import content_boundary_lab.store as s\ns.revoke_engagement(conn, clock, eid)",
    "kept in a variable": "from content_boundary_lab import store\nrevoke = store.revoke_engagement",
    "from-import": "from content_boundary_lab.store import revoke_engagement",
    "from-import, aliased": "from content_boundary_lab.store import revoke_engagement as revoke",
    "relative from-import": "from .store import revoke_engagement",
    "bare call after import": "from content_boundary_lab.store import revoke_engagement\nrevoke_engagement(conn, clock, eid)",
    "star import": "from content_boundary_lab.store import *",
    "relative star import": "from .store import *",
    "getattr with the name": "from content_boundary_lab import store\ngetattr(store, 'revoke_engagement')",
    "inside a function": "def handler(store, conn, clock, eid):\n    return store.revoke_engagement(conn, clock, eid)",
}
GOOD_SAMPLES = {
    "scoped call": "from content_boundary_lab import store\nstore.revoke_engagement_in_production(conn, pid, eid, now)",
    "scoped from-import": "from content_boundary_lab.store import revoke_engagement_in_production",
    "scoped, aliased": "from content_boundary_lab.store import revoke_engagement_in_production as revoke",
    "a docstring that mentions it": 'def f():\n    """Do not use store.revoke_engagement here."""',
    "another store function": "from content_boundary_lab import store\nstore.add_engagement(conn, clock, 1, pid, 'vendor', ends)",
    "a star import from another module": "from content_boundary_lab.audit import *",
    "no store at all": "import json\n",
}


@pytest.mark.parametrize("source", BAD_SAMPLES.values(), ids=list(BAD_SAMPLES))
def test_the_guard_flags_every_way_of_reaching_the_unscoped_function(source):
    assert _unscoped_uses(source)


@pytest.mark.parametrize("source", GOOD_SAMPLES.values(), ids=list(GOOD_SAMPLES))
def test_the_guard_accepts_the_scoped_function_and_everything_else(source):
    assert _unscoped_uses(source) == []


def test_no_module_outside_the_store_uses_the_unscoped_function():
    offenders = {
        str(path.relative_to(PACKAGE)): uses
        for path in sorted(PACKAGE.rglob("*.py"))
        if path.relative_to(PACKAGE) != APPROVED and (uses := _unscoped_uses(path.read_text()))
    }
    assert offenders == {}


def test_the_guard_is_not_vacuous_it_scans_the_modules_that_matter_and_both_functions_exist():
    scanned = {path.name for path in PACKAGE.rglob("*.py")}
    assert {"store.py", "engagements.py", "request_flow.py", "authz.py", "audit.py"} <= scanned
    defined = {node.name for node in ast.walk(ast.parse((PACKAGE / APPROVED).read_text())) if isinstance(node, ast.FunctionDef)}
    assert {UNSCOPED, SCOPED} <= defined  # if the old one is removed, retire this guard knowingly

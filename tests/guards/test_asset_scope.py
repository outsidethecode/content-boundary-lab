"""Source guard: the assets table is read in one place, by the one scoped statement, and nowhere by id alone.

`assets.get_asset_in_scope` binds the asset, its real production, the requested production and the caller's current
engagement in a single SELECT. The point of the guard is that no other code in src/ can read, update or delete an asset
by its id, which is the F-02 mistake. store.py may create the table and insert rows (seeding and, later, ingest); it may
not read them. Like the other guards it catches accidents and drift; it does not read a statement built at run time.
"""

import ast
import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "content_boundary_lab"
READER = Path("assets.py")  # the only module that may read the table
WRITER = Path("store.py")  # the only module that may create it and insert into it
SQL_START = re.compile(r"\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|WITH|REPLACE|DROP|ALTER)\b", re.IGNORECASE)
NAMES_ASSETS = re.compile(r"\bassets\b", re.IGNORECASE)
# What the one reading statement must contain, so that dropping a condition fails here and not only in a test.
SCOPE = (r"\bid = \?", r"\bproduction_id = \?", r"\bissuer = \?", r"\bsubject = \?", r"revoked_at IS NULL", r"ends_at > \?")


def _statements(source: str) -> list[tuple[int, str]]:
    """(line, text) of every string in the source that is SQL naming the assets table.

    A plain string, or an f-string with its constant parts joined, counts when it starts like a statement.
    """
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr):
            text = " ".join(part.value for part in node.values if isinstance(part, ast.Constant))
        else:
            continue
        if SQL_START.match(text) and NAMES_ASSETS.search(text):
            found.append((node.lineno, " ".join(text.split())))
    return sorted(found)


def violations(relative: Path, source: str) -> list[str]:
    problems = []
    for line, text in _statements(source):
        verb = SQL_START.match(text).group(1).upper()
        if relative == WRITER:
            if verb not in {"CREATE", "INSERT"}:
                problems.append(f"{relative}:{line}: {verb} on assets outside the reading module")
        elif relative == READER:
            missing = [pattern for pattern in SCOPE if not re.search(pattern, text)]
            if verb != "SELECT" or missing:
                problems.append(f"{relative}:{line}: {verb} on assets without {missing or 'being a SELECT'}")
        else:
            problems.append(f"{relative}:{line}: SQL on assets in a module that may not touch the table")
    return problems


SCOPED = (
    "SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a "
    "JOIN engagements AS e ON e.production_id = a.production_id JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE a.id = ? AND a.production_id = ? AND s.issuer = ? AND s.subject = ? AND e.revoked_at IS NULL AND e.ends_at > ?"
)
BAD_READERS = {
    "by id alone": "SELECT id, display_name FROM assets WHERE id = ?",
    "by id after a production check": "SELECT * FROM assets WHERE id = ? AND production_id = ?",
    "without the revocation test": SCOPED.replace(" AND e.revoked_at IS NULL", ""),
    "without the end of the engagement": SCOPED.replace(" AND e.ends_at > ?", ""),
    "without the issuer": SCOPED.replace(" AND s.issuer = ?", ""),
    "an update by id": "UPDATE assets SET display_name = ? WHERE id = ?",
    "a delete": "DELETE FROM assets WHERE id = ?",
    "a statement built with an f-string": 'f"SELECT * FROM assets WHERE id = \'{asset_id}\'"',
}
GOOD_READERS = {"the scoped statement": SCOPED}


def _module(statement: str) -> str:
    return f"QUERY = {statement}\n" if statement.startswith("f") else f"QUERY = {statement!r}\n"


@pytest.mark.parametrize("statement", BAD_READERS.values(), ids=list(BAD_READERS))
def test_the_guard_flags_every_unscoped_way_to_read_an_asset(statement):
    assert violations(READER, _module(statement))  # even inside the one module allowed to read
    assert violations(Path("engagements.py"), _module(statement))  # and anywhere else


def test_the_guard_accepts_the_scoped_statement_in_the_reading_module_only():
    assert violations(READER, _module(SCOPED)) == []
    assert violations(Path("management.py"), _module(SCOPED))
    assert violations(WRITER, _module(SCOPED))  # the store may not read


@pytest.mark.parametrize(
    "statement",
    ["INSERT INTO assets (id, production_id, display_name, created_at) VALUES (?, ?, ?, ?)", "CREATE TABLE assets (id TEXT)"],
)
def test_the_store_may_create_and_insert_and_nothing_else_may(statement):
    assert violations(WRITER, _module(statement)) == []
    assert violations(READER, _module(statement))
    assert violations(Path("request_flow.py"), _module(statement))


def test_prose_that_mentions_assets_is_not_sql():
    assert violations(Path("engagements.py"), '"""Reads assets only through the reading module."""\n') == []


def test_no_module_in_src_reads_updates_or_deletes_an_asset_except_by_the_scoped_statement():
    problems = []
    for path in sorted(PACKAGE.rglob("*.py")):
        problems += violations(path.relative_to(PACKAGE), path.read_text())
    assert problems == []


def test_the_guard_is_not_vacuous_it_sees_the_reader_and_the_writer():
    assert any("FROM assets" in text for _, text in _statements((PACKAGE / READER).read_text()))
    writer_verbs = {SQL_START.match(text).group(1).upper() for _, text in _statements((PACKAGE / WRITER).read_text())}
    assert {"CREATE", "INSERT"} <= writer_verbs

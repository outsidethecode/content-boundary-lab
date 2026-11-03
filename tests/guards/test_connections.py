"""Source guard: application code opens SQLite databases only in store.py.

store.connect() checks the schema and installs the authorizer, so a connection opened anywhere else would skip both.
Like the other guards, this catches accidents and drift; it is not a general static analyser.
"""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "content_boundary_lab"
APPROVED = Path("store.py")
INTERNAL_MODULES = {"sqlite3.dbapi2", "_sqlite3"}


def _database_openings(source: str) -> list[tuple[int, str]]:
    """(line, what) for each way the source can open a SQLite database.

    Flags `connect` reached through the sqlite3 module or an alias of it (called or not), a call of `Connection`
    the same way or after `from sqlite3 import Connection`, `from sqlite3 import connect`, star imports, and any use
    of sqlite3.dbapi2 or _sqlite3. Using `sqlite3.Connection` as a type annotation is not flagged.
    """
    tree = ast.parse(source)
    modules, connection_names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {alias.asname or alias.name for alias in node.names if alias.name == "sqlite3"}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "sqlite3":
            connection_names |= {alias.asname or alias.name for alias in node.names if alias.name == "Connection"}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(node.lineno, f"import {a.name}") for a in node.names if a.name in INTERNAL_MODULES]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module in INTERNAL_MODULES:
                found.append((node.lineno, f"from {node.module} import"))
            elif node.module == "sqlite3":
                imported = [alias.name for alias in node.names if alias.name in {"connect", "dbapi2", "*"}]
                found += [(node.lineno, f"from sqlite3 import {name}") for name in imported]
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules:
            if node.attr in {"connect", "dbapi2"}:
                found.append((node.lineno, f"sqlite3.{node.attr}"))
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in modules:
                if func.attr == "Connection":
                    found.append((node.lineno, "sqlite3.Connection(...)"))
            elif isinstance(func, ast.Name) and func.id in connection_names:
                found.append((node.lineno, "Connection(...)"))
    return sorted(found)


BAD_SAMPLES = {
    "sqlite3.connect call": "import sqlite3\nsqlite3.connect('x')",
    "aliased module": "import sqlite3 as db\ndb.connect('x')",
    "connect kept in a variable": "import sqlite3\nopen_database = sqlite3.connect\n",
    "Connection constructed": "import sqlite3\nsqlite3.Connection('x')",
    "from-import of connect": "from sqlite3 import connect\n",
    "from-import of connect, aliased": "from sqlite3 import connect as open_database\n",
    "from-import of Connection, called": "from sqlite3 import Connection\nConnection('x')",
    "from-import of Connection, aliased and called": "from sqlite3 import Connection as C\nC('x')",
    "star import": "from sqlite3 import *\n",
    "dbapi2 imported": "import sqlite3.dbapi2\n",
    "dbapi2 from-imported": "from sqlite3 import dbapi2\n",
    "dbapi2 reached through the module": "import sqlite3\nsqlite3.dbapi2.connect('x')",
    "the C module": "import _sqlite3\n",
    "inside a function": "import sqlite3\ndef open_it():\n    return sqlite3.connect('x')",
}
GOOD_SAMPLES = {
    "annotation only": "import sqlite3\ndef f(conn: sqlite3.Connection) -> None: ...",
    "error and row types": "import sqlite3\nclass Failure(sqlite3.Error): ...\nfactory = sqlite3.Row",
    "Connection imported for an annotation": "from sqlite3 import Connection\ndef f(conn: Connection) -> None: ...",
    "no sqlite at all": "import json\n",
}


@pytest.mark.parametrize("source", BAD_SAMPLES.values(), ids=list(BAD_SAMPLES))
def test_the_guard_flags_every_way_of_opening_a_database(source):
    assert _database_openings(source)


@pytest.mark.parametrize("source", GOOD_SAMPLES.values(), ids=list(GOOD_SAMPLES))
def test_the_guard_accepts_code_that_only_uses_sqlite_types(source):
    assert _database_openings(source) == []


def test_only_the_store_opens_sqlite_databases():
    offenders = {
        str(path.relative_to(PACKAGE)): openings
        for path in sorted(PACKAGE.rglob("*.py"))
        if path.relative_to(PACKAGE) != APPROVED and (openings := _database_openings(path.read_text()))
    }
    assert offenders == {}


def test_the_guard_does_see_the_openings_in_the_store():
    assert _database_openings((PACKAGE / APPROVED).read_text())

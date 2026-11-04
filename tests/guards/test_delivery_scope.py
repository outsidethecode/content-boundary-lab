"""Source guards for ingest: deliveries are read and changed in two places only, and quarantine stays apart from trusted storage.

Three things are checked over src/, each against bad and good samples so that the guard is shown to fail:

1. SQL that names the deliveries table: store.py may create it and insert rows; ingest.py may read a delivery only by the
   one scoped statement (or by the two fixed reconciliation reads) and may update it only by the compare-and-set that
   names the delivery, its production, its owner and the state INITIATED. Nothing may delete or replace a row.
2. request_flow.proceed() runs a transaction without authenticating anyone, so only ingest.py may call it, and only
   after request_flow.decide() has authorised the same request.
3. Only assets.py (the trusted root) and quarantine.py (the quarantine root) open, move or delete files, and neither
   mentions the other's root. Nothing that can write quarantine can write the trusted asset root.

Like the other guards, these catch accidents and drift; they do not read a statement built at run time.
"""

import ast
import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "content_boundary_lab"
STORE, INGEST = Path("store.py"), Path("ingest.py")
SQL_START = re.compile(r"\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|WITH|REPLACE|DROP|ALTER)\b", re.IGNORECASE)
NAMES_DELIVERIES = re.compile(r"\bdeliveries\b", re.IGNORECASE)
SCOPED_READ = (r"\bd\.id = \?", r"\bd\.production_id = \?", r"\bissuer = \?", r"\bsubject = \?", r"revoked_at IS NULL", r"ends_at > \?")
COMPARE_AND_SET = (r"\bid = \?", r"\bproduction_id = \?", r"\bowner_subject_id = \?", r"\bstate = 'INITIATED'\s*$")
CHANGEABLE = {"state", "received_size", "received_sha256", "uploaded_at"}
RECONCILIATION_READS = (
    re.compile(r"SELECT state FROM deliveries WHERE storage_key = \?$"),
    re.compile(r"SELECT id, storage_key FROM deliveries WHERE state != 'INITIATED'$"),
)
FILE_OPERATIONS = {"open", "rename", "replace", "unlink", "link", "mkdir", "rmdir", "remove", "symlink", "truncate"}
PATH_METHODS = {"write_bytes", "write_text", "unlink", "rename", "rmdir", "mkdir", "touch", "symlink_to", "hardlink_to"}
FILE_MODULES = {Path("assets.py"), Path("quarantine.py")}


def _statements(source: str) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr):
            text = " ".join(part.value for part in node.values if isinstance(part, ast.Constant))
        else:
            continue
        if SQL_START.match(text) and NAMES_DELIVERIES.search(text):
            found.append((node.lineno, " ".join(text.split())))
    return sorted(found)


def sql_violations(relative: Path, source: str) -> list[str]:
    problems = []
    for line, text in _statements(source):
        verb = SQL_START.match(text).group(1).upper()
        where = f"{relative}:{line}: {verb} on deliveries"
        if relative == STORE:
            if verb not in {"CREATE", "INSERT"}:
                problems.append(f"{where} outside the reading module")
        elif relative == INGEST:
            if verb == "SELECT":
                scoped = all(re.search(pattern, text) for pattern in SCOPED_READ)
                if not scoped and not any(pattern.fullmatch(text) for pattern in RECONCILIATION_READS):
                    problems.append(f"{where} that is neither the scoped read nor a reconciliation read")
            elif verb == "UPDATE":
                assignments = re.search(r"\bSET\b(.*)\bWHERE\b", text, re.IGNORECASE | re.DOTALL)
                columns = {part.split("=")[0].strip() for part in assignments.group(1).split(",")} if assignments else {"?"}
                missing = [pattern for pattern in COMPARE_AND_SET if not re.search(pattern, text)]
                if missing or not columns <= CHANGEABLE:
                    problems.append(f"{where} that is not the compare-and-set of the receipt (missing {missing}, sets {sorted(columns - CHANGEABLE)})")
            else:
                problems.append(f"{where} in the module that may only read and compare-and-set")
        else:
            problems.append(f"{where} in a module that may not touch the table")
    return problems


SCOPED = (
    "SELECT d.id, d.production_id, d.owner_subject_id, d.storage_key, d.display_name, d.state FROM deliveries AS d "
    "JOIN engagements AS e ON e.production_id = d.production_id AND e.subject_id = d.owner_subject_id "
    "JOIN subjects AS s ON s.id = d.owner_subject_id "
    "WHERE d.id = ? AND d.production_id = ? AND s.issuer = ? AND s.subject = ? AND e.revoked_at IS NULL AND e.ends_at > ?"
)
CAS = (
    "UPDATE deliveries SET state = 'UPLOADED', received_size = ?, received_sha256 = ?, uploaded_at = ? "
    "WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = 'INITIATED'"
)
BAD = {
    "a read by id alone": "SELECT * FROM deliveries WHERE id = ?",
    "a read by id and production only": "SELECT * FROM deliveries AS d WHERE d.id = ? AND d.production_id = ?",
    "the scoped read without the revocation test": SCOPED.replace(" AND e.revoked_at IS NULL", ""),
    "the scoped read without the end of the engagement": SCOPED.replace(" AND e.ends_at > ?", ""),
    "the scoped read without the issuer": SCOPED.replace(" AND s.issuer = ?", ""),
    "a state change without the owner": CAS.replace(" AND owner_subject_id = ?", ""),
    "a state change without the production": CAS.replace(" AND production_id = ?", ""),
    "a state change from any state": CAS.replace(" AND state = 'INITIATED'", ""),
    "an update of the identity": CAS.replace("SET state = 'UPLOADED'", "SET owner_subject_id = ?, state = 'UPLOADED'"),
    "an update of the storage key": CAS.replace("SET state = 'UPLOADED'", "SET storage_key = ?, state = 'UPLOADED'"),
    "an insert outside the store": "INSERT INTO deliveries (id) VALUES (?)",
    "a delete": "DELETE FROM deliveries WHERE id = ?",
    "a replace": "INSERT OR REPLACE INTO deliveries (id) VALUES (?)",
    "a statement built with an f-string": 'f"SELECT * FROM deliveries WHERE id = \'{delivery_id}\'"',
}


def _module(statement: str) -> str:
    return f"QUERY = {statement}\n" if statement.startswith("f") else f"QUERY = {statement!r}\n"


@pytest.mark.parametrize("statement", BAD.values(), ids=list(BAD))
def test_the_guard_flags_every_unscoped_or_unconditional_way_to_touch_a_delivery(statement):
    assert sql_violations(INGEST, _module(statement))
    assert sql_violations(Path("management.py"), _module(statement))  # and no other module may touch it at all


def test_the_guard_accepts_the_two_statements_ingest_is_allowed_and_the_reconciliation_reads():
    assert sql_violations(INGEST, _module(SCOPED)) == []
    assert sql_violations(INGEST, _module(CAS)) == []
    for read in ("SELECT state FROM deliveries WHERE storage_key = ?", "SELECT id, storage_key FROM deliveries WHERE state != 'INITIATED'"):
        assert sql_violations(INGEST, _module(read)) == []
        assert sql_violations(STORE, _module(read))  # the store may not read
    assert sql_violations(Path("assets.py"), _module(SCOPED))


def test_the_store_may_create_and_insert_and_nothing_else_may():
    for statement in ("CREATE TABLE deliveries (id TEXT)", "INSERT INTO deliveries (id) VALUES (?)"):
        assert sql_violations(STORE, _module(statement)) == []
        assert sql_violations(INGEST, _module(statement))
    assert sql_violations(STORE, _module(CAS))


def test_prose_that_mentions_deliveries_is_not_sql():
    assert sql_violations(Path("management.py"), '"""Reads deliveries only through ingest."""\n') == []


def test_no_module_in_src_touches_the_deliveries_table_except_as_allowed():
    problems = []
    for path in sorted(PACKAGE.rglob("*.py")):
        problems += sql_violations(path.relative_to(PACKAGE), path.read_text())
    assert problems == []


def test_the_sql_guard_is_not_vacuous_it_sees_the_store_and_ingest():
    assert {"CREATE", "INSERT"} <= {SQL_START.match(text).group(1).upper() for _, text in _statements((PACKAGE / STORE).read_text())}
    verbs = [SQL_START.match(text).group(1).upper() for _, text in _statements((PACKAGE / INGEST).read_text())]
    assert verbs.count("SELECT") >= 3 and verbs.count("UPDATE") == 1


# --- proceed() --------------------------------------------------------------------------------------------------------


def callers_of(source: str, name: str) -> list[int]:
    return sorted(
        node.lineno
        for node in ast.walk(ast.parse(source))
        if (isinstance(node, ast.Attribute) and node.attr == name) or (isinstance(node, ast.Name) and node.id == name)
    )


@pytest.mark.parametrize(
    "source",
    ["request_flow.proceed(clock, path)", "from content_boundary_lab.request_flow import proceed\nproceed()", "p = request_flow.proceed"],
    ids=["a call", "an import and a call", "an alias"],
)
def test_the_guard_sees_every_way_of_reaching_proceed(source):
    assert callers_of(source, "proceed")


def test_only_ingest_refers_to_the_transaction_that_authenticates_nobody():
    users = [
        path.relative_to(PACKAGE) for path in sorted(PACKAGE.rglob("*.py")) if callers_of(path.read_text(), "proceed")
    ]
    assert users == [INGEST]  # request_flow.py defines it; a definition is not a reference


def functions_referring_to(source: str, name: str) -> set[str]:
    return {
        function.name
        for function in ast.walk(ast.parse(source))
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            (isinstance(node, ast.Attribute) and node.attr == name) or (isinstance(node, ast.Name) and node.id == name)
            for node in ast.walk(function)
        )
    }


def test_the_guard_finds_the_function_that_refers_to_a_name():
    source = "def a():\n    return request_flow.proceed()\n\nasync def b():\n    return decide()\n\ndef c():\n    pass\n"
    assert functions_referring_to(source, "proceed") == {"a"} and functions_referring_to(source, "decide") == {"b"}


def test_the_code_that_proceeds_is_reached_only_from_the_code_that_decided():
    """`_receive` (the only function that refers to proceed) is called from `_upload` (the only one that uses decide)."""
    source = (PACKAGE / INGEST).read_text()
    proceeding, deciding = functions_referring_to(source, "proceed"), functions_referring_to(source, "decide")
    assert proceeding == {"_receive"} and deciding == {"_upload"}
    callers = {
        function.name
        for function in ast.walk(ast.parse(source))
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(node, ast.Name) and node.id in proceeding for node in ast.walk(function))
        and function.name not in proceeding
    }
    assert callers == deciding


# --- quarantine and the trusted root ---------------------------------------------------------------------------------------


def file_operations(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Attribute) and function.attr in FILE_OPERATIONS and isinstance(function.value, ast.Name) and function.value.id in {"os", "shutil", "Path"}:
                found.append(f"os.{function.attr}")
            elif isinstance(function, ast.Name) and function.id == "open":
                found.append("open")
            elif isinstance(function, ast.Attribute) and function.attr in PATH_METHODS:
                found.append(f".{function.attr}")  # unambiguous pathlib names only: str.replace and file.open are not these
    return found


@pytest.mark.parametrize(
    "source",
    ["os.open(name, flags)", "os.rename(a, b)", "os.unlink(a)", "open(path, 'wb')", "path.write_bytes(data)", "target.rename(other)"],
)
def test_the_guard_sees_the_ways_of_writing_to_a_directory(source):
    assert file_operations(source)


def test_only_the_trusted_and_the_quarantine_modules_open_move_or_delete_files():
    users = {path.relative_to(PACKAGE) for path in PACKAGE.rglob("*.py") if file_operations(path.read_text())}
    assert users == FILE_MODULES


def identifiers(source: str) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, (ast.arg,)):
            names.add(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.name.split(".")[-1] for alias in node.names)
    return names


def test_the_two_storage_modules_know_nothing_of_each_other_s_root():
    quarantine_names = identifiers((PACKAGE / "quarantine.py").read_text())
    trusted_names = identifiers((PACKAGE / "assets.py").read_text())
    assert not {"asset_root", "assets", "open_asset_file"} & quarantine_names
    assert not {"quarantine", "quarantine_root", "ingest", "IncomingFile"} & trusted_names


def functions_calling(source: str, module: str, attribute: str) -> set[str]:
    """Names of the functions in `source` that call `module.attribute(...)`."""
    return {
        function.name
        for function in ast.walk(ast.parse(source))
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == attribute
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == module
    }


def test_the_guard_finds_the_functions_that_call_a_module_function():
    source = "def a():\n    os.unlink(x)\n\ndef b():\n    other.unlink(x)\n\nasync def c():\n    os.unlink(y)\n"
    assert functions_calling(source, "os", "unlink") == {"a", "c"}


def test_quarantine_deletes_only_staged_files_the_staged_name_after_placement_and_the_exact_file_it_published():
    """There is no function that deletes whatever is at a storage key: the one that deletes a final file checks identity."""
    source = (PACKAGE / "quarantine.py").read_text()
    assert functions_calling(source, "os", "unlink") == {"remove_staged", "publish", "remove_if_same_file"}
    assert functions_calling(source, "os", "rename") == set()  # nothing is moved by an operation that can replace
    assert functions_calling(source, "os", "replace") == set()
    assert functions_calling(source, "os", "link") == {"publish"}  # the no-clobber placement, in one place


def test_ingest_never_receives_the_trusted_root_and_the_asset_route_never_receives_quarantine():
    app_source = (PACKAGE / "app.py").read_text()
    tree = ast.parse(app_source)
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        text = ast.unparse(call)
        if text.startswith("ingest."):
            assert "asset_root" not in text, text
        if text.startswith("assets."):
            assert "quarantine_root" not in text, text

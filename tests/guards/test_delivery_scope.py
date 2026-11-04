"""Source guards for ingest: deliveries are read and changed in two places only, and quarantine stays apart from trusted storage.

Three things are checked over src/, each against bad and good samples so that the guard is shown to fail:

1. SQL that names the deliveries table: store.py may create it and insert rows; ingest.py may read a delivery only by the
   one scoped statement (or by the two fixed reconciliation reads) and may update it only by the compare-and-set that
   names the delivery, its production, its owner and the state INITIATED. Nothing may delete or replace a row. M1J adds
   two more owners: acceptance.py reads a delivery only through the coordinator-scoped statement and moves it only by
   the compare-and-set that binds the sealed digest and the verdict; trust.py's rescan reads the one delivery the
   operator names (no caller is involved) and moves it only from SCAN_FAILED or SCAN_PASSED back to SEALING.
2. request_flow.proceed() runs a transaction without authenticating anyone, so only ingest.py and trust.py may call it,
   and only after request_flow.decide() has authorised the same request. request_flow.run_system() runs one for the lab's
   own named system actor, and only trust.py's rescan may call it.
3. Only assets.py (the trusted root) and quarantine.py (the quarantine root) open, move or delete files, and neither
   mentions the other's root. Nothing that can write quarantine can write the trusted asset root.

Like the other guards, these catch accidents and drift; they do not read a statement built at run time.
"""

import ast
import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "content_boundary_lab"
STORE, INGEST, TRUST, ACCEPTANCE = Path("store.py"), Path("ingest.py"), Path("trust.py"), Path("acceptance.py")
PROMOTION = Path("promotion.py")
SQL_START = re.compile(r"\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|WITH|REPLACE|DROP|ALTER)\b", re.IGNORECASE)
NAMES_DELIVERIES = re.compile(r"\bdeliveries\b", re.IGNORECASE)
SCOPED_READ = (r"\bd\.id = \?", r"\bd\.production_id = \?", r"\bissuer = \?", r"\bsubject = \?", r"revoked_at IS NULL", r"ends_at > \?")
OWNER_READ = SCOPED_READ + (r"\be\.subject_id = d\.owner_subject_id",)  # ingest: the caller is the delivery's owner
COORDINATOR_READ = SCOPED_READ + (r"\brole = 'coordinator'",)  # the same scope, for the coordinator of the delivery's production
SYSTEM_READ = re.compile(r"SELECT [\w., ]+ FROM deliveries AS d WHERE d\.id = \?$")  # the rescan: the one delivery the operator named
# The modules that may change a delivery, each by compare-and-set from the state it owns, naming the delivery and its
# production and what else binds the step, and setting only the columns that step writes: ingest INITIATED -> UPLOADED;
# trust the seal (UPLOADED -> SEALING -> its outcome) and the rescan (SCAN_FAILED or SCAN_PASSED -> SEALING, which keeps
# the seal); acceptance SCAN_PASSED -> ACCEPTED, bound to the sealed digest and the verdict. Keyed by the state the
# statement moves a delivery from, which it must end with.
OWNED = (r"\bid = \?", r"\bproduction_id = \?", r"\bowner_subject_id = \?")
SETTERS = {
    INGEST: ({"INITIATED": {"state", "received_size", "received_sha256", "uploaded_at"}}, OWNED),
    TRUST: (
        {
            "UPLOADED": {"state"},
            "SEALING": {"state", "state_reason", "sealed_size", "sealed_sha256", "receipt_matched", "verdict_id"},
            "SCAN_FAILED": {"state", "state_reason", "verdict_id"},
            "SCAN_PASSED": {"state", "state_reason", "verdict_id"},
        },
        OWNED,
    ),
    ACCEPTANCE: (
        {"SCAN_PASSED": {"state", "accepted_sha256", "accepted_at", "accepted_by"}},
        (r"\bid = \?", r"\bproduction_id = \?", r"\bsealed_sha256 = \?", r"\bverdict_id = \?"),
    ),
    # M1K: promotion moves ACCEPTED -> PROMOTING (P1: the attempt and the asset key are recorded with it), and PROMOTING ->
    # PROMOTED or INTEGRITY_FAILED (P4), each naming the delivery, its production and the accepted digest.
    PROMOTION: (
        {"ACCEPTED": {"state", "promotion_attempt", "asset_id"}, "PROMOTING": {"state"}},
        (r"\bid = \?", r"\bproduction_id = \?", r"\baccepted_sha256 = \?"),
    ),
}
# What else a statement must bind, by the module and the state it moves a delivery from.
EXTRA_BINDING = {
    (PROMOTION, "ACCEPTED"): (r"\bverdict_id = \?",),
    (PROMOTION, "PROMOTING"): (r"\bpromotion_attempt = \?", r"\basset_id = \?"),
}
PROMOTION_READ = re.compile(r"SELECT [\w., ]+ FROM deliveries AS d WHERE d\.id = \? AND d\.production_id = \?$")
PROMOTION_LISTINGS = (  # the recovery pass: which deliveries are promoting, and which carry a promotion record
    re.compile(r"SELECT d\.id, d\.production_id FROM deliveries AS d WHERE d\.state = 'PROMOTING' ORDER BY d\.rowid$"),
    re.compile(r"SELECT [\w., ]+ FROM deliveries AS d WHERE d\.promotion_attempt IS NOT NULL ORDER BY d\.rowid$"),
)
RECONCILIATION_READS = (
    re.compile(r"SELECT state FROM deliveries WHERE storage_key = \?$"),
    re.compile(r"SELECT id, storage_key FROM deliveries WHERE state != 'INITIATED'$"),
)
FILE_OPERATIONS = {"open", "rename", "replace", "unlink", "link", "mkdir", "rmdir", "remove", "symlink", "truncate"}
PATH_METHODS = {"write_bytes", "write_text", "unlink", "rename", "rmdir", "mkdir", "touch", "symlink_to", "hardlink_to"}
FILE_MODULES = {Path("assets.py"), Path("quarantine.py")}


def _statements(source: str, names: re.Pattern = NAMES_DELIVERIES) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr):
            text = " ".join(part.value for part in node.values if isinstance(part, ast.Constant))
        else:
            continue
        if SQL_START.match(text) and names.search(text):
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
        elif relative in SETTERS:
            changeable_from, binding = SETTERS[relative]
            if verb == "SELECT":
                if relative == TRUST:  # the seal reads through ingest.get_delivery_in_scope; only the rescan reads by id
                    if not SYSTEM_READ.fullmatch(text):
                        problems.append(f"{where} that is not the rescan's read of the one delivery the operator named")
                elif relative == ACCEPTANCE:
                    if not all(re.search(pattern, text) for pattern in COORDINATOR_READ):
                        problems.append(f"{where} that is not the coordinator-scoped read")
                elif relative == PROMOTION:
                    if not PROMOTION_READ.fullmatch(text) and not any(pattern.fullmatch(text) for pattern in PROMOTION_LISTINGS):
                        problems.append(f"{where} that is neither the delivery-and-production read nor a recovery listing")
                elif not all(re.search(pattern, text) for pattern in OWNER_READ) and not any(
                    pattern.fullmatch(text) for pattern in RECONCILIATION_READS
                ):
                    problems.append(f"{where} that is neither the owner-scoped read nor a reconciliation read")
            elif verb == "UPDATE":
                assignments = re.search(r"\bSET\b(.*)\bWHERE\b", text, re.IGNORECASE | re.DOTALL)
                columns = {part.split("=")[0].strip() for part in assignments.group(1).split(",")} if assignments else {"?"}
                from_state = re.search(r"\bstate = '(\w+)'\s*$", text)
                changeable = changeable_from.get(from_state.group(1) if from_state else "", set())
                extra = EXTRA_BINDING.get((relative, from_state.group(1) if from_state else ""), ())
                missing = [pattern for pattern in (*binding, *extra) if not re.search(pattern, text)]
                if not from_state or from_state.group(1) not in changeable_from:
                    missing.append("a state it may move a delivery from")
                if missing or not columns <= changeable:
                    problems.append(f"{where} that is not a compare-and-set of {relative} (missing {missing}, sets {sorted(columns - changeable)})")
            else:
                problems.append(f"{where} in a module that may only read and compare-and-set")
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


SEAL_START = "UPDATE deliveries SET state = 'SEALING' WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = 'UPLOADED'"
SEAL_END = (
    "UPDATE deliveries SET state = ?, state_reason = ?, sealed_size = ?, sealed_sha256 = ?, receipt_matched = ?, verdict_id = ? "
    "WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = 'SEALING'"
)
TRUST_BAD = {
    "a seal start without the owner": SEAL_START.replace(" AND owner_subject_id = ?", ""),
    "a seal start from any state": SEAL_START.replace(" AND state = 'UPLOADED'", ""),
    "a seal start from the upload's state": SEAL_START.replace("'UPLOADED'", "'INITIATED'"),
    "a seal end without the production": SEAL_END.replace(" AND production_id = ?", ""),
    "a seal end from any state": SEAL_END.replace(" AND state = 'SEALING'", ""),
    "a seal end that rewrites the identity": SEAL_END.replace("SET state = ?", "SET storage_key = ?, state = ?"),
    "a seal end that rewrites what was declared": SEAL_END.replace("SET state = ?", "SET declared_sha256 = ?, state = ?"),
    "a read of a delivery by id": "SELECT state FROM deliveries WHERE id = ?",
    "the scoped read, repeated in trust": SCOPED,
}


@pytest.mark.parametrize("statement", TRUST_BAD.values(), ids=list(TRUST_BAD))
def test_the_guard_flags_a_seal_that_changes_a_delivery_by_anything_but_its_two_compare_and_sets(statement):
    assert sql_violations(TRUST, _module(statement))


def test_the_guard_accepts_the_two_compare_and_sets_of_the_seal_in_trust_only():
    for statement in (SEAL_START, SEAL_END):
        assert sql_violations(TRUST, _module(statement)) == []
        assert sql_violations(INGEST, _module(statement))  # ingest owns INITIATED -> UPLOADED, not the seal
        assert sql_violations(Path("management.py"), _module(statement))
    assert sql_violations(TRUST, _module(CAS))  # and trust may not do ingest's


# --- M1J: the coordinator's read and acceptance, and the rescan's read and restart ---------------------------------------------

REVIEW = (
    "SELECT d.id, d.production_id, d.owner_subject_id, d.state, d.sealed_sha256, s.id, "
    "EXISTS (SELECT 1 FROM engagements AS o WHERE o.subject_id = d.owner_subject_id AND o.production_id = d.production_id "
    "AND o.revoked_at IS NOT NULL) FROM deliveries AS d "
    "JOIN engagements AS e ON e.production_id = d.production_id JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE d.id = ? AND d.production_id = ? AND s.issuer = ? AND s.subject = ? AND e.role = 'coordinator' "
    "AND e.revoked_at IS NULL AND e.ends_at > ?"
)
ACCEPT = (
    "UPDATE deliveries SET state = 'ACCEPTED', accepted_sha256 = ?, accepted_at = ?, accepted_by = ? "
    "WHERE id = ? AND production_id = ? AND sealed_sha256 = ? AND verdict_id = ? AND state = 'SCAN_PASSED'"
)
RESCAN_READ = (
    "SELECT d.id, d.production_id, d.owner_subject_id, d.storage_key, d.state, d.sealed_size, d.sealed_sha256, d.verdict_id "
    "FROM deliveries AS d WHERE d.id = ?"
)
RESCAN_START = (
    "UPDATE deliveries SET state = 'SEALING', state_reason = NULL, verdict_id = NULL "
    "WHERE id = ? AND production_id = ? AND owner_subject_id = ? AND state = '{state}'"
)
ACCEPTANCE_BAD = {
    "a read by id alone": "SELECT d.id FROM deliveries AS d WHERE d.id = ?",
    "the review without the coordinator's role": REVIEW.replace(" AND e.role = 'coordinator'", ""),
    "the review without the revocation test": REVIEW.replace(" AND e.revoked_at IS NULL", ""),
    "the review without the end of the engagement": REVIEW.replace(" AND e.ends_at > ?", ""),
    "the review without the production": REVIEW.replace(" AND d.production_id = ?", ""),
    "the review without the caller's issuer": REVIEW.replace(" AND s.issuer = ?", ""),
    "an acceptance that does not bind the digest": ACCEPT.replace(" AND sealed_sha256 = ?", ""),
    "an acceptance that does not bind the verdict": ACCEPT.replace(" AND verdict_id = ?", ""),
    "an acceptance without the production": ACCEPT.replace(" AND production_id = ?", ""),
    "an acceptance from any state": ACCEPT.replace(" AND state = 'SCAN_PASSED'", ""),
    "an acceptance from a failed scan": ACCEPT.replace("'SCAN_PASSED'", "'SCAN_FAILED'"),
    "an acceptance that rewrites the seal": ACCEPT.replace("SET state = 'ACCEPTED'", "SET sealed_sha256 = ?, state = 'ACCEPTED'"),
    "an acceptance that swaps the verdict": ACCEPT.replace("SET state = 'ACCEPTED'", "SET verdict_id = ?, state = 'ACCEPTED'"),
    "a delete": "DELETE FROM deliveries WHERE id = ?",
    "an insert": "INSERT INTO deliveries (id) VALUES (?)",
}


@pytest.mark.parametrize("statement", ACCEPTANCE_BAD.values(), ids=list(ACCEPTANCE_BAD))
def test_the_guard_flags_every_way_for_acceptance_to_read_or_move_a_delivery_that_leaves_a_condition_out(statement):
    assert sql_violations(ACCEPTANCE, _module(statement))


def test_the_guard_accepts_the_coordinator_read_and_the_acceptance_in_acceptance_only():
    for statement in (REVIEW, ACCEPT):
        assert sql_violations(ACCEPTANCE, _module(statement)) == []
        for other in (INGEST, TRUST, Path("management.py"), STORE):
            assert sql_violations(other, _module(statement)), other
    assert sql_violations(ACCEPTANCE, _module(CAS)) and sql_violations(ACCEPTANCE, _module(SEAL_START))
    assert sql_violations(ACCEPTANCE, _module(SCOPED))  # the owner's read is not the coordinator's


RESCAN_BAD = {
    "a read of a delivery by id, unaliased": "SELECT state FROM deliveries WHERE id = ?",
    "a read that adds a condition it should not skip": RESCAN_READ + " OR 1 = 1",
    "a restart without the owner": RESCAN_START.format(state="SCAN_FAILED").replace(" AND owner_subject_id = ?", ""),
    "a restart without the production": RESCAN_START.format(state="SCAN_FAILED").replace(" AND production_id = ?", ""),
    "a restart from any state": RESCAN_START.format(state="SCAN_FAILED").replace(" AND state = 'SCAN_FAILED'", ""),
    "a restart from an accepted delivery": RESCAN_START.format(state="ACCEPTED"),
    "a restart from a rejected delivery": RESCAN_START.format(state="REJECTED"),
    "a restart that clears the seal": RESCAN_START.format(state="SCAN_FAILED").replace("SET state", "SET sealed_sha256 = NULL, state"),
}


@pytest.mark.parametrize("statement", RESCAN_BAD.values(), ids=list(RESCAN_BAD))
def test_the_guard_flags_a_rescan_that_reads_or_restarts_more_than_it_may(statement):
    assert sql_violations(TRUST, _module(statement))


def test_the_guard_accepts_the_rescans_read_and_its_two_restarts_in_trust_only():
    for statement in (RESCAN_READ, RESCAN_START.format(state="SCAN_FAILED"), RESCAN_START.format(state="SCAN_PASSED")):
        assert sql_violations(TRUST, _module(statement)) == []
        for other in (INGEST, ACCEPTANCE, Path("management.py"), STORE):
            assert sql_violations(other, _module(statement)), other


# --- M1K: promotion's reads and its three compare-and-sets -----------------------------------------------------------------------

PROMOTE_READ = (
    "SELECT d.id, d.production_id, d.state, d.storage_key, d.sealed_size, d.accepted_sha256, d.promotion_attempt, d.asset_id "
    "FROM deliveries AS d WHERE d.id = ? AND d.production_id = ?"
)
PROMOTE_LISTING = "SELECT d.id, d.production_id FROM deliveries AS d WHERE d.state = 'PROMOTING' ORDER BY d.rowid"
PROMOTE_RECORDS = "SELECT d.id, d.production_id, d.state FROM deliveries AS d WHERE d.promotion_attempt IS NOT NULL ORDER BY d.rowid"
PROMOTE_BEGIN = (
    "UPDATE deliveries SET state = 'PROMOTING', promotion_attempt = ?, asset_id = ? "
    "WHERE id = ? AND production_id = ? AND accepted_sha256 = ? AND verdict_id = ? AND state = 'ACCEPTED'"
)
PROMOTE_END = (
    "UPDATE deliveries SET state = '{to}' "
    "WHERE id = ? AND production_id = ? AND accepted_sha256 = ? AND promotion_attempt = ? AND asset_id = ? AND state = 'PROMOTING'"
)
PROMOTION_BAD = {
    "a read by id alone": "SELECT d.id FROM deliveries AS d WHERE d.id = ?",
    "a read that adds a condition it should not skip": PROMOTE_READ + " OR 1 = 1",
    "a read of every delivery": "SELECT d.id FROM deliveries AS d",
    "a begin that does not bind the digest": PROMOTE_BEGIN.replace(" AND accepted_sha256 = ?", ""),
    "a begin that does not bind the verdict": PROMOTE_BEGIN.replace(" AND verdict_id = ?", ""),
    "a begin without the production": PROMOTE_BEGIN.replace(" AND production_id = ?", ""),
    "a begin from any state": PROMOTE_BEGIN.replace(" AND state = 'ACCEPTED'", ""),
    "a begin from the scan": PROMOTE_BEGIN.replace("'ACCEPTED'", "'SCAN_PASSED'"),
    "a begin that rewrites the acceptance": PROMOTE_BEGIN.replace("SET state", "SET accepted_sha256 = ?, state"),
    "a begin that rewrites the seal": PROMOTE_BEGIN.replace("SET state", "SET sealed_sha256 = ?, state"),
    "an end that does not bind the attempt": PROMOTE_END.format(to="PROMOTED").replace(" AND promotion_attempt = ?", ""),
    "an end that does not bind the asset key": PROMOTE_END.format(to="PROMOTED").replace(" AND asset_id = ?", ""),
    "an end that does not bind the digest": PROMOTE_END.format(to="PROMOTED").replace(" AND accepted_sha256 = ?", ""),
    "an end from any state": PROMOTE_END.format(to="PROMOTED").replace(" AND state = 'PROMOTING'", ""),
    "an end from the acceptance": PROMOTE_END.format(to="PROMOTED").replace("'PROMOTING'", "'ACCEPTED'"),
    "an end that rebinds the accepted digest": PROMOTE_END.format(to="PROMOTED").replace("SET state", "SET accepted_sha256 = ?, state"),
    "an end that swaps the asset key": PROMOTE_END.format(to="PROMOTED").replace("SET state", "SET asset_id = ?, state"),
    "a delete": "DELETE FROM deliveries WHERE id = ?",
    "an insert": "INSERT INTO deliveries (id) VALUES (?)",
}


@pytest.mark.parametrize("statement", PROMOTION_BAD.values(), ids=list(PROMOTION_BAD))
def test_the_guard_flags_a_promotion_that_reads_or_moves_a_delivery_beyond_its_three_steps(statement):
    assert sql_violations(PROMOTION, _module(statement))


def test_the_guard_accepts_promotions_reads_and_compare_and_sets_in_promotion_only():
    good = (PROMOTE_READ, PROMOTE_LISTING, PROMOTE_RECORDS, PROMOTE_BEGIN, PROMOTE_END.format(to="PROMOTED"), PROMOTE_END.format(to="INTEGRITY_FAILED"))
    for statement in good:
        assert sql_violations(PROMOTION, _module(statement)) == [], statement
        for other in (INGEST, TRUST, ACCEPTANCE, Path("management.py"), STORE):
            assert sql_violations(other, _module(statement)), (other, statement)
    for statement in (CAS, SEAL_START, SEAL_END, ACCEPT, RESCAN_READ):
        assert sql_violations(PROMOTION, _module(statement)), statement  # and promotion may not do anyone else's


NAMES_VERDICTS = re.compile(r"\bverdicts\b", re.IGNORECASE)
VERDICT_BY_ID =re.compile(r"SELECT [\w., ]+ FROM verdicts WHERE id = \?$")  # a verdict row is immutable; its id is the delivery's
CACHE_READ = (
    r"\bsha256 = \?", r"\bengine_id = \?", r"\bengine_version = \?", r"\bengine_kind = \?", r"\bpolicy_fingerprint = \?",
    r"\bverdict = 'no_detection'", r"\bvalid_until > \?",
)  # fmt: skip


def verdict_violations(relative: Path, source: str) -> list[str]:
    """The verdict cache: created and inserted into by the store, read only by the one lookup that binds every condition."""
    problems = []
    for line, text in _statements(source, NAMES_VERDICTS):
        verb = SQL_START.match(text).group(1).upper()
        if relative == STORE:
            ok = verb in {"CREATE", "INSERT"}
        elif relative == TRUST:
            ok = verb == "SELECT" and (all(re.search(pattern, text) for pattern in CACHE_READ) or bool(VERDICT_BY_ID.fullmatch(text)))
        else:
            ok = False
        if not ok:
            problems.append(f"{relative}:{line}: {verb} on verdicts that is not allowed there")
    return problems


LOOKUP = (
    "SELECT id, valid_until FROM verdicts WHERE sha256 = ? AND engine_id = ? AND engine_version = ? AND engine_kind = ? "
    "AND policy_fingerprint = ? AND verdict = 'no_detection' AND valid_until > ? ORDER BY scanned_at DESC LIMIT 1"
)
VERDICT_BAD = {
    "a lookup by digest alone": "SELECT id FROM verdicts WHERE sha256 = ?",
    "a lookup that ignores the engine version": LOOKUP.replace("engine_version = ? AND ", ""),
    "a lookup that ignores the policy": LOOKUP.replace("AND policy_fingerprint = ? ", ""),
    "a lookup that ignores expiry": LOOKUP.replace(" AND valid_until > ?", ""),
    "a lookup that accepts a detection": LOOKUP.replace("verdict = 'no_detection'", "verdict = ?"),
    "an update": "UPDATE verdicts SET valid_until = ? WHERE id = ?",
    "a delete": "DELETE FROM verdicts WHERE id = ?",
}


@pytest.mark.parametrize("statement", VERDICT_BAD.values(), ids=list(VERDICT_BAD))
def test_the_guard_flags_every_way_of_reusing_a_verdict_that_leaves_a_condition_out(statement):
    assert verdict_violations(TRUST, _module(statement))
    assert verdict_violations(Path("ingest.py"), _module(statement))


def test_the_guard_accepts_the_one_cache_lookup_and_the_read_by_id_in_trust_and_the_stores_inserts():
    by_id = "SELECT id, sha256, engine_id, engine_version, engine_kind, policy_fingerprint, verdict, scanned_sha256, scanned_at, valid_until FROM verdicts WHERE id = ?"
    assert verdict_violations(TRUST, _module(LOOKUP)) == [] and verdict_violations(TRUST, _module(by_id)) == []
    assert verdict_violations(Path("ingest.py"), _module(LOOKUP))  # only trust reads the cache
    for module in (Path("ingest.py"), ACCEPTANCE, STORE):
        assert verdict_violations(module, _module(by_id)), module  # and only trust reads a verdict, acceptance through trust
    assert verdict_violations(TRUST, _module(by_id + " OR 1 = 1")) and verdict_violations(TRUST, _module("SELECT id FROM verdicts"))
    assert verdict_violations(STORE, _module("INSERT INTO verdicts (id) VALUES (?)")) == []
    assert verdict_violations(STORE, _module(LOOKUP))  # and the store does not read it


def test_no_module_in_src_reads_or_changes_a_verdict_except_as_allowed():
    problems = []
    for path in sorted(PACKAGE.rglob("*.py")):
        problems += verdict_violations(path.relative_to(PACKAGE), path.read_text())
    assert problems == []
    assert any("FROM verdicts" in text for _, text in _statements((PACKAGE / TRUST).read_text(), NAMES_VERDICTS))  # not vacuous


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


def test_only_ingest_and_trust_refer_to_the_transaction_that_authenticates_nobody():
    users = [
        path.relative_to(PACKAGE) for path in sorted(PACKAGE.rglob("*.py")) if callers_of(path.read_text(), "proceed")
    ]
    assert users == [INGEST, TRUST]  # request_flow.py defines it; a definition is not a reference


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


def test_the_seal_proceeds_only_in_the_function_that_decided_it():
    source = (PACKAGE / TRUST).read_text()
    assert functions_referring_to(source, "proceed") == functions_referring_to(source, "decide") == {"_seal"}


@pytest.mark.parametrize(
    "source",
    ["request_flow.run_system(clock, path)", "from content_boundary_lab.request_flow import run_system\nrun_system()", "r = request_flow.run_system"],
    ids=["a call", "an import and a call", "an alias"],
)
def test_the_guard_sees_every_way_of_reaching_the_system_flow(source):
    assert callers_of(source, "run_system")


def test_only_the_rescan_and_the_promotion_job_refer_to_the_transaction_that_runs_as_the_system():
    """run_system() authenticates and authorises nobody: it is the lab's own act, so only trust.rescan() and promotion's one
    helper may start one."""
    users = [path.relative_to(PACKAGE) for path in sorted(PACKAGE.rglob("*.py")) if callers_of(path.read_text(), "run_system")]
    assert users == [PROMOTION, TRUST]  # request_flow.py defines it; a definition is not a reference
    assert functions_referring_to((PACKAGE / TRUST).read_text(), "run_system") == {"rescan"}
    assert functions_referring_to((PACKAGE / PROMOTION).read_text(), "run_system") == {"_transaction"}


def test_each_system_actor_is_named_only_where_its_work_runs():
    for name, home, function in (("SYSTEM_RESCAN", TRUST, "rescan"), ("SYSTEM_PROMOTE", PROMOTION, "_transaction")):
        users = [path.relative_to(PACKAGE) for path in sorted(PACKAGE.rglob("*.py")) if callers_of(path.read_text(), name)]
        assert users == sorted([Path("audit.py"), home]), name  # audit defines it and checks who may use it
        assert functions_referring_to((PACKAGE / home).read_text(), name) == {function}, name


def test_promotion_writes_nowhere_but_through_the_two_storage_modules_and_has_no_route():
    source = (PACKAGE / PROMOTION).read_text()
    assert not file_operations(source)  # every open, link, unlink and mkdir is in assets.py or quarantine.py
    assert not functions_referring_to(source, "proceed") and not functions_referring_to(source, "decide")
    app_names = identifiers((PACKAGE / "app.py").read_text())
    assert "promotion" not in app_names and not any("promot" in name.lower() for name in app_names)


def test_acceptance_proceeds_in_one_transaction_and_never_calls_the_scanner_or_a_file():
    source = (PACKAGE / ACCEPTANCE).read_text()
    assert not functions_referring_to(source, "proceed") and not functions_referring_to(source, "decide")
    assert not functions_referring_to(source, "run_system") and not functions_referring_to(source, "open_stored")
    assert not functions_referring_to(source, "scan") and not file_operations(source)
    assert not identifiers(source) & {"quarantine_root", "asset_root", "quarantine", "assets", "Scanner"}


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
        if text.startswith(("ingest.", "trust.")):
            assert "asset_root" not in text, text
        if text.startswith("assets."):
            assert "quarantine_root" not in text, text

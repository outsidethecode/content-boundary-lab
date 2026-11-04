"""M3: the remediation matrices (M0 §9), one per finding.

For each of F-02, F-03, F-04 and F-06 the matrix lists the attempts that matter (the behaviour that must keep working, the
original exploit, and the alternate and boundary attempts) and runs them against the reference, the seeded variant, one or two
deliberately partial fixes, and where one is instructive a different complete fix. Each variant is EXPECTED to fail exactly
the rows written next to it in labs/*/matrix.py. So these tests show three things at once: the reference holds every row; the
seeded variant (the seam reverted) fails its suite; and each naive fix fails the rows that teach why it is incomplete while
passing the ones it repairs. The weak fixes live in labs/*/naive.py and are applied only for the length of a row.
"""

import pytest

from content_boundary_lab import quarantine, trust
from labs import f02_parent_check as f02
from labs import f03_declared_identity as f03
from labs import f04_unverified_promotion as f04
from labs import f06_stale_authorisation as f06
from labs import matrix as harness

FINDINGS = [f02, f03, f04, f06]
SEAMS = [finding.SEAM for finding in FINDINGS]
ORIGINAL_CHUNKS, ORIGINAL_LOOKUP = quarantine.StoredFile.chunks, trust.lookup_verdict  # taken before any matrix has run


@pytest.fixture(scope="module", params=FINDINGS, ids=[f.ID for f in FINDINGS])
def evaluated(request):
    return request.param, harness.evaluate(request.param.matrix.build())


def test_the_reference_holds_every_row_of_the_matrix_without_a_fault(evaluated):
    _, matrix = evaluated
    reference = matrix.variants[0]
    assert reference.key == "R" and reference.seams == () and reference.fails == frozenset()
    assert [row for row, cell in matrix.results["R"].items() if not cell.holds or cell.error] == []


def test_every_variant_fails_exactly_the_rows_it_is_expected_to(evaluated):
    _, matrix = evaluated
    for variant in matrix.variants:
        assert harness.failures(matrix, variant) == variant.fails, variant.key
    assert harness.as_expected(matrix)


def test_the_matrix_has_the_six_things_the_reviewer_asked_for(evaluated):
    finding, matrix = evaluated
    kinds = [row.kind for row in matrix.rows]
    assert kinds.count("legitimate") >= 3 and kinds.count("exploit") >= 1 and kinds.count("boundary") >= 3
    ids = [row.id for row in matrix.rows]
    assert len(ids) == len(set(ids)) and "X1" in ids  # X1 is always the original exploit
    assert next(row for row in matrix.rows if row.id == "X1").kind == "exploit"
    seeded = next(v for v in matrix.variants if v.key == "V")
    assert seeded.seams == (finding.SEAM,) and "X1" in seeded.fails  # reverting the seam fails the original exploit's row
    legitimate = {row.id for row in matrix.rows if row.kind == "legitimate"}
    assert legitimate - seeded.fails  # and the seeded variant still does the legitimate things it did before


def test_the_original_exploit_row_is_blocked_by_the_reference_and_succeeds_against_the_seeded_variant(evaluated):
    _, matrix = evaluated
    assert matrix.results["R"]["X1"].holds and not matrix.results["V"]["X1"].holds


def test_each_naive_fix_leaves_a_bypass_and_the_alternative_fix_leaves_none(evaluated):
    _, matrix = evaluated
    naive = [v for v in matrix.variants if v.key.startswith("N")]
    assert naive and all(v.fails and v.lesson for v in naive)  # every naive fix has a bypass, named by the rows it fails
    assert all(v.fails <= {row.id for row in matrix.rows} for v in naive)
    for alternative in (v for v in matrix.variants if v.key.startswith("A")):
        assert alternative.fails == frozenset()


def test_nothing_is_left_applied_after_a_matrix_the_four_seams_and_the_two_helpers_a_row_may_swap(evaluated):
    finding, _ = evaluated
    assert getattr(finding.SEAM.module, finding.SEAM.name) is finding.SEAM.reference
    for seam in SEAMS:
        assert getattr(seam.module, seam.name) is seam.reference
    assert quarantine.StoredFile.chunks is ORIGINAL_CHUNKS  # F-04's X8 swaps this for the length of one row
    assert trust.lookup_verdict is ORIGINAL_LOOKUP  # F-03's naive fix swaps this on top of the seeded identity


def test_the_f02_matrix_distinguishes_the_naive_fix_only_on_callers_engaged_in_both_productions():
    matrix = harness.evaluate(f02.matrix.build())
    assert harness.failures(matrix, next(v for v in matrix.variants if v.key == "N1")) == {"X4", "X5"}
    assert harness.failures(matrix, next(v for v in matrix.variants if v.key == "A1")) == frozenset()


def test_the_f06_matrix_separates_the_two_naive_fixes_by_what_each_misses():
    matrix = harness.evaluate(f06.matrix.build())
    by_key = {v.key: harness.failures(matrix, v) for v in matrix.variants}
    assert by_key["N1"] == by_key["V"]  # re-checking the token repairs nothing
    assert by_key["N2"] == {"X3", "X4"}  # the store is read and revocation honoured; only the end-date boundary rows fail
    assert {"T1", "T2", "T3", "T4", "T5", "T6", "T7"}.isdisjoint(by_key["V"])  # the verifier is intact in the seeded variant too


def test_the_f04_matrix_separates_the_two_naive_fixes_by_what_each_misses():
    matrix = harness.evaluate(f04.matrix.build())
    by_key = {v.key: harness.failures(matrix, v) for v in matrix.variants}
    assert by_key["N1"] == {"X1"}  # same length gets through; every other length is refused
    assert by_key["N2"] == {"X8"}  # hashing first catches every substitution that is already there, not one that arrives after


def test_the_f03_matrix_shows_a_cache_check_on_a_declared_digest_changes_nothing():
    matrix = harness.evaluate(f03.matrix.build())
    by_key = {v.key: harness.failures(matrix, v) for v in matrix.variants}
    assert by_key["N1"] == by_key["V"] == {"X1", "X2"}


def test_the_command_prints_every_matrix_and_writes_one_evidence_file_each(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(harness, "all_matrices", lambda: [f03.matrix.build()])  # one is enough to show the command; the rest are above
    assert harness.main(["--evidence", str(tmp_path)]) == 0
    shown = capsys.readouterr().out
    written = (tmp_path / "f03-matrix.txt").read_text()
    assert shown.rstrip("\n") in written and written.startswith("date     ")
    assert "RESULT     every variant fails exactly the rows it is expected to: YES" in shown

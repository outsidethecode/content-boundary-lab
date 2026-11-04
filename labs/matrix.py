"""Remediation matrices (M0 §9, M3): does the fix hold, and does a partial fix?

A matrix is a list of rows and a list of variants. A **row** is one attempt, and `holds(world)` says whether the REQUIRED
OUTCOME holds for it: for a legitimate row, that the behaviour which must keep working still works; for an exploit or boundary
row, that the violation is refused. A **variant** is an application: the reference, the seeded twin of the finding, a
deliberately partial fix (a "naive fix"), and, where one is instructive, a different but complete fix. Each variant carries
the rows it is EXPECTED to fail, which is the matrix's own statement of what that variant teaches:

    reference           fails none (it is the remediation)
    seeded variant      fails the exploit rows, and whatever else its mistake breaks
    naive fix           fails exactly the rows that a partial fix leaves open, and passes the rows it repairs
    alternative fix     fails none (a matrix measures the security condition, not the reference's wording)

Every row of a variant runs in a fresh synthetic world, except the rows marked as not changing anything, which share one world
per variant. A row that raises counts as not holding, and the error is shown. Nothing is left applied when a row ends.

`python -m labs.matrix` prints the four matrices and exits 0 only if every variant fails exactly the rows it is expected to;
`--evidence DIR` also writes one file per finding under a header.
"""

import argparse
import logging
import sys
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from labs.demo import header
from labs.seam import Seam, applied
from labs.world import World


@dataclass(frozen=True)
class Row:
    id: str
    kind: str  # "legitimate": must keep working; "exploit": the original attempt; "boundary": an alternate or edge attempt
    what: str
    holds: Callable[[World], bool]
    changes_state: bool = True  # False: the row only reads, so variants may share one world for it


@dataclass(frozen=True)
class Variant:
    key: str  # the column heading: R, V, N1, A1
    name: str
    seams: tuple[Seam, ...] = ()
    fails: frozenset[str] = frozenset()  # the rows this variant is expected NOT to hold
    lesson: str = ""


@dataclass(frozen=True)
class Cell:
    holds: bool
    error: str | None = None


@dataclass
class Matrix:
    finding: str
    title: str
    rows: tuple[Row, ...]
    variants: tuple[Variant, ...]
    results: dict[str, dict[str, Cell]] = field(default_factory=dict)  # variant key -> row id -> cell


def _run(row: Row, world: World) -> Cell:
    try:
        return Cell(bool(row.holds(world)))
    except Exception as error:  # a fault is an outcome of the row: the required outcome did not hold
        return Cell(False, type(error).__name__)


def evaluate(matrix: Matrix) -> Matrix:
    for variant in matrix.variants:
        cells: dict[str, Cell] = {}
        with ExitStack() as stack:
            for chosen in variant.seams:
                stack.enter_context(applied(chosen))
            with World.temporary() as shared:
                for row in matrix.rows:
                    if row.changes_state:
                        with World.temporary() as fresh:
                            cells[row.id] = _run(row, fresh)
                    else:
                        cells[row.id] = _run(row, shared)
        matrix.results[variant.key] = cells
    return matrix


def failures(matrix: Matrix, variant: Variant) -> frozenset[str]:
    return frozenset(row for row, cell in matrix.results[variant.key].items() if not cell.holds)


def as_expected(matrix: Matrix) -> bool:
    reference = matrix.variants[0]
    clean = all(cell.holds and cell.error is None for cell in matrix.results[reference.key].values())
    return clean and all(failures(matrix, v) == v.fails for v in matrix.variants)


def render(matrix: Matrix) -> str:
    keys = [v.key for v in matrix.variants]
    lines = [f"{matrix.finding}  {matrix.title}: remediation matrix", "does the required outcome hold?  yes = it holds, NO = it does not", ""]
    lines += [f"  {v.key:<3} {v.name}" for v in matrix.variants]
    lines += ["", f"{'row':<5}{'kind':<12}" + "".join(f"{k:<5}" for k in keys) + "what"]
    for row in matrix.rows:
        cells = "".join(f"{('yes' if matrix.results[k][row.id].holds else 'NO'):<5}" for k in keys)
        lines.append(f"{row.id:<5}{row.kind:<12}{cells}{row.what}")
    errors = [(k, r, c.error) for k in keys for r, c in matrix.results[k].items() if c.error]
    lines += [""]
    if errors:
        lines += [f"errors     {k} / {r}: {e}" for k, r, e in errors]
    for v in matrix.variants:
        failed = sorted(failures(matrix, v), key=lambda r: [x.id for x in matrix.rows].index(r))
        shown = ", ".join(failed) if failed else "none"
        verdict = "as expected" if frozenset(failed) == v.fails else f"NOT as expected (expected {', '.join(sorted(v.fails)) or 'none'})"
        lines.append(f"{v.key:<3} fails: {shown}  [{verdict}]")
        if v.lesson:
            lines.append(f"      {v.lesson}")
    lines.append("")
    lines.append(f"RESULT     every variant fails exactly the rows it is expected to: {'YES' if as_expected(matrix) else 'NO'}")
    return "\n".join(lines) + "\n"


def all_matrices() -> list[Matrix]:
    from labs import f02_parent_check, f03_declared_identity, f04_unverified_promotion, f06_stale_authorisation

    # A matrix is built afresh by each finding's `build()`, so results never outlive the call that evaluated them.
    return [m.matrix.build() for m in (f02_parent_check, f03_declared_identity, f04_unverified_promotion, f06_stale_authorisation)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m labs.matrix", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--evidence", type=Path, help="a directory to write one file per finding into")
    arguments = parser.parse_args(argv)
    logging.getLogger("content_boundary_lab").addHandler(logging.NullHandler())  # the reference's own warnings are not the matrix's output
    ok = True
    for matrix in all_matrices():
        evaluate(matrix)
        text = render(matrix)
        print(text)
        ok &= as_expected(matrix)
        if arguments.evidence is not None:
            name = f"{matrix.finding.lower().replace('-', '')}-matrix.txt"
            command = f"python -m labs.matrix --evidence {arguments.evidence}"
            (arguments.evidence / name).write_text(header(command) + text, encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

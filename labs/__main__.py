"""`python -m labs`: run all four demonstrations and say how many were reproduced and how many the reference blocked.

`python -m labs --evidence docs/evidence` also writes one evidence file per finding and `summary.txt`, which holds the lines
the README quotes. A finding is `python -m labs.fNN_...`.
"""

import argparse
import sys
from pathlib import Path

from labs import demo, f02_parent_check, f03_declared_identity, f04_unverified_promotion, f06_stale_authorisation

FINDINGS = (f02_parent_check, f03_declared_identity, f04_unverified_promotion, f06_stale_authorisation)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m labs", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--evidence", type=Path, help="a directory to write one evidence file per finding into")
    arguments = parser.parse_args(argv)
    results = []
    for finding in FINDINGS:
        options = [] if arguments.evidence is None else ["--evidence", str(arguments.evidence / f"{finding.ID.lower().replace('-', '')}.txt")]
        results.append(demo.main(finding, options) == 0)
        print()
    done = sum(results)
    summary = f"{done} exploits reproduced against the seeded variants; {done} blocked by the reference ({len(FINDINGS)} findings)."
    print(summary)
    if arguments.evidence is not None:  # the README quotes this run, so it is evidence too
        lines = [
            f"{finding.ID}  seeded variant exploited and reference blocked: {'YES' if ok else 'NO'}  ({finding.TITLE})"
            for finding, ok in zip(FINDINGS, results, strict=True)
        ]
        command = f"python -m labs --evidence {arguments.evidence}"
        (arguments.evidence / "summary.txt").write_text(demo.header(command) + "\n".join([*lines, "", summary]) + "\n", encoding="utf-8")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

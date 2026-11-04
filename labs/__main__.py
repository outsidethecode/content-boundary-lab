"""`python -m labs`: run all four demonstrations and say how many were reproduced and how many the reference blocked.

`python -m labs --evidence docs/evidence` also writes one evidence file per finding. A finding is `python -m labs.fNN_...`.
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
    print(f"{done} exploits reproduced against the seeded variants; {done} blocked by the reference ({len(FINDINGS)} findings).")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

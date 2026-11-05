"""The shared part of a finding's demonstration: what was observed, how it is shown, and the command line.

A finding is a package with four members, so that the tests and the demonstration run the very same scenario:

    ID, TITLE      its identifier and title
    SEAM           the `labs.seam.Seam`: the reference function and its seeded twin
    scenario.run   `run(world) -> Observed`: the attacker's steps, in order, against whichever variant is in force
    scenario.exploited(facts) -> bool: whether the security violation occurred

`python -m labs.fNN_...` runs the scenario twice, each time in a fresh synthetic world, once against the reference
application and once with only the seam swapped, prints both side by side, and exits 0 only if the seeded variant was
exploited and the reference blocked it. `--evidence PATH` also writes the output to a file under a header that records
the date, the command, the commit, the Python and the pinned versions.
"""

import argparse
import importlib.metadata
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from labs.seam import applied
from labs.world import World

SENTENCE = "Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system."
PINNED = ("fastapi", "starlette", "PyJWT", "cryptography", "httpx2")


@dataclass
class Observed:
    """The attacker's steps in order, as (what was done, what came back), and the facts a test or a verdict reads."""

    steps: list[tuple[str, str]] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def step(self, did: str, got: object) -> None:
        self.steps.append((did, str(got)))


def shown(reply, **known: bytes) -> str:
    """A reply in one phrase: its status, and which known content (if any) its body is."""
    for name, content in known.items():
        if reply.body == content:
            return f"{reply.status}, {len(reply.body)} bytes: exactly {name}"
    body = reply.body.decode("utf-8", "replace")
    return f"{reply.status} {body[:80]}" if len(reply.body) <= 80 else f"{reply.status}, {len(reply.body)} bytes"


def run_variant(finding, vulnerable: bool) -> Observed:
    with World.temporary() as world:
        if vulnerable:
            with applied(finding.SEAM):
                return finding.scenario.run(world)
        return finding.scenario.run(world)


def render(finding, reference: Observed, seeded: Observed) -> tuple[str, bool]:
    blocked = not finding.scenario.exploited(reference.facts)
    exploited = finding.scenario.exploited(seeded.facts)
    lines = [
        f"{finding.ID}  {finding.TITLE}",
        f"seam       {finding.SEAM.where}",
        f"twin       {finding.SEAM.vulnerable.__module__}.{finding.SEAM.vulnerable.__name__}",
        f"scenario   {finding.SCENARIO}",
        "",
    ]
    for title, observed in (("REFERENCE", reference), ("SEEDED VARIANT (only the seam above is swapped)", seeded)):
        lines.append(f"== {title}")
        lines += [f"  {number}. {did}\n       -> {got}" for number, (did, got) in enumerate(observed.steps, start=1)]
        lines.append("")
    lines.append(f"RESULT     seeded variant exploited: {'YES' if exploited else 'NO'}   reference blocked: {'YES' if blocked else 'NO'}")
    return "\n".join(lines) + "\n", exploited and blocked


def _provenance(root: Path) -> tuple[str, bool]:
    """The short commit of the checkout at `root`, and whether the tree is exactly that commit.

    Outside a checkout the commit is "unknown" and the tree is not clean. Changes under docs/evidence are ignored: a run
    writes its own output there, so without this every file after the first would be made from an "unclean" tree.
    """
    try:
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
        differs = subprocess.run(
            ["git", "status", "--porcelain", "--", ".", ":(exclude)docs/evidence"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown", False
    return (f"{head} plus an uncommitted working tree", False) if differs else (head, True)


def header(command: str, root: Path | None = None) -> str:
    commit, clean = _provenance(root if root is not None else Path(__file__).resolve().parents[1])
    status = (
        "FINAL: generated from a clean committed tree (docs/decisions.md, AM-31)"
        if clean
        else "PROVISIONAL: the tree was not a clean checkout; regenerate from a clean committed tree (docs/decisions.md, AM-31)"
    )
    pins = ", ".join(f"{name}=={importlib.metadata.version(name)}" for name in PINNED)
    return (
        f"date     {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"command  {command}\n"
        f"commit   {commit}\n"
        f"python   {platform.python_version()} on {platform.system()} {platform.machine()}\n"
        f"pinned   {pins}\n"
        f"status   {status}\n"
        f"note     {SENTENCE}\n"
        "         Synthetic identities, content and keys only. The scanner is the lab's synthetic marker scanner and provides\n"
        "         no malware protection. A passing run shows the seeded defect is reproducible and the reference blocks it\n"
        "         under the stated assumptions; it shows nothing about any other system.\n\n"
    )


def main(finding, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=f"python -m {finding.__name__}", description=f"{finding.ID}: {finding.TITLE}", allow_abbrev=False)
    parser.add_argument("--evidence", type=Path, help="also write the output, under a header, to this file")
    arguments = parser.parse_args(argv)
    text, ok = render(finding, run_variant(finding, False), run_variant(finding, True))
    print(text, end="")
    if arguments.evidence is not None:
        command = f"python -m {finding.__name__} --evidence {arguments.evidence}"
        arguments.evidence.write_text(header(command) + text, encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit("run a finding: python -m labs.f02_parent_check")

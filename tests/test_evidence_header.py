"""What an evidence file says about the tree it was made from (M0 Addendum A11: regenerated from a clean tree at M5).

`labs.demo.header(command, root)` records the commit, and says FINAL only when the tree is exactly that commit. Changes
under docs/evidence do not count: a run writes its own output there, and the second of eight files would otherwise always be
made from a "dirty" tree. Anything else that differs, a tracked file changed or an untracked file added, makes it
PROVISIONAL. A directory that is not a git checkout names no commit and is PROVISIONAL.

Real git repositories in a temporary directory, made with explicit identities and no use of the user's configuration.
"""

import re
import subprocess

import pytest

from labs.demo import header

GIT = ["git", "-c", "user.name=lab-test", "-c", "user.email=lab-test@example.invalid", "-c", "commit.gpgsign=false"]


def git(root, *arguments):
    return subprocess.run([*GIT, *arguments], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "checkout"
    (root / "docs" / "evidence").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "docs" / "evidence" / "f02.txt").write_text("first run\n", encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "synthetic")
    return root


def fields(root):
    text = header("python -m labs", root)
    return {match.group(1): match.group(2) for match in re.finditer(r"^(\w+) +(.*)$", text, re.MULTILINE)}


def test_a_clean_tree_is_recorded_by_its_short_commit_and_called_final(checkout):
    found = fields(checkout)
    assert found["commit"] == git(checkout, "rev-parse", "--short", "HEAD")
    assert found["status"].startswith("FINAL: ")


def test_a_change_under_the_evidence_directory_does_not_make_the_tree_unclean(checkout):
    (checkout / "docs" / "evidence" / "f02.txt").write_text("second run\n", encoding="utf-8")
    (checkout / "docs" / "evidence" / "f03.txt").write_text("a new file\n", encoding="utf-8")
    found = fields(checkout)
    assert found["commit"] == git(checkout, "rev-parse", "--short", "HEAD") and found["status"].startswith("FINAL: ")


@pytest.mark.parametrize("change", ["a tracked file is edited", "an untracked file is added", "a tracked file is deleted"])
def test_any_other_difference_makes_it_provisional_and_says_so(checkout, change):
    if change == "a tracked file is edited":
        (checkout / "src" / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
    elif change == "an untracked file is added":
        (checkout / "src" / "extra.py").write_text("VALUE = 3\n", encoding="utf-8")
    else:
        (checkout / "src" / "module.py").unlink()
    found = fields(checkout)
    assert found["commit"] == f"{git(checkout, 'rev-parse', '--short', 'HEAD')} plus an uncommitted working tree"
    assert found["status"].startswith("PROVISIONAL: ") and "regenerate" in found["status"]


def test_a_directory_that_is_not_a_checkout_names_no_commit_and_is_provisional(tmp_path):
    found = fields(tmp_path)
    assert found["commit"] == "unknown" and found["status"].startswith("PROVISIONAL: ")


def test_the_labs_command_writes_a_summary_file_whose_last_line_is_the_sentence_it_prints(tmp_path, capsys):
    """The README quotes `python -m labs` verbatim from docs/evidence, so that run has an evidence file of its own."""
    from labs.__main__ import main

    assert main(["--evidence", str(tmp_path)]) == 0
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["f02.txt", "f03.txt", "f04.txt", "f06.txt", "summary.txt"]
    summary = (tmp_path / "summary.txt").read_text(encoding="utf-8")
    assert summary.rstrip().endswith(printed) and printed == "4 exploits reproduced against the seeded variants; 4 blocked by the reference (4 findings)."
    assert re.search(r"^command  python -m labs --evidence ", summary, re.MULTILINE) and re.search(r"^status   (FINAL|PROVISIONAL): ", summary, re.MULTILINE)
    assert all(f"F-0{number}  seeded variant exploited and reference blocked: YES" in summary for number in (2, 3, 4, 6))


def test_the_header_still_records_when_how_and_with_what_it_was_made(checkout):
    text = header("python -m labs --evidence docs/evidence", checkout)
    for label in ("date", "command", "commit", "python", "pinned", "status", "note"):
        assert re.search(rf"^{label} ", text, re.MULTILINE), label
    assert "command  python -m labs --evidence docs/evidence" in text

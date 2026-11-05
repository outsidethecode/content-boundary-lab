"""tools/check_docs.py: relative links and anchors resolve, code fences are closed, quoted snippets match their source, and quoted
evidence is evidence (M0 section 7, Addendum README contract; M5 acceptance: "the link and snippet checker passes").

The checker is a standard-library script that reads the repository and, only for the provenance of evidence files, runs `git`
without a shell. It is tested here on small trees made for the purpose, each broken in one way, and then on this repository.
"""

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "check_docs.py"
GIT = ["git", "-c", "user.name=lab-test", "-c", "user.email=lab-test@example.invalid", "-c", "commit.gpgsign=false"]

HEADER = (
    "date     2026-11-05T09:00:00Z\ncommand  python -m labs --evidence docs/evidence\ncommit   {commit}\n"
    "python   3.13.7 on Darwin arm64\npinned   fastapi==0.141.1\nstatus   {status}\nnote     Synthetic.\n\n"
)
EVIDENCE_BODY = "F-02  Object access\n  1. a step\n       -> 200\n\nRESULT     seeded variant exploited: YES   reference blocked: YES\n"
FINAL = "FINAL: generated from a clean committed tree"
PROVISIONAL = "PROVISIONAL: the tree was not a clean checkout; regenerate from a clean committed tree"


def load():
    spec = importlib.util.spec_from_file_location("check_docs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker():
    return load()


def write(root: Path, name: str, body: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")


@pytest.fixture
def tree(tmp_path):
    """A small, correct repository: a README, a page, a module, an evidence file."""
    write(tmp_path, "README.md", """
        # Title

        See [the page](docs/page.md#a-heading), [the module](src/module.py) and [up](#title).

        <!-- snippet: src/module.py#double -->
        ```python
        def double(value):
            return value * 2
        ```

        <!-- evidence: docs/evidence/f02.txt -->
        ```text
          1. a step
               -> 200
        …
        RESULT     seeded variant exploited: YES   reference blocked: YES
        ```
        """)
    write(tmp_path, "docs/page.md", "# Page\n\n## A heading\n\n## `Code` and (punctuation)!\n\n## A heading\n")
    write(tmp_path, "src/module.py", "def double(value):\n    return value * 2\n\n\nclass Box:\n    def open(self):\n        return 1\n")
    write(tmp_path, "docs/evidence/f02.txt", HEADER.format(commit="abc1234", status=PROVISIONAL) + EVIDENCE_BODY)
    return tmp_path


def problems(checker, root, **options):
    return checker.check(root, **options)


def test_a_correct_tree_has_no_problems(checker, tree):
    assert problems(checker, tree) == []


# --- links and anchors -----------------------------------------------------------------------------------------------------------


def test_a_link_to_a_file_that_is_not_there_is_reported(checker, tree):
    with (tree / "docs" / "page.md").open("a", encoding="utf-8") as page:
        page.write("\nSee [gone](missing.md).\n")
    found = problems(checker, tree)
    assert len(found) == 1 and "docs/page.md" in found[0] and "missing.md" in found[0]


@pytest.mark.parametrize("target", ["docs/page.md#no-such-heading", "#no-such-heading"])
def test_an_anchor_that_names_no_heading_is_reported(checker, tree, target):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write(f"\nAnd [broken]({target}).\n")
    found = problems(checker, tree)
    assert len(found) == 1 and "no-such-heading" in found[0]


@pytest.mark.parametrize(
    "anchor", ["a-heading", "a-heading-1", "code-and-punctuation"], ids=["first", "repeated heading gets -1", "code and punctuation dropped"]
)
def test_anchors_follow_the_way_github_names_headings(checker, tree, anchor):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write(f"\nAnd [ok](docs/page.md#{anchor}).\n")
    assert problems(checker, tree) == []


def test_external_links_and_mail_links_are_not_followed(checker, tree):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write("\n[a](https://example.invalid/x) and [b](mailto:someone@example.invalid).\n")
    assert problems(checker, tree) == []


def test_a_link_shown_inside_a_code_block_is_an_example_and_not_checked(checker, tree):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write("\n```markdown\n[example](nowhere.md#none)\n```\n")
    assert problems(checker, tree) == []


def test_a_code_block_that_is_never_closed_is_reported(checker, tree):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write("\n```text\nnever closed\n")
    assert any("README.md" in found and "fence" in found for found in problems(checker, tree))


# --- snippets --------------------------------------------------------------------------------------------------------------------


def test_a_snippet_that_no_longer_matches_its_source_is_reported(checker, tree):
    (tree / "src" / "module.py").write_text("def double(value):\n    return value + value\n", encoding="utf-8")
    found = problems(checker, tree)
    assert len(found) == 1 and "snippet" in found[0] and "src/module.py#double" in found[0]


def test_a_method_can_be_quoted_by_its_class_and_name(checker, tree):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write("\n<!-- snippet: src/module.py#Box.open -->\n```python\ndef open(self):\n    return 1\n```\n")
    assert problems(checker, tree) == []


@pytest.mark.parametrize(
    "marker, expected",
    [
        ("src/gone.py#double", "gone.py"),
        ("src/module.py#nothing_here", "nothing_here"),
        ("src/module.py", "name"),
    ],
)
def test_a_snippet_marker_that_names_nothing_is_reported(checker, tree, marker, expected):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write(f"\n<!-- snippet: {marker} -->\n```python\npass\n```\n")
    found = problems(checker, tree)
    assert len(found) == 1 and expected in found[0]


def test_a_marker_that_is_not_followed_by_a_code_block_is_reported(checker, tree):
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write("\n<!-- snippet: src/module.py#double -->\n\nJust a paragraph.\n")
    found = problems(checker, tree)
    assert len(found) == 1 and "code block" in found[0]


# --- evidence blocks -------------------------------------------------------------------------------------------------------------


def test_a_quoted_line_that_is_not_in_the_evidence_file_is_reported(checker, tree):
    page = (tree / "README.md").read_text(encoding="utf-8").replace("       -> 200\n", "       -> 201\n")
    (tree / "README.md").write_text(page, encoding="utf-8")
    found = problems(checker, tree)
    assert len(found) == 1 and "-> 201" in found[0] and "f02.txt" in found[0]


def test_an_evidence_marker_for_a_file_that_is_not_there_is_reported(checker, tree):
    (tree / "docs" / "evidence" / "f02.txt").unlink()
    assert any("f02.txt" in found for found in problems(checker, tree))


# --- evidence files and their provenance ------------------------------------------------------------------------------------------


def test_an_evidence_file_without_its_header_fields_or_its_result_is_reported(checker, tree):
    (tree / "docs" / "evidence" / "f02.txt").write_text("F-02\nno header\n", encoding="utf-8")
    found = " ".join(problems(checker, tree))
    assert "date" in found and "RESULT" in found


def test_provisional_evidence_is_noted_but_is_not_a_failure_until_final_is_asked_for(checker, tree):
    assert problems(checker, tree) == []
    found = problems(checker, tree, final=True)
    assert len(found) == 1 and "PROVISIONAL" in found[0] and "f02.txt" in found[0]


def git(root, *arguments):
    return subprocess.run([*GIT, *arguments], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def committed(tree, status):
    """Make `tree` a repository with the evidence file made at its first commit, claiming `status`."""
    git(tree, "init", "-q", "-b", "main")
    git(tree, "add", "-A")
    git(tree, "commit", "-q", "-m", "first")
    commit = git(tree, "rev-parse", "--short", "HEAD")
    (tree / "docs" / "evidence" / "f02.txt").write_text(HEADER.format(commit=commit, status=status) + EVIDENCE_BODY, encoding="utf-8")
    git(tree, "add", "-A")
    git(tree, "commit", "-q", "-m", "evidence")
    return commit


def test_final_evidence_whose_commit_is_in_the_history_and_whose_code_has_not_changed_passes(checker, tree):
    committed(tree, FINAL)
    assert problems(checker, tree, final=True) == []
    (tree / "docs" / "page.md").write_text("# Page\n\n## A heading\n\n## `Code` and (punctuation)!\n\n## A heading\n\nA later edit.\n", encoding="utf-8")
    git(tree, "commit", "-q", "-a", "-m", "docs only")
    assert problems(checker, tree, final=True) == []  # documents may change; the code under test may not


def test_final_evidence_is_reported_when_the_code_has_changed_since_it_was_made(checker, tree):
    committed(tree, FINAL)
    (tree / "src" / "module.py").write_text("def double(value):\n    return value * 3\n", encoding="utf-8")
    git(tree, "commit", "-q", "-a", "-m", "code")
    found = problems(checker, tree, final=True)
    assert any("f02.txt" in item and "changed since" in item for item in found)


@pytest.mark.parametrize("name", ["tests/test_module.py", "labs/demo.py", "requirements.lock", "pyproject.toml"])
def test_final_evidence_is_reported_when_a_test_or_the_lab_code_or_the_configuration_has_changed_since_it_was_made(checker, tree, name):
    """A descendant that only adds the evidence is valid (the test above); one that also changes what the evidence
    was made with, tests included, is not: the evidence would be vouching for a tree it was not made from."""
    committed(tree, FINAL)
    write(tree, name, "changed = True\n")
    git(tree, "add", "-A")
    git(tree, "commit", "-q", "-m", "changed")
    found = problems(checker, tree, final=True)
    assert any("f02.txt" in item and "changed since" in item for item in found)


def test_final_evidence_naming_a_commit_that_does_not_exist_is_reported(checker, tree):
    committed(tree, FINAL)
    page = (tree / "docs" / "evidence" / "f02.txt").read_text(encoding="utf-8").replace("commit   ", "commit   deadbee", 1)
    (tree / "docs" / "evidence" / "f02.txt").write_text(page, encoding="utf-8")
    assert any("f02.txt" in item and "not in the history" in item for item in problems(checker, tree, final=True))


@pytest.mark.parametrize("kind, marker", [("snippet", "../outside.py#double"), ("evidence", "../outside.txt"), ("snippet", "/etc/hosts#double")])
def test_a_marker_that_names_a_file_outside_the_repository_is_reported_and_that_file_is_not_read(checker, tree, kind, marker):
    (tree.parent / "outside.py").write_text("def double(value):\n    return value * 2\n", encoding="utf-8")
    (tree.parent / "outside.txt").write_text("  1. a step\n", encoding="utf-8")
    with (tree / "README.md").open("a", encoding="utf-8") as page:
        page.write(f"\n<!-- {kind}: {marker} -->\n```text\n  1. a step\n```\n")
    found = problems(checker, tree)
    assert len(found) == 1 and "outside the repository" in found[0]


@pytest.mark.parametrize("claimed", ["--exec-path=/nonexistent", "-h", "HEAD~1", "main", "abc123;touch", "abc12"])
def test_a_commit_field_that_is_not_a_hexadecimal_hash_is_reported_and_never_handed_to_git(checker, tree, monkeypatch, claimed):
    """The field is read from a file in the checkout, which a pull request can change; git must not see it as an option."""
    committed(tree, FINAL)
    path = tree / "docs" / "evidence" / "f02.txt"
    path.write_text(path.read_text(encoding="utf-8").replace("commit   ", f"commit   {claimed}\n#", 1), encoding="utf-8")
    seen = []
    real = checker.git
    monkeypatch.setattr(checker, "git", lambda root, *arguments: seen.append(arguments) or real(root, *arguments))
    found = problems(checker, tree, final=True)
    assert any("f02.txt" in item and "not a commit hash" in item for item in found)
    assert not any(claimed in argument for call in seen for argument in call)


# --- the script, and this repository ----------------------------------------------------------------------------------------------


def test_the_script_exits_one_with_each_problem_on_its_own_line_and_zero_when_there_is_none(tree):
    ok = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(tree)], capture_output=True, text=True)
    assert ok.returncode == 0 and "0 problems" in ok.stdout
    (tree / "README.md").write_text("[gone](nowhere.md)\n", encoding="utf-8")
    bad = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(tree)], capture_output=True, text=True)
    assert bad.returncode == 1 and "nowhere.md" in bad.stdout and "1 problem" in bad.stdout


def test_this_repository_passes_the_checker(checker):
    assert checker.check(ROOT) == []


def test_the_checker_uses_nothing_but_the_standard_library_and_no_network():
    import ast

    imported = set()
    for node in ast.walk(ast.parse(SCRIPT.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert {name.split(".")[0] for name in imported} <= set(sys.stdlib_module_names)
    network = {"socket", "ssl", "http", "urllib.request", "urllib.error", "requests", "httpx", "shutil"}
    assert not {name for name in imported if name in network or name.split(".")[0] in {"socket", "ssl", "http", "requests", "httpx"}}

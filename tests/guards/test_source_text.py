"""No text file of the repository carries a character that is invisible or that changes how the text is displayed.

A bidirectional override or a zero-width character inside a source file can make a reviewer read something other than what
the interpreter reads (CWE-1007, the "Trojan Source" class). The tests that need such characters as *data* write them as
`\\N{NAME}` escapes, which is what the file then shows. This guard reads every text file of the project, the documents
included, and refuses a literal control, format, line or paragraph separator, surrogate or private-use character. A tab is
allowed, and so is a line ending.
"""

import os
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUFFIXES = {".py", ".md", ".toml", ".txt", ".lock", ".in", ".cfg", ".json", ".yml", ".yaml"}
SKIPPED_DIRECTORIES = {".git", ".venv", ".dev", ".pytest_cache", "__pycache__", "build", "dist", ".ruff_cache", ".mypy_cache"}
FORBIDDEN_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Cs", "Co"}
ALLOWED = {"\t", "\n", "\r"}


def unsafe_characters(text: str) -> list[tuple[int, int, str]]:
    """(line, column, code point name) of every character in `text` that a reader cannot see or that moves other text."""
    found = []
    for number, line in enumerate(text.splitlines(keepends=True), start=1):
        for column, character in enumerate(line, start=1):
            if character not in ALLOWED and unicodedata.category(character) in FORBIDDEN_CATEGORIES:
                found.append((number, column, f"U+{ord(character):04X} {unicodedata.name(character, 'unnamed')}"))
    return found


def project_text_files() -> list[Path]:
    paths = []
    for directory, names, files in os.walk(ROOT):
        names[:] = sorted(name for name in names if name not in SKIPPED_DIRECTORIES and not name.endswith(".egg-info"))
        paths.extend(Path(directory, file) for file in sorted(files) if Path(file).suffix in SUFFIXES)
    return paths


# --- the checker sees what it must, and leaves ordinary text alone -------------------------------------------------------------

BAD = {
    "a right-to-left override": "name\N{RIGHT-TO-LEFT OVERRIDE}fdp.exe",
    "a left-to-right isolate": "x\N{LEFT-TO-RIGHT ISOLATE}y",
    "a zero-width joiner": "a\N{ZERO WIDTH JOINER}b",
    "a zero-width space": "a\N{ZERO WIDTH SPACE}b",
    "a byte-order mark inside a line": "a\N{ZERO WIDTH NO-BREAK SPACE}b",
    "a line separator": "a\N{LINE SEPARATOR}b",
    "a paragraph separator": "a\N{PARAGRAPH SEPARATOR}b",
    "a NUL": "a\x00b",
    "an escape": "a\x1bb",
    "a delete": "a\x7fb",
    "a C1 control": "a\x85b",
    "a private-use character": "a" + chr(0xE000) + "b",
}

GOOD = {
    "ASCII": "plain text, 1 + 2 = 3\n",
    "accented letters": "résumé, Zoë, naïve, Ångström\n",
    "a tab and a Windows line ending": "a\tb\r\nc\r\n",
    "symbols and arrows": "a → b, ≥, ✓, ©\n",
    "an escape written as text": 'name = "a\\N{RIGHT-TO-LEFT OVERRIDE}b"\n',
}


@pytest.mark.parametrize("sample", BAD.values(), ids=BAD.keys())
def test_the_checker_flags_a_character_a_reader_cannot_see(sample):
    assert unsafe_characters(sample) != []


@pytest.mark.parametrize("sample", GOOD.values(), ids=GOOD.keys())
def test_the_checker_leaves_ordinary_text_alone(sample):
    assert unsafe_characters(sample) == []


def test_the_checker_reports_where_the_character_is():
    assert unsafe_characters("one\ntwo \N{RIGHT-TO-LEFT OVERRIDE}\n") == [(2, 5, "U+202E RIGHT-TO-LEFT OVERRIDE")]


# --- the project ---------------------------------------------------------------------------------------------------------------


def test_the_walk_reads_the_sources_the_tests_the_labs_and_the_documents():
    relative = {path.relative_to(ROOT).as_posix() for path in project_text_files()}
    assert {"src/content_boundary_lab/runner.py", "tests/guards/test_source_text.py", "labs/matrix.py", "docs/claims.md", "README.md"} <= relative
    assert not any(name.startswith((".git/", ".venv/", ".dev/")) for name in relative)


def test_no_text_file_of_the_project_carries_an_invisible_or_display_changing_character():
    offences = {}
    for path in project_text_files():
        found = unsafe_characters(path.read_text(encoding="utf-8"))
        if found:
            offences[path.relative_to(ROOT).as_posix()] = found
    assert offences == {}

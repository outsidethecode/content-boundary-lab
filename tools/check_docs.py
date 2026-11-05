"""Check the documents against the repository: links, quoted code and quoted evidence (M0 section 7, Addendum README contract).

    python tools/check_docs.py [--root DIR] [--final]

Standard library only. It reads files; to judge where evidence came from it also runs `git` (a fixed argument list, no shell,
no network). It exits 0 when nothing is wrong and 1 with one problem per line otherwise.

What it checks, in every Markdown page of the README, SECURITY.md, labs/, docs/ (not docs/milestones, which are preserved records):

- every relative link points at something that exists, and every `#anchor` names a heading of the page it points at;
- every fenced code block is closed;
- `<!-- snippet: PATH#NAME -->` before a code block: the block is exactly the source of that function, class or method (so a
  snippet is found by name, never by line number);
- `<!-- evidence: PATH -->` before a code block: every line of the block, except a line that is only "…", is a line of that
  evidence file, so a README or write-up quotes the evidence and does not retype it;
- each file in docs/evidence has its header (date, command, commit, python, pinned, status, note) and ends with its result.

Evidence made from a tree that was not a clean commit says PROVISIONAL in its header. That is reported as a note. With `--final`
it is a problem, and so is evidence whose commit is not in the history of HEAD or whose code (src/, labs/, tests/,
requirements.lock, pyproject.toml) differs from that commit's: the evidence then describes other code than the code in front
of you. The commit does not have to be HEAD: a later commit that changes only the evidence, or a document, is valid, which is
how evidence can name the commit it was made from and be committed after it. HEAD is compared with that commit, so a change
that is not yet committed is not seen; run it on a clean checkout.
"""

import argparse
import ast
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

PAGES = ("README.md", "SECURITY.md", "labs/README.md", "docs/*.md", "docs/findings/*.md", "docs/review/*.md")
CODE_UNDER_TEST = ("src", "labs", "tests", "requirements.lock", "pyproject.toml")  # what the evidence was made with, and the tests that vouch for it
HEADER_FIELDS = ("date", "command", "commit", "python", "pinned", "status", "note")
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
MARKER = re.compile(r"^<!-- (snippet|evidence): (\S+) -->$")
SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:")
STATUS = re.compile(r"^status +(FINAL|PROVISIONAL): ", re.MULTILINE)
COMMIT = re.compile(r"[0-9a-f]{7,40}")


@dataclass
class Report:
    problems: list[str] = field(default_factory=list)
    pages: int = 0
    links: int = 0
    snippets: int = 0
    blocks: int = 0
    evidence_files: int = 0
    provisional: list[str] = field(default_factory=list)

    def add(self, where: str, message: str) -> None:
        self.problems.append(f"{where}: {message}")


def slug(heading: str) -> str:
    """The anchor GitHub gives a heading: formatting and punctuation dropped, lower case, spaces as hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading).replace("`", "").replace("*", "").strip().lower()
    return "".join(ch for ch in text if ch.isalnum() or ch in " -_").replace(" ", "-")


def lines_with_fences(text: str) -> tuple[list[tuple[str, bool]], bool]:
    """Each line with whether it is inside a fenced code block (the fences themselves are inside), and whether one is left open."""
    found, inside = [], False
    for line in text.splitlines():
        fence = line.lstrip().startswith("```")
        if fence:
            inside = not inside
            found.append((line, True))
        else:
            found.append((line, inside))
    return found, inside


def anchors_of(path: Path, cache: dict[Path, set[str]]) -> set[str]:
    if path not in cache:
        seen: dict[str, int] = {}
        names: set[str] = set()
        for line, inside in lines_with_fences(path.read_text(encoding="utf-8"))[0]:
            match = None if inside else HEADING.match(line)
            if match:
                base = slug(match.group(1))
                count = seen.get(base, 0)
                seen[base] = count + 1
                names.add(base if count == 0 else f"{base}-{count}")
        cache[path] = names
    return cache[path]


def source_of(path: Path, name: str) -> str | None:
    """The source text of a top-level function or class, or of `Class.method`, dedented; None if there is no such thing."""
    text = path.read_text(encoding="utf-8")
    node: ast.AST = ast.parse(text)
    for part in name.split("."):
        node = next(
            (
                child
                for child in getattr(node, "body", [])
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == part
            ),
            None,
        )
        if node is None:
            return None
    start = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
    return textwrap.dedent("\n".join(text.splitlines()[start - 1 : node.end_lineno]))


def normal(lines: list[str]) -> str:
    return "\n".join(line.rstrip() for line in lines).strip("\n")


def check_links(root: Path, page: Path, lines: list[tuple[str, bool]], report: Report, cache: dict[Path, set[str]]) -> None:
    where = page.relative_to(root).as_posix()
    for line, inside in lines:
        if inside:
            continue  # a link shown inside a code block is an example
        for target in LINK.findall(line):
            if SCHEME.match(target):
                continue  # an external link, or a mail link: not followed
            report.links += 1
            path, _, anchor = target.partition("#")
            destination = page if not path else (page.parent / unquote(path))
            if not destination.exists():
                report.add(where, f"the link {target} points at nothing")
            elif anchor and destination.suffix == ".md" and anchor not in anchors_of(destination, cache):
                report.add(where, f"the link {target} names a heading that is not in {destination.relative_to(root).as_posix()}")


def block_after(lines: list[tuple[str, bool]], index: int) -> list[str] | None:
    """The lines of the code block that follows the marker at `index`, or None if the next non-blank line does not open one."""
    after = index + 1
    while after < len(lines) and not lines[after][0].strip():
        after += 1
    if after >= len(lines) or not lines[after][0].lstrip().startswith("```"):
        return None
    block = []
    for line, _ in lines[after + 1 :]:
        if line.lstrip().startswith("```"):
            return block
        block.append(line)
    return None


def check_markers(root: Path, page: Path, lines: list[tuple[str, bool]], report: Report) -> None:
    where = page.relative_to(root).as_posix()
    for index, (line, inside) in enumerate(lines):
        match = None if inside else MARKER.match(line)
        if not match:
            continue
        kind, spec = match.groups()
        block = block_after(lines, index)
        if block is None:
            report.add(where, f"the {kind} marker for {spec} is not followed by a code block")
            continue
        if kind == "snippet":
            report.snippets += 1
            check_snippet(root, where, spec, block, report)
        else:
            report.blocks += 1
            check_evidence_block(root, where, spec, block, report)


def inside(root: Path, path: str) -> bool:
    """Whether `path`, a marker's file, stays within the repository once `..`, absolute paths and links are resolved."""
    return (root / path).resolve().is_relative_to(root.resolve())


def check_snippet(root: Path, where: str, spec: str, block: list[str], report: Report) -> None:
    path, _, name = spec.partition("#")
    if not inside(root, path):
        report.add(where, f"the snippet marker {spec} names a file outside the repository, which is not read")
    elif not name:
        report.add(where, f"the snippet marker {spec} needs a name after '#', as PATH#NAME")
    elif not (root / path).is_file():
        report.add(where, f"the snippet {spec}: there is no file {path}")
    elif not path.endswith(".py"):
        report.add(where, f"the snippet {spec}: only Python source can be quoted by name")
    else:
        source = source_of(root / path, name)
        if source is None:
            report.add(where, f"the snippet {spec}: {path} has no {name}")
        elif normal(source.splitlines()) != normal(block):
            report.add(where, f"the snippet {spec} does not match the source")


def check_evidence_block(root: Path, where: str, path: str, block: list[str], report: Report) -> None:
    if not inside(root, path):
        report.add(where, f"the evidence marker names {path}, a file outside the repository, which is not read")
        return
    if not (root / path).is_file():
        report.add(where, f"the evidence marker names {path}, which is not there")
        return
    known = {line.rstrip() for line in (root / path).read_text(encoding="utf-8").splitlines()}
    quoted = [line.rstrip() for line in block if line.strip() and line.strip() != "…"]
    if not quoted:
        report.add(where, f"the evidence block for {path} quotes nothing")
    for line in quoted:
        if line not in known:
            report.add(where, f"the evidence block quotes a line that is not in {path}: {line.strip()}")


def git(root: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *arguments], cwd=root, capture_output=True, text=True)


def check_evidence_file(root: Path, path: Path, final: bool, report: Report) -> None:
    name = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    header = text.split("\n\n", 1)[0]
    for label in HEADER_FIELDS:
        if not re.search(rf"^{label} ", header, re.MULTILINE):
            report.add(name, f"the header has no {label} line")
    status = STATUS.search(header)
    if status is None:
        report.add(name, "the header's status line is neither FINAL nor PROVISIONAL")
    elif status.group(1) == "PROVISIONAL":
        report.provisional.append(name)
        if final:
            report.add(name, "the evidence is PROVISIONAL; regenerate it from a clean committed tree")
    if re.fullmatch(r"f\d\d(-matrix)?\.txt", path.name):
        last = [line for line in text.splitlines() if line.strip()][-1:]
        if not last or not last[0].startswith("RESULT"):
            report.add(name, "the file does not end with its RESULT line")
    if final and status is not None and status.group(1) == "FINAL":
        check_provenance(root, name, header, report)


def check_provenance(root: Path, name: str, header: str, report: Report) -> None:
    match = re.search(r"^commit +(\S+)(.*)$", header, re.MULTILINE)
    commit = match.group(1) if match else ""
    if not match or commit == "unknown" or "uncommitted" in match.group(2):
        report.add(name, "the evidence names no clean commit")
    elif not COMMIT.fullmatch(commit):  # the field is read from a file a pull request can change: it never reaches git as an option
        report.add(name, "the commit field is not a commit hash (7 to 40 lowercase hexadecimal characters)")
    elif git(root, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0 or git(root, "merge-base", "--is-ancestor", commit, "HEAD").returncode != 0:
        report.add(name, f"the commit {commit} is not in the history of HEAD")
    elif git(root, "diff", "--quiet", commit, "HEAD", "--", *CODE_UNDER_TEST).returncode != 0:
        report.add(name, f"the code under test has changed since commit {commit}, so the evidence describes other code")


def pages_of(root: Path) -> list[Path]:
    found = {path for pattern in PAGES for path in root.glob(pattern) if path.is_file()}
    return sorted(found)


def run(root: Path, final: bool = False) -> Report:
    report = Report()
    cache: dict[Path, set[str]] = {}
    for page in pages_of(root):
        report.pages += 1
        lines, open_fence = lines_with_fences(page.read_text(encoding="utf-8"))
        if open_fence:
            report.add(page.relative_to(root).as_posix(), "a code fence is never closed")
        check_links(root, page, lines, report, cache)
        check_markers(root, page, lines, report)
    for path in sorted((root / "docs" / "evidence").glob("*.txt")):
        report.evidence_files += 1
        check_evidence_file(root, path, final, report)
    return report


def check(root: Path, final: bool = False) -> list[str]:
    return run(root, final).problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python tools/check_docs.py", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="the repository to check")
    parser.add_argument("--final", action="store_true", help="also require final evidence made from the code in this checkout")
    arguments = parser.parse_args(argv)
    report = run(arguments.root.resolve(), arguments.final)
    for problem in report.problems:
        print(problem)
    count = len(report.problems)
    print(
        f"check_docs: {report.pages} pages, {report.links} links, {report.snippets} snippets, {report.blocks} evidence blocks, "
        f"{report.evidence_files} evidence files; {count} {'problem' if count == 1 else 'problems'}"
    )
    if report.provisional and not arguments.final:
        print(f"note: {len(report.provisional)} evidence files are PROVISIONAL; regenerate them from a clean committed tree and run with --final")
    return 1 if report.problems else 0


if __name__ == "__main__":
    sys.exit(main())

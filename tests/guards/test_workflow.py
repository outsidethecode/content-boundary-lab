"""The CI workflow (M0 section 9, M5) first ran on GitHub on 2026-11-09, and what it is allowed to do is fixed here (V10).

GitHub's guidance for workflows (the Actions security hardening guide on docs.github.com, retrieved 2026-11-05; docs/references.md): pin every
action to a full commit SHA, give the token read-only repository contents and raise it only where a job needs more, do not
use `pull_request_target` (or check out untrusted code in `workflow_run`), do not put untrusted event data into a script, and
keep secrets out of workflow files. `actions/checkout` is told not to persist the token. These checks read the workflow as text,
with the standard library: no YAML parser is installed, and the workflow uses no feature that needs one. They show the file says
these things; they do not run it. The one run on GitHub (2026-11-09) is recorded in docs/publication.md.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_there_is_a_workflow():
    assert [path.name for path in WORKFLOWS] == ["ci.yml"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_the_token_can_read_the_repository_and_nothing_can_write_to_it(path):
    body = text(path)
    top = re.search(r"^permissions:\n((?:[ ]+\S.*\n)+)", body, re.MULTILINE)
    assert top and top.group(1).split() == ["contents:", "read"]  # the default for every job, and no more than that
    assert not re.search(r":\s*(write|admin)\b", body)  # and no job asks for more


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_to_a_full_commit_sha_with_its_release_in_a_comment(path):
    used = [match for line in text(path).splitlines() if (match := USES.match(line))]
    assert used, "the workflow uses no action, which is not what this test expects"
    for match in used:
        reference, rest = match.groups()
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference
        assert re.fullmatch(r"\s+# v\d+\.\d+\.\d+\s*", rest), reference  # the release the SHA is, for the human reading it


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_checkout_declines_to_keep_the_token(path):
    lines = text(path).splitlines()
    checkouts = [i for i, line in enumerate(lines) if "actions/checkout@" in line]
    assert checkouts
    for index in checkouts:
        step = []
        for line in lines[index + 1 :]:
            if re.match(r"\s*-\s", line):
                break
            step.append(line.strip())
        assert "persist-credentials: false" in step


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_it_runs_on_push_and_pull_request_only_and_never_with_the_privilege_of_the_base_repository(path):
    body = text(path)
    events = re.search(r"^on:\n((?:[ ]+\S.*\n)+)", body, re.MULTILINE).group(1)
    assert set(re.findall(r"^  (\w+):", events, re.MULTILINE)) == {"push", "pull_request"}
    assert not re.search(r"pull_request_target|workflow_run|workflow_dispatch|schedule:", body)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_event_data_or_secret_reaches_a_script_and_nothing_is_piped_into_a_shell(path):
    body = text(path)
    assert not re.search(r"github\.(event|head_ref|base_ref|actor)|\bsecrets\.|inputs\.", body)
    assert not re.search(r"(curl|wget)[^\n]*\|\s*(ba|z)?sh", body)
    assert re.findall(r"\$\{\{\s*([^}]*?)\s*\}\}", body) == []  # the workflow uses no expression at all


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_it_installs_the_locked_environment_by_hash_and_runs_the_established_checks(path):
    body = text(path)
    assert "pip install --require-hashes --only-binary=:all: -r requirements.lock" in body
    for command in (
        "-m pytest -q -W error",
        "-m pytest -q -m clean_env",
        "-m pytest -q -m real_server",
        "-m pytest -q -m packaging",
        "-m labs.matrix",
        "-m labs\n",
        "tools/check_docs.py",
        "-m pip check",
    ):
        assert command in body, command
    assert "runs-on: macos-" in body  # the lock is verified for macOS arm64 only; see requirements.lock and the README

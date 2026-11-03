"""Environment checks: interpreter, build-backend pin, dependency pins, lock and import location."""

import importlib
import importlib.metadata
import json
import re
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock"
EXACT_PIN = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9._+!-]+)")
SHA256_OPTION = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def _pyproject() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)


def _runtime_and_dev_requirements(pyproject: dict) -> list[str]:
    project = pyproject["project"]
    extras = project.get("optional-dependencies", {})
    return [
        *project.get("dependencies", []),
        *(requirement for group in extras.values() for requirement in group),
    ]


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_requirements() -> list[str]:
    """Logical lines of requirements.lock: comments dropped, backslash continuations joined."""
    lines, pending = [], ""
    for raw in LOCK.read_text().splitlines():
        text = raw.strip()
        if not pending and (not text or text.startswith("#")):
            continue
        if text.endswith("\\"):
            pending += text[:-1] + " "
            continue
        lines.append((pending + text).strip())
        pending = ""
    assert not pending, "requirements.lock ends inside a line continuation"
    return lines


def _locked_versions() -> dict[str, str]:
    pins = (EXACT_PIN.fullmatch(line.split()[0]) for line in _lock_requirements())
    return {_canonical(pin["name"]): pin["version"] for pin in pins if pin}


def _installed_problems(expected: dict[str, str], label: str) -> list[str]:
    problems = []
    for name, version in expected.items():
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            problems.append(f"{name}: {label} {version}, not installed")
            continue
        if installed != version:
            problems.append(f"{name}: {label} {version}, installed {installed}")
    return problems


def _editable_direct_url() -> dict | None:
    for dist in importlib.metadata.distributions(name="content-boundary-lab"):
        text = dist.read_text("direct_url.json")
        if text:
            return json.loads(text)
    return None


def test_python_is_at_least_3_12():
    assert sys.version_info >= (3, 12), f"Python {sys.version.split()[0]} is older than 3.12"
    assert _pyproject()["project"]["requires-python"] == ">=3.12"


def test_build_backend_is_exactly_pinned():
    # The backend runs in pip's isolated build environment, so its installed version is not checked.
    build_system = _pyproject()["build-system"]
    requires = build_system["requires"]
    pins = [EXACT_PIN.fullmatch(requirement) for requirement in requires]
    assert build_system["build-backend"] == "setuptools.build_meta"
    assert all(pins), f"build requirements are not all exact '==' pins: {requires}"
    assert "setuptools" in {pin["name"] for pin in pins}, f"setuptools is not pinned: {requires}"


def test_installed_versions_match_runtime_and_dev_pins():
    requirements = _runtime_and_dev_requirements(_pyproject())
    assert requirements, "pyproject.toml declares no runtime or dev requirements"
    problems, pins = [], {}
    for requirement in requirements:
        match = EXACT_PIN.fullmatch(requirement)
        if match is None:
            problems.append(f"{requirement!r} is not an exact '==' pin")
        else:
            pins[match["name"]] = match["version"]
    problems += _installed_problems(pins, "pinned")
    assert not problems, "; ".join(problems)


def test_package_is_imported_from_src():
    module = importlib.import_module("content_boundary_lab")
    location = Path(module.__file__ or "").resolve()
    assert location == ROOT / "src" / "content_boundary_lab" / "__init__.py"


def test_lock_entries_are_exact_pins_with_sha256_hashes():
    lines = _lock_requirements()
    assert lines, "requirements.lock contains no requirements"
    problems, seen = [], set()
    for line in lines:
        requirement, *options = line.split()
        match = EXACT_PIN.fullmatch(requirement)
        if match is None:
            problems.append(f"{requirement!r} is not an exact '==' pin")
            continue
        name = _canonical(match["name"])
        if name in seen:
            problems.append(f"{name} appears more than once")
        seen.add(name)
        if not options:
            problems.append(f"{name} has no --hash=sha256 option")
        problems += [
            f"{name}: {option!r} is not --hash=sha256:<64 hex digits>"
            for option in options
            if not SHA256_OPTION.fullmatch(option)
        ]
    assert not problems, "; ".join(problems)


def test_direct_pins_match_the_lock():
    locked = _locked_versions()
    problems = []
    for requirement in _runtime_and_dev_requirements(_pyproject()):
        match = EXACT_PIN.fullmatch(requirement)
        if match is None:
            problems.append(f"{requirement!r} cannot be compared with the lock: not an exact '==' pin")
            continue
        in_lock = locked.get(_canonical(match["name"]), "no entry")
        if in_lock != match["version"]:
            problems.append(f"{match['name']}: pyproject pins {match['version']}, lock has {in_lock}")
    assert not problems, "; ".join(problems)


def test_locked_dependencies_are_installed_at_locked_versions():
    # Extra packages are tolerated here; exact-set checking is test_clean_environment_*.
    locked = _locked_versions()
    assert locked, "requirements.lock pins nothing"
    problems = _installed_problems(locked, "locked")
    assert not problems, "; ".join(problems)


@pytest.mark.clean_env
def test_clean_environment_contains_exactly_the_locked_set():
    """Deselected by default. Run `pytest -m clean_env` in a fresh venv built from requirements.lock."""
    installed = {_canonical(dist.metadata["Name"]) for dist in importlib.metadata.distributions()}
    locked = set(_locked_versions())
    expected_tooling = {"pip"}
    local_editable = {"content-boundary-lab"}
    build_backend = {"setuptools"}  # lives only in pip's isolated build environment
    problems = []
    if missing := (locked | local_editable) - installed:
        problems.append(f"missing: {sorted(missing)}")
    if leaked := installed & build_backend:
        problems.append(f"isolated build backend present in the environment: {sorted(leaked)}")
    if unexpected := installed - locked - expected_tooling - local_editable - build_backend:
        problems.append(f"unexpected: {sorted(unexpected)}")
    direct_url = _editable_direct_url()
    if direct_url is None or not direct_url.get("dir_info", {}).get("editable") or direct_url["url"] != ROOT.as_uri():
        problems.append(f"content-boundary-lab is not an editable install of {ROOT}: {direct_url}")
    assert not problems, "; ".join(problems)

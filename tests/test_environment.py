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

# The reviewed dependency set (docs/decisions.md AM-9, AM-14). Changing it is a deliberate edit of this test.
APPROVED_RUNTIME_PINS = {"cryptography": "50.0.2", "fastapi": "0.141.1", "pyjwt": "2.15.1"}
APPROVED_DEV_PINS = {"httpx2": "2.13.1", "pytest": "9.1.1"}
TRANSITIVE_ONLY = {"cffi", "pycparser"}  # locked, never declared directly
APPROVED_LOCK = {
    "annotated-doc": "0.0.4",
    "annotated-types": "0.7.0",
    "anyio": "4.14.2",
    "cffi": "2.1.1",
    "cryptography": "50.0.2",
    "fastapi": "0.141.1",
    "h11": "0.16.0",
    "httpcore2": "2.13.1",
    "httpx2": "2.13.1",
    "idna": "3.18",
    "iniconfig": "2.3.1",
    "packaging": "26.3",
    "pluggy": "1.7.0",
    "pycparser": "3.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "pygments": "2.21.0",
    "pyjwt": "2.15.1",
    "pytest": "9.1.1",
    "starlette": "1.3.1",
    "truststore": "0.10.5",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.2",
}


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


def test_direct_dependencies_are_exactly_the_approved_pins():
    project = _pyproject()["project"]

    def pins(requirements):
        matches = [EXACT_PIN.fullmatch(requirement) for requirement in requirements]
        assert all(matches), f"not exact '==' pins without extras: {requirements}"
        found = {_canonical(match["name"]): match["version"] for match in matches}
        assert len(found) == len(matches), f"a distribution is declared twice: {requirements}"
        return found

    assert pins(project["dependencies"]) == APPROVED_RUNTIME_PINS
    assert set(project["optional-dependencies"]) == {"dev"}
    assert pins(project["optional-dependencies"]["dev"]) == APPROVED_DEV_PINS


def test_the_lock_is_exactly_the_reviewed_set_of_23_distributions():
    assert _locked_versions() == APPROVED_LOCK
    assert len(APPROVED_LOCK) == 23


def test_transitive_distributions_are_locked_but_not_declared_directly():
    requirements = _runtime_and_dev_requirements(_pyproject())
    declared = {_canonical(EXACT_PIN.fullmatch(requirement)["name"]) for requirement in requirements}
    assert TRANSITIVE_ONLY <= set(_locked_versions())
    assert not TRANSITIVE_ONLY & declared


def test_pinned_cryptography_stack_imports_and_enables_es256():
    """Import-level compatibility only: PyJWT found cryptography and offers ES256. No key is created or used here."""
    from jwt import algorithms

    assert algorithms.has_crypto
    assert "ES256" in algorithms.get_default_algorithms()


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

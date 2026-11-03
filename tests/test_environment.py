"""Environment checks: interpreter, build-backend pin, installed dependency pins, import location."""

import importlib
import importlib.metadata
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXACT_PIN = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9._+!-]+)")


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
    problems = []
    for requirement in requirements:
        match = EXACT_PIN.fullmatch(requirement)
        if match is None:
            problems.append(f"{requirement!r} is not an exact '==' pin")
            continue
        name, pinned = match["name"], match["version"]
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            problems.append(f"{name}: pinned {pinned}, not installed")
            continue
        if installed != pinned:
            problems.append(f"{name}: pinned {pinned}, installed {installed}")
    assert not problems, "; ".join(problems)


def test_package_is_imported_from_src():
    module = importlib.import_module("content_boundary_lab")
    location = Path(module.__file__ or "").resolve()
    assert location == ROOT / "src" / "content_boundary_lab" / "__init__.py"

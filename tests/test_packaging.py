"""M2A, layer 6 of the isolation proof (Addendum §5.5): the built distributions contain none of labs/, tests/, tools/ or docs/,
no module named for a vulnerable variant, and no key material. Opt-in: `pytest -m packaging` (it fetches the pinned build backend).

The project is copied, a scratch environment gets only the pinned backend, and the wheel and the sdist are built with it. The
same checker runs on a second build of a copy into which a labs/ package and a module named for a vulnerable variant have been
put under src/, to show that it would notice (the negative control). Nothing is built in the repository itself.
"""

import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.packaging

ROOT = Path(__file__).resolve().parents[1]
IGNORED = shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__", "*.egg-info", "dist", "build", ".dev")
FORBIDDEN_TOP = {"labs", "tests", "tools", "docs"}
FORBIDDEN_SUFFIXES = (".pem", ".key", ".sqlite3", ".db")


def problems(names: list[str]) -> list[str]:
    found = []
    for name in names:
        parts = Path(name).parts
        inner = parts[1:] if parts and parts[0].startswith("content_boundary_lab-") else parts  # an sdist keeps one top directory
        if set(inner) & FORBIDDEN_TOP or "labs" in inner or (len(inner) > 1 and inner[0] == "src" and "labs" in inner[1:2]):
            found.append(f"{name}: a directory that is not part of the reference")
        if "vulnerable" in name.lower():
            found.append(f"{name}: named for a vulnerable variant")
        if name.endswith(FORBIDDEN_SUFFIXES):
            found.append(f"{name}: key or database material")
    return found


def build(tmp_path: Path, label: str, extra: bool) -> tuple[list[str], list[str]]:
    project = tmp_path / label
    shutil.copytree(ROOT, project, ignore=IGNORED)
    if extra:  # the negative control: what a careless change would put into the package
        (project / "src" / "labs").mkdir()
        (project / "src" / "labs" / "__init__.py").write_text("")
        (project / "src" / "content_boundary_lab" / "vulnerable_probe.py").write_text("")
    backend = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]["requires"][0]  # the pinned setuptools
    env = tmp_path / f"{label}-env"
    subprocess.run([sys.executable, "-m", "venv", str(env)], check=True, capture_output=True)
    python = str(env / "bin" / "python")
    subprocess.run([python, "-m", "pip", "install", "--quiet", backend], check=True, capture_output=True, timeout=300)
    out = tmp_path / f"{label}-dist"
    out.mkdir()
    build_script = "from setuptools import build_meta as b; b.build_wheel('{0}'); b.build_sdist('{0}')".format(out)
    subprocess.run([python, "-c", build_script], cwd=project, check=True, capture_output=True, timeout=300)
    wheel = next(out.glob("*.whl"))
    sdist = next(out.glob("*.tar.gz"))
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_names = archive.getnames()
    return wheel_names, sdist_names


def test_the_built_wheel_and_sdist_hold_the_reference_and_nothing_vulnerable(tmp_path):
    wheel, sdist = build(tmp_path, "clean", extra=False)
    assert "content_boundary_lab/runner.py" in wheel and "content_boundary_lab/assets.py" in wheel  # the checker is looking at the package
    assert any(name.endswith("src/content_boundary_lab/runner.py") for name in sdist)
    assert problems(wheel) == [] and problems(sdist) == []


def test_the_checker_notices_a_labs_package_and_a_vulnerable_module_when_they_are_put_in(tmp_path):
    wheel, sdist = build(tmp_path, "control", extra=True)
    assert any("labs" in problem for problem in problems(wheel)) and any("vulnerable_probe" in problem for problem in problems(wheel))
    assert any("vulnerable_probe" in problem for problem in problems(sdist))

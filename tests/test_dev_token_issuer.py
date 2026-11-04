"""tools/dev_token_issuer.py: the development issuer for manual runs (M0 Addendum §5.5), outside the package.

It makes a throwaway signing key in a git-ignored directory, the trusted settings that name only the public half, and
short-lived tokens signed with it. These tests run it as an operator would, in a temporary directory, and check what it
leaves behind and that what it mints is accepted by the lab's own verifier (and nothing else is). Synthetic subjects only.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from content_boundary_lab import identity
from content_boundary_lab.clock import SystemClock
from content_boundary_lab.settings import load_settings

TOOL = Path(__file__).resolve().parents[1] / "tools" / "dev_token_issuer.py"


def tool(*arguments: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), *arguments], capture_output=True, text=True, cwd=cwd, timeout=60, check=False
    )


@pytest.fixture
def dev(tmp_path) -> Path:
    directory = tmp_path / ".dev"
    done = tool("setup", "--dir", str(directory), cwd=tmp_path)
    assert done.returncode == 0, done.stderr
    return directory


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_setup_leaves_a_private_key_the_trusted_settings_and_two_private_storage_directories(dev):
    assert sorted(path.name for path in dev.iterdir()) == ["jwks.json", "quarantine", "settings.toml", "signing-key.pem", "trusted"]
    assert mode(dev) == 0o700 and mode(dev / "signing-key.pem") == 0o600
    assert mode(dev / "trusted") == 0o700 and mode(dev / "quarantine") == 0o700


def test_setup_prints_where_everything_is_as_json(tmp_path):
    directory = tmp_path / ".dev"
    done = tool("setup", "--dir", str(directory), cwd=tmp_path)
    shown = json.loads(done.stdout)
    assert shown == {
        "directory": str(directory),
        "settings": str(directory / "settings.toml"),
        "trusted_root": str(directory / "trusted"),
        "quarantine_root": str(directory / "quarantine"),
        "database": str(directory / "lab.sqlite3"),
    }


def test_the_settings_it_writes_load_into_the_lab_with_one_public_key(dev):
    settings = load_settings(dev / "settings.toml")
    assert list(settings.public_keys) == ["dev-key-1"]
    assert settings.issuer.startswith("https://") and settings.audience.startswith("https://")


def test_nothing_but_the_signing_key_holds_the_private_half(dev):
    pem = (dev / "signing-key.pem").read_bytes()
    private = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(private, ec.EllipticCurvePrivateKey) and isinstance(private.curve, ec.SECP256R1)
    scalar = private.private_numbers().private_value.to_bytes(32, "big")
    for name in ("jwks.json", "settings.toml"):
        body = (dev / name).read_bytes()
        assert scalar not in body and b"PRIVATE" not in body
    assert "d" not in json.loads((dev / "jwks.json").read_text())["keys"][0]


def test_setup_twice_changes_nothing_and_says_so(tmp_path, dev):
    before = {path.name: path.read_bytes() for path in dev.iterdir() if path.is_file()}
    done = tool("setup", "--dir", str(dev), cwd=tmp_path)
    assert done.returncode == 2 and "already" in done.stderr
    assert {path.name: path.read_bytes() for path in dev.iterdir() if path.is_file()} == before


def test_setup_will_not_write_through_a_symbolic_link(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / ".dev"
    link.symlink_to(target, target_is_directory=True)
    done = tool("setup", "--dir", str(link), cwd=tmp_path)
    assert done.returncode == 2 and list(target.iterdir()) == []


def minted(dev: Path, *arguments: str, cwd: Path) -> subprocess.CompletedProcess:
    return tool("mint", "--dir", str(dev), *arguments, cwd=cwd)


def test_a_minted_token_is_accepted_by_the_lab_s_own_verifier_as_that_subject(tmp_path, dev):
    done = minted(dev, "--subject", "dev-vendor-a", cwd=tmp_path)
    assert done.returncode == 0 and done.stdout.count("\n") == 1  # the token and nothing else
    who = identity.authenticate(f"Bearer {done.stdout.strip()}", load_settings(dev / "settings.toml"), SystemClock())
    assert (who.issuer, who.subject) == (load_settings(dev / "settings.toml").issuer, "dev-vendor-a")


def test_a_token_lives_for_the_time_asked_and_five_minutes_by_default(tmp_path, dev):
    import base64

    def claims(token: str) -> dict:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))

    default = claims(minted(dev, "--subject", "dev-vendor-a", cwd=tmp_path).stdout.strip())
    short = claims(minted(dev, "--subject", "dev-vendor-a", "--ttl-seconds", "60", cwd=tmp_path).stdout.strip())
    assert default["exp"] - default["iat"] == 300 and short["exp"] - short["iat"] == 60
    assert default["nbf"] == default["iat"]


@pytest.mark.parametrize("ttl", ["0", "-5", str(identity.MAX_LIFETIME_SECONDS + 1), "ten", ""])
def test_a_lifetime_the_verifier_would_refuse_is_not_minted(tmp_path, dev, ttl):
    done = minted(dev, "--subject", "dev-vendor-a", "--ttl-seconds", ttl, cwd=tmp_path)
    assert done.returncode == 2 and done.stdout == ""


@pytest.mark.parametrize("subject", ["", " ", "a b", "x" * 201, "line\nbreak", "café"])
def test_a_subject_that_is_not_plain_visible_text_is_not_minted(tmp_path, dev, subject):
    done = minted(dev, "--subject", subject, cwd=tmp_path)
    assert done.returncode == 2 and done.stdout == ""


def test_without_a_setup_there_is_no_key_and_no_token(tmp_path):
    done = minted(tmp_path / ".dev", "--subject", "dev-vendor-a", cwd=tmp_path)
    assert done.returncode == 2 and done.stdout == "" and "setup" in done.stderr


def test_a_token_from_another_setup_is_refused_by_this_one(tmp_path, dev):
    other = tmp_path / "other" / ".dev"
    other.parent.mkdir()
    assert tool("setup", "--dir", str(other), cwd=tmp_path).returncode == 0
    foreign = minted(other, "--subject", "dev-vendor-a", cwd=tmp_path).stdout.strip()
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate(f"Bearer {foreign}", load_settings(dev / "settings.toml"), SystemClock())


def test_the_tool_writes_only_inside_the_directory_it_was_given(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    before = sorted(work.rglob("*"))
    tool("setup", "--dir", str(tmp_path / "area" / ".dev"), cwd=work)  # the parent does not exist: refused, not created
    assert sorted(work.rglob("*")) == before


def test_the_tool_is_outside_the_package_so_it_is_not_packaged():
    assert "src" not in TOOL.relative_to(TOOL.parents[1]).parts and TOOL.parent.name == "tools"
    assert not (TOOL.parent / "__init__.py").exists()

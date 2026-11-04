"""Source guard: the runner is the one place the lab's trusted dependencies are chosen, and it chooses them without help.

Four things are kept true here, each with a bad sample the rule must flag and an ordinary one it must leave alone:
the runner offers a fixed, named set of options, none of which picks an address, a scanner, a clock or a switch; it reads no
environment variable; the only address in it is the loopback, and that is what it hands the server; and uvicorn is imported
in one function of one module and nowhere else, with no test importing uvicorn or a socket (M0 Addendum §5.5, §6 M1M).
Like the other guards, this catches accidents and drift; it is not a general static analyser.
"""

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "content_boundary_lab"
RUNNER = Path("runner.py")
LOOPBACK = "127.0.0.1"
OPTIONS = {
    "--settings",
    "--database",
    "--trusted-root",
    "--quarantine-root",
    "--max-upload-bytes",
    "--port",
    "--production-id",
    "--delivery-id",
    "--min-age-seconds",
}
# What the call to uvicorn fixes as literals. Left out, uvicorn would take workers from WEB_CONCURRENCY and trust proxy headers.
SERVER_SETTINGS = {
    "workers": 1,
    "reload": False,
    "http": "h11",
    "loop": "asyncio",
    "proxy_headers": False,
    "server_header": False,
}
ENVIRONMENT_NAMES = {"environ", "environb", "getenv", "getenvb", "putenv", "unsetenv"}
ADDRESS = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FORBIDDEN_IN_TESTS = {"uvicorn", "socket"}


def tree_of(relative: Path) -> ast.Module:
    return ast.parse((PACKAGE / relative).read_text())


def options_in(source: str) -> set[str]:
    """Every `--name` given as an argument to an add_argument(...) call."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
            found |= {arg.value for arg in node.args if isinstance(arg, ast.Constant) and str(arg.value).startswith("--")}
    return found


def environment_reads(source: str) -> list[int]:
    return [
        node.lineno
        for node in ast.walk(ast.parse(source))
        if (isinstance(node, ast.Attribute) and node.attr in ENVIRONMENT_NAMES)
        or (isinstance(node, ast.ImportFrom) and any(alias.name in ENVIRONMENT_NAMES | {"*"} for alias in node.names) and node.module == "os")
    ]


def addresses_in(source: str) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found |= set(ADDRESS.findall(node.value))
            found |= {"localhost"} if "localhost" in node.value.lower() else set()
            found |= {"::"} if "::" in node.value else set()
    return found


def constructions(source: str, name: str) -> list[int]:
    return [
        node.lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and ((isinstance(node.func, ast.Name) and node.func.id == name) or (isinstance(node.func, ast.Attribute) and node.func.attr == name))
    ]


def imports_of(source: str, modules: set[str]) -> list[tuple[int, str, bool]]:
    """(line, module, inside_a_function) for each import of one of `modules`."""
    tree = ast.parse(source)
    inside = {
        id(node) for function in ast.walk(tree) if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(function)
    }
    found = []
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        found += [(node.lineno, name, id(node) in inside) for name in names if name in modules]
    return found


# --- the guards have teeth ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "parser.add_argument('--host', default='0.0.0.0')",
        "sub.add_argument('--scanner', choices=['real'])",
        "sub.add_argument('--no-auth', action='store_true')",
        "sub.add_argument('--settings'); sub.add_argument('--reload')",
    ],
)
def test_the_option_rule_sees_an_option_that_is_not_on_the_list(source):
    assert options_in(source) - OPTIONS


def test_the_option_rule_leaves_the_listed_options_alone():
    assert not options_in("sub.add_argument('--port', type=int, required=True); sub.add_argument('command')") - OPTIONS


@pytest.mark.parametrize("source", ["import os\nos.environ['HOST']", "import os\nos.getenv('PORT')", "from os import environ", "from os import *"])
def test_the_environment_rule_flags_every_way_to_read_it(source):
    assert environment_reads(source)


def test_the_environment_rule_leaves_other_uses_of_os_alone():
    assert environment_reads("import os\nos.path.abspath('x')\nos.umask(0o077)\nos.geteuid()") == []


@pytest.mark.parametrize("source", ["HOST = '0.0.0.0'", "bind('192.168.1.5')", "url = 'http://localhost:80'", "listen('::')"])
def test_the_address_rule_flags_any_address_but_the_loopback(source):
    assert addresses_in(source) - {LOOPBACK}


def test_the_address_rule_leaves_the_loopback_and_ordinary_text_alone():
    assert addresses_in("HOST = '127.0.0.1'\nhelp = 'serve it on 127.0.0.1.'\nversion = 'a 1.2 b'") - {LOOPBACK} == set()


def test_the_import_rule_sees_where_a_module_is_imported():
    assert imports_of("import uvicorn", {"uvicorn"}) == [(1, "uvicorn", False)]
    assert imports_of("def f():\n    import uvicorn", {"uvicorn"}) == [(2, "uvicorn", True)]
    assert imports_of("from uvicorn.config import Config", {"uvicorn"}) == [(1, "uvicorn", False)]
    assert imports_of("import json", {"uvicorn"}) == []


# --- the runner -----------------------------------------------------------------------------------------------------------------------


def test_the_runner_offers_exactly_the_listed_options():
    assert options_in((PACKAGE / RUNNER).read_text()) == OPTIONS


def test_the_runner_reads_no_environment_variable():
    assert environment_reads((PACKAGE / RUNNER).read_text()) == []


def test_the_only_address_in_the_runner_is_the_loopback():
    assert addresses_in((PACKAGE / RUNNER).read_text()) == {LOOPBACK}
    assignments = [
        node.value.value
        for node in tree_of(RUNNER).body
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "HOST" for t in node.targets)
    ]
    assert assignments == [LOOPBACK]


def test_the_server_is_given_the_loopback_constant_and_nothing_else_names_a_host():
    tree = tree_of(RUNNER)
    serve = [
        node
        for function in ast.walk(tree)
        if isinstance(function, ast.FunctionDef) and function.name == "_serve"
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "serve"
    ]
    assert len(serve) == 1 and isinstance(serve[0].args[1], ast.Name) and serve[0].args[1].id == "HOST"
    runs = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run" and getattr(node.func.value, "id", "") == "uvicorn"
    ]
    assert len(runs) == 1
    assert {keyword.arg for keyword in runs[0].keywords} == set(SERVER_SETTINGS) | {"host", "port"}
    assert all(not any(isinstance(sub, ast.Constant) and sub.value == LOOPBACK for sub in ast.walk(k.value)) for k in runs[0].keywords)
    fixed = {k.arg: ast.literal_eval(k.value) for k in runs[0].keywords if isinstance(k.value, ast.Constant)}
    assert fixed == SERVER_SETTINGS  # each of these is a literal in the call, so no variable, option or file can set it


def test_only_the_runner_builds_the_dependencies():
    builders = {path.name for path in PACKAGE.glob("*.py") if constructions(path.read_text(), "Dependencies")}
    assert builders == {"runner.py"}


def test_uvicorn_is_imported_in_one_function_of_the_runner_and_nowhere_else_in_the_package():
    found = {path.name: imports_of(path.read_text(), {"uvicorn"}) for path in PACKAGE.glob("*.py")}
    assert {name: seen for name, seen in found.items() if seen} == {"runner.py": [(found["runner.py"][0][0], "uvicorn", True)]}


def socket_uses_other_than_refusing(source: str) -> list[int]:
    """Lines where the name `socket` is used for anything but `monkeypatch.setattr(socket, name, refuse)`."""
    tree = ast.parse(source)
    refusals = {
        id(call.args[0])
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "setattr"
        and call.args
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "socket"
    }
    return [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "socket" and id(node) not in refusals]


def test_the_socket_rule_tells_refusing_the_network_from_using_it():
    refusing = "import socket\nmonkeypatch.setattr(socket, 'socket', refuse)"
    using = "import socket\nconnection = socket.socket()\nmonkeypatch.setattr(socket, 'socket', refuse)"
    assert socket_uses_other_than_refusing(refusing) == []
    assert socket_uses_other_than_refusing(using) == [2]


def test_no_test_imports_uvicorn_and_none_uses_a_socket_except_to_refuse_the_network():
    """Addendum §5.5: the lab apps run in-process; nothing a test does listens or connects.

    Two tests import socket for the opposite reason: to replace its functions with refusals while the verifier and the
    settings loader run, which is how they show those make no network call. That is the only use allowed.
    """
    offenders = []
    for path in sorted([*(ROOT / "tests").rglob("*.py"), *(ROOT / "labs").rglob("*.py")]):  # labs/ and tests/ alike (§5.5 item 7)
        source = path.read_text()
        offenders += [f"{path.relative_to(ROOT)}:{line} imports uvicorn" for line, *_ in imports_of(source, {"uvicorn"})]
        if imports_of(source, {"socket"}):
            offenders += [f"{path.relative_to(ROOT)}:{line} uses socket" for line in socket_uses_other_than_refusing(source)]
    assert offenders == []

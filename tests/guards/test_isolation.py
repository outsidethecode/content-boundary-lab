"""Source-tree isolation guards: AST checks that reference code cannot load or select lab code.

Each rule names the exact syntax it flags. The guards catch accidents and drift; they are not a general
static analyser and do not stop a maintainer who deliberately edits them (decisions R7).
"""

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "content_boundary_lab"
SOURCE_FILES = sorted(PACKAGE.rglob("*.py"))
LAB_FILES = sorted((ROOT / "labs").rglob("*.py"))  # labs/ is introduced later; no files until then
TEST_FILES = sorted((ROOT / "tests").rglob("*.py"))

# Modules, relative to the package, allowed to read environment variables or command-line arguments.
# Add a module only in the slice that needs it, after review, and never to select an implementation (decisions §4).
# The runner (M1M) is the composition root and takes its command line from argparse; tests/guards/test_runner_scope.py
# holds it to a fixed list of options and to reading no environment variable at all.
ENVIRONMENT_READERS: frozenset[str] = frozenset({"runner.py"})

OVERRIDES = "dependency_overrides"
FORBIDDEN_IMPORT_ROOTS = {"labs", "tests"}
ENVIRONMENT_ATTRIBUTES = {
    "os": {"environ", "environb", "getenv", "getenvb", "putenv", "unsetenv"},
    "sys": {"argv", "orig_argv"},
}
COMMAND_LINE_PARSERS = {"argparse", "optparse", "getopt"}
SELECTOR_TOKENS = {"vulnerable", "insecure"}
DYNAMIC_LOADING_MODULES = {"importlib", "runpy", "pkgutil", "zipimport", "pickle", "marshal", "shelve"}
DYNAMIC_BUILTINS = {"eval", "exec", "__import__"}
IMPORT_SYSTEM_STATE = {"path", "modules", "meta_path", "path_hooks", "path_importer_cache"}
DOCUMENTATION_URLS = {"docs_url", "redoc_url", "openapi_url"}
READ_ONLY_CALLS = {"len", "bool"}

Violations = list[tuple[int, str]]


def _imported_roots(tree: ast.Module) -> Violations:
    """(line, top-level module) of every absolute import; relative imports stay inside the package."""
    roots = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots += [(node.lineno, alias.name.split(".")[0]) for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.append((node.lineno, node.module.split(".")[0]))
    return roots


def _from_imports(tree: ast.Module, module: str) -> Violations:
    """(line, name) for each `from <module> import name`; the name is '*' for a star import."""
    return [
        (node.lineno, alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == module
        for alias in node.names
    ]


def _module_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> top-level module, for `import os` and `import os as o`."""
    return {
        (alias.asname or alias.name.split(".")[0]): alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }


def _identifiers(tree: ast.Module) -> Violations:
    """(line, name) of each identifier used or bound: names, attributes, definitions, arguments, keywords, imports."""
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.append((node.lineno, node.id))
        elif isinstance(node, ast.Attribute):
            names.append((node.lineno, node.attr))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append((node.lineno, node.name))
        elif isinstance(node, ast.arg):
            names.append((node.lineno, node.arg))
        elif isinstance(node, ast.keyword) and node.arg:
            names.append((node.value.lineno, node.arg))
        elif isinstance(node, ast.alias):
            names += [(node.lineno, name) for name in (node.name, node.asname) if name]
    return names


def _tokens(name: str) -> set[str]:
    """Lower-case words of a snake_case or CamelCase identifier."""
    return {word.lower() for word in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", name)}


def _fastapi_names(tree: ast.Module) -> set[str]:
    """`FastAPI` plus any `from fastapi import FastAPI as name` alias; other rebinding is not followed."""
    aliases = {
        alias.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in {"fastapi", "fastapi.applications"}
        for alias in node.names
        if alias.name == "FastAPI" and alias.asname
    }
    return {"FastAPI"} | aliases


def _fastapi_calls(tree: ast.Module) -> list[ast.Call]:
    """Calls of FastAPI by name or alias, or as `<module>.FastAPI(...)`."""
    names = _fastapi_names(tree)
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id in names)
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "FastAPI")
        )
    ]


def _read_only(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """True when the expression is only compared, negated, asserted, measured or formatted."""
    parent = parents.get(node)
    return (
        isinstance(parent, (ast.Compare, ast.FormattedValue))
        or (isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not))
        or (isinstance(parent, ast.Assert) and parent.test is node)
        or (
            isinstance(parent, ast.Call)
            and isinstance(parent.func, ast.Name)
            and parent.func.id in READ_ONLY_CALLS
            and node in parent.args
        )
    )


def _attribute_function(node: ast.AST) -> str | None:
    """'getattr', 'setattr' or 'delattr' when node is such a call naming dependency_overrides."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"getattr", "setattr", "delattr"}
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == OVERRIDES
    ):
        return node.func.id
    return None


def lab_import_violations(tree: ast.Module) -> Violations:
    """Control 1: an import whose top-level module is labs or tests."""
    return [
        (line, f"imports {root!r}, which is outside the reference package")
        for line, root in _imported_roots(tree)
        if root in FORBIDDEN_IMPORT_ROOTS
    ]


def environment_violations(tree: ast.Module) -> Violations:
    """Control 2: reading os.environ/getenv-style or sys.argv-style values, or importing a command-line parser."""
    aliases, found = _module_aliases(tree), []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = aliases.get(node.value.id)
            if node.attr in ENVIRONMENT_ATTRIBUTES.get(module, ()):
                found.append((node.lineno, f"reads {module}.{node.attr}"))
    for module, attributes in ENVIRONMENT_ATTRIBUTES.items():
        found += [
            (line, f"imports {module}.{name}") for line, name in _from_imports(tree, module) if name in attributes | {"*"}
        ]
    found += [
        (line, f"imports command-line parser {root!r}")
        for line, root in _imported_roots(tree)
        if root in COMMAND_LINE_PARSERS
    ]
    return found


def selector_name_violations(tree: ast.Module) -> Violations:
    """Control 2: an identifier containing the word 'vulnerable' or 'insecure' (a flag, setting or parameter)."""
    return [
        (line, f"identifier {name!r} names a vulnerable or insecure variant")
        for line, name in _identifiers(tree)
        if _tokens(name) & SELECTOR_TOKENS
    ]


def override_mentions(tree: ast.Module) -> Violations:
    """Control 3, for src/ and labs/: any identifier or exact string constant dependency_overrides."""
    named = [line for line, name in _identifiers(tree) if name == OVERRIDES]
    quoted = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Constant) and node.value == OVERRIDES]
    return [(line, f"mentions {OVERRIDES}") for line in named + quoted]


def override_misuse_in_tests(tree: ast.Module) -> Violations:
    """Controls 3 and 5, for tests/: any use of dependency_overrides except a read-only comparison."""
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    found = []
    for node in ast.walk(tree):
        accessor = _attribute_function(node)
        direct = isinstance(node, ast.Attribute) and node.attr == OVERRIDES
        if (direct or accessor) and (accessor in {"setattr", "delattr"} or not _read_only(node, parents)):
            found.append((node.lineno, f"uses {OVERRIDES} other than in a read-only comparison"))
    return found


def dynamic_loading_violations(tree: ast.Module) -> Violations:
    """Control 4: importing a code-loading module, eval/exec/__import__, or touching the import system's state."""
    aliases = _module_aliases(tree)
    found = [(line, f"imports {root!r}") for line, root in _imported_roots(tree) if root in DYNAMIC_LOADING_MODULES]
    found += [
        (line, f"imports sys.{name}") for line, name in _from_imports(tree, "sys") if name in IMPORT_SYSTEM_STATE | {"*"}
    ]
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in DYNAMIC_BUILTINS:
            found.append((node.lineno, f"uses {node.id}"))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = aliases.get(node.value.id)
            if (module == "builtins" and node.attr in DYNAMIC_BUILTINS) or (
                module == "sys" and node.attr in IMPORT_SYSTEM_STATE
            ):
                found.append((node.lineno, f"uses {module}.{node.attr}"))
    return found


def fastapi_documentation_violations(tree: ast.Module) -> Violations:
    """Control 6: a FastAPI(...) construction that does not set docs_url, redoc_url and openapi_url to None."""
    found = []
    for call in _fastapi_calls(tree):
        disabled = {kw.arg for kw in call.keywords if isinstance(kw.value, ast.Constant) and kw.value.value is None}
        if missing := DOCUMENTATION_URLS - disabled:
            found.append((call.lineno, f"FastAPI(...) must set {sorted(missing)} to None"))
    return found


# Bad samples: each rule must flag them, with a message containing the second item.
FLAGGED = [
    (rule, source, expected)
    for rule, cases in {
        lab_import_violations: [
            ("import labs.f02.vulnerable", "'labs'"),
            ("from labs.f02 import vulnerable", "'labs'"),
            ("import tests.support.token_issuer", "'tests'"),
            ("def f():\n    from tests import support", "'tests'"),
        ],
        environment_violations: [
            ("import os\nmode = os.environ['MODE']", "os.environ"),
            ("import os\nmode = os.getenv('MODE')", "os.getenv"),
            ("import os as o\nmode = o.environ", "os.environ"),
            ("from os import environ", "os.environ"),
            ("from os import *", "os.*"),
            ("import sys\nmode = sys.argv[1]", "sys.argv"),
            ("import argparse", "argparse"),
        ],
        selector_name_violations: [
            ("use_vulnerable = True", "use_vulnerable"),
            ("class Settings:\n    vulnerable_mode: bool = False", "vulnerable_mode"),
            ("def build(InsecureStore): ...", "InsecureStore"),
            ("from impl import vulnerable_scan", "vulnerable_scan"),
            ("make(vulnerable=True)", "vulnerable"),
        ],
        override_mentions: [
            ("app.dependency_overrides[get_store] = fake", OVERRIDES),
            ("assert app.dependency_overrides == {}", OVERRIDES),
            ("setattr(app, 'dependency_overrides', {})", OVERRIDES),
            ("def build(dependency_overrides): ...", OVERRIDES),
        ],
        override_misuse_in_tests: [
            ("app.dependency_overrides[dep] = fake", "read-only"),
            ("app.dependency_overrides = {}", "read-only"),
            ("app.dependency_overrides.update({dep: fake})", "read-only"),
            ("app.dependency_overrides |= {dep: fake}", "read-only"),
            ("del app.dependency_overrides[dep]", "read-only"),
            ("overrides = app.dependency_overrides\noverrides[dep] = fake", "read-only"),
            ("setattr(app, 'dependency_overrides', {})", "read-only"),
            ("getattr(app, 'dependency_overrides')[dep] = fake", "read-only"),
        ],
        dynamic_loading_violations: [
            ("import importlib", "'importlib'"),
            ("from importlib import import_module", "'importlib'"),
            ("import runpy", "'runpy'"),
            ("import pickle", "'pickle'"),
            ("eval('1 + 1')", "eval"),
            ("exec('x = 1')", "exec"),
            ("__import__('labs')", "__import__"),
            ("import builtins\nbuiltins.__import__ = None", "builtins.__import__"),
            ("import sys\nsys.path.insert(0, 'labs')", "sys.path"),
            ("import sys\nsys.modules['m'] = None", "sys.modules"),
            ("from sys import modules", "sys.modules"),
        ],
        fastapi_documentation_violations: [
            ("from fastapi import FastAPI\napp = FastAPI()", "docs_url"),
            ("app = FastAPI(docs_url=None, redoc_url=None)", "openapi_url"),
            ("app = FastAPI(docs_url=None, redoc_url=None, openapi_url='/o')", "openapi_url"),
            ("app = FastAPI(**options)", "docs_url"),
            ("import fastapi\napp = fastapi.FastAPI()", "docs_url"),
            ("from fastapi import FastAPI as API\napp = API()", "docs_url"),
            ("from fastapi.applications import FastAPI as API\napp = API(docs_url=None)", "openapi_url"),
        ],
    }.items()
    for source, expected in cases
]

# Good samples: ordinary code each rule must leave alone (false-positive controls).
ACCEPTED = [
    (lab_import_violations, "import os\nfrom pathlib import Path\nfrom . import app\nfrom content_boundary_lab import app"),
    (environment_violations, "import os\nimport sys\nos.makedirs('x', exist_ok=True)\nos.path.join('a', 'b')\nsys.exit(1)"),
    (selector_name_violations, "label = 'table'\ndef reject_unsupported(file): ..."),
    (override_mentions, "app.openapi_url = None"),
    (override_misuse_in_tests, "assert app.dependency_overrides == {}"),
    (override_misuse_in_tests, "assert not app.dependency_overrides"),
    (override_misuse_in_tests, "assert len(app.dependency_overrides) == 0"),
    (override_misuse_in_tests, "assert dep not in app.dependency_overrides"),
    (override_misuse_in_tests, "assert getattr(app, 'dependency_overrides') == {}"),
    (override_misuse_in_tests, "assert ok, f'overrides: {app.dependency_overrides}'"),
    (dynamic_loading_violations, "import ast, re, sys\nre.compile('x')\nast.literal_eval('1')\nsys.exit(0)\nmodel.eval()"),
    (fastapi_documentation_violations, "app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)"),
    (fastapi_documentation_violations, "app = fastapi.FastAPI(docs_url=None, redoc_url=None, openapi_url=None)"),
    (
        fastapi_documentation_violations,
        "from fastapi import FastAPI as API\napp = API(docs_url=None, redoc_url=None, openapi_url=None)",
    ),
]


def _scan(paths: list[Path], rule) -> list[str]:
    return [
        f"{path.relative_to(ROOT).as_posix()}:{line}: {message}"
        for path in paths
        for line, message in rule(ast.parse(path.read_text(), filename=str(path)))
    ]


@pytest.mark.parametrize(
    ("rule", "source", "expected"), FLAGGED, ids=[f"{rule.__name__}-{n}" for n, (rule, _, _) in enumerate(FLAGGED)]
)
def test_rule_flags_its_bad_sample(rule, source, expected):
    messages = [message for _, message in rule(ast.parse(source))]
    assert any(expected in message for message in messages), messages


@pytest.mark.parametrize(
    ("rule", "source"), ACCEPTED, ids=[f"{rule.__name__}-{n}" for n, (rule, _) in enumerate(ACCEPTED)]
)
def test_rule_accepts_its_good_sample(rule, source):
    assert rule(ast.parse(source)) == []


def test_the_guards_see_the_reference_sources():
    assert PACKAGE / "app.py" in SOURCE_FILES


def test_labs_and_tests_are_not_inside_src():
    assert not [p for p in (ROOT / "src").rglob("*") if p.name in {"labs", "tests", "labs.py", "tests.py"}]


def test_reference_source_does_not_import_labs_or_tests():
    assert _scan(SOURCE_FILES, lab_import_violations) == []


def test_only_listed_modules_read_environment_or_command_line():
    unlisted = [p for p in SOURCE_FILES if p.relative_to(PACKAGE).as_posix() not in ENVIRONMENT_READERS]
    assert _scan(unlisted, environment_violations) == []


def test_reference_source_names_no_vulnerable_variant():
    assert _scan(SOURCE_FILES, selector_name_violations) == []


def test_reference_source_and_labs_never_mention_dependency_overrides():
    assert _scan(SOURCE_FILES + LAB_FILES, override_mentions) == []


def test_tests_only_read_dependency_overrides():
    assert _scan(TEST_FILES, override_misuse_in_tests) == []


def test_reference_source_has_no_dynamic_loading_or_evaluation():
    assert _scan(SOURCE_FILES, dynamic_loading_violations) == []


def test_every_fastapi_construction_disables_documentation():
    assert _scan(SOURCE_FILES, fastapi_documentation_violations) == []
    assert any(_fastapi_calls(ast.parse(p.read_text())) for p in SOURCE_FILES), "guard would be vacuous"

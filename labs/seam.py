"""A seam: one function that makes one security decision, and the only thing a finding changes.

A `Seam` pairs the reference function (as `src/` has it) with its seeded twin (as `labs/` has it). `applied(seam)` swaps the
one module attribute for the length of a block and puts the reference back when the block ends, however it ends. There is no
flag, no setting and no way to leave it swapped: outside the block the application is the reference application.

The swap is checked rather than trusted: the twin must take the same parameters as the reference, the reference must be what
is there when the block starts, and `moved()` compares every module-level name in the reference package inside and outside the
block so that a test can show that exactly one name differs.
"""

import inspect
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class Seam:
    finding: str
    module: ModuleType
    name: str
    reference: Callable
    vulnerable: Callable

    @property
    def where(self) -> str:
        return f"{self.module.__name__}.{self.name}"


def seam(finding: str, module: ModuleType, name: str, vulnerable: Callable) -> Seam:
    return Seam(finding, module, name, getattr(module, name), vulnerable)


def _parameters(function: Callable) -> list[tuple[str, object]]:
    return [(p.name, p.kind) for p in inspect.signature(function).parameters.values()]


@contextmanager
def applied(chosen: Seam) -> Iterator[Seam]:
    """Swap `chosen.module.<name>` for the seeded twin, and put the reference back at the end of the block."""
    if getattr(chosen.module, chosen.name) is not chosen.reference:
        raise RuntimeError(f"{chosen.where} is not the reference function: a seam is already applied")
    if _parameters(chosen.vulnerable) != _parameters(chosen.reference):
        raise TypeError(f"the twin of {chosen.where} must take the same parameters as the reference")
    setattr(chosen.module, chosen.name, chosen.vulnerable)
    try:
        yield chosen
    finally:
        setattr(chosen.module, chosen.name, chosen.reference)


def reference_names() -> dict[tuple[str, str], int]:
    """Every module-level name of the reference package, with the identity of what it is bound to."""
    found = {}
    for module_name, module in list(sys.modules.items()):
        if module is not None and (module_name == "content_boundary_lab" or module_name.startswith("content_boundary_lab.")):
            found |= {(module_name, name): id(value) for name, value in vars(module).items()}
    return found


def moved(chosen: Seam) -> set[tuple[str, str]]:
    """The module-level names of the reference package that differ inside the block from outside it."""
    outside = reference_names()
    with applied(chosen):
        inside = reference_names()
    return {key for key in outside.keys() | inside.keys() if outside.get(key) != inside.get(key)}

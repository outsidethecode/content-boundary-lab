"""A seam: one function that makes one security decision, and the only thing a finding changes.

A `Seam` pairs the reference function (as `src/` has it) with its seeded twin (as `labs/` has it). `applied(seam)` swaps the
one module attribute for the length of a block and puts the reference back when the block ends, however it ends. There is no
flag, no setting and no way to leave it swapped: outside the block the application is the reference application.

The swap is checked rather than trusted: the twin must take the same parameters as the reference, the reference must be what
is there when the block starts, and `moved()` compares every module-level name in the reference package inside and outside the
block so that a test can show that exactly one name differs.

`restored(seam)` is the converse for a scenario that has to judge what an exploit left behind: inside its block the reference
function is back in force, and when the block ends whatever was in force before is put back.
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


@contextmanager
def restored(chosen: Seam) -> Iterator[Seam]:
    """Put the reference function back for the length of a block, whatever is in force when it starts, and then put that back.

    A finding's seeded function is in force for the exploit; what the exploit leaves behind (a row in the database, a grant) is
    judged by the application as it really is. This is the only way a scenario sets the reference down in the middle of a run,
    and it is not a way to apply a twin: nothing here installs anything but the reference.
    """
    in_force = getattr(chosen.module, chosen.name)
    setattr(chosen.module, chosen.name, chosen.reference)
    try:
        yield chosen
    finally:
        setattr(chosen.module, chosen.name, in_force)


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

"""Test-only: run one finding's scenario against the reference and against the seeded variant, once each, in a fresh world.

`variants(finding)` returns a module-scoped fixture whose value is (variant, facts, world) for "reference" and for
"vulnerable". The only difference between the two runs is `labs.seam.applied(finding.SEAM)` around the vulnerable one; the
world, the application, the scenario and the assertions are the same code. Nothing under src/ imports this module.
"""

import pytest

from labs.seam import applied
from labs.world import World


def variants(finding):
    @pytest.fixture(scope="module", params=["reference", "vulnerable"])
    def case(request, tmp_path_factory):
        world = World(tmp_path_factory.mktemp(f"{finding.ID.lower()}-{request.param}"))
        if request.param == "vulnerable":
            with applied(finding.SEAM):
                observed = finding.scenario.run(world)
        else:
            observed = finding.scenario.run(world)
        return request.param, observed.facts, world

    return case

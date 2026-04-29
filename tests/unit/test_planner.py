from __future__ import annotations

import pytest

from ai_recon.core.runner import build_plan
from ai_recon.techniques.base import Technique


def _make(name, requires=None, produces=None):
    cls = type(name, (Technique,), {
        "id": name,
        "intrusiveness": "passive",
        "requires": set(requires or ()),
        "produces": set(produces or ()),
        "run": lambda self, target: [],
    })
    return cls


def test_topological_order_respects_dependencies():
    A = _make("A", produces={"x"})
    B = _make("B", requires={"x"}, produces={"y"})
    C = _make("C", requires={"y"})

    plan = build_plan([C, B, A])
    ids = [c.id for c in plan]
    assert ids.index("A") < ids.index("B") < ids.index("C")


def test_independent_techniques_returned():
    A = _make("A", produces={"a"})
    B = _make("B", produces={"b"})
    plan = build_plan([A, B])
    assert {c.id for c in plan} == {"A", "B"}


def test_cycle_degrades_gracefully():
    A = _make("A", requires={"y"}, produces={"x"})
    B = _make("B", requires={"x"}, produces={"y"})
    plan = build_plan([A, B])
    # Cycle: planner does not raise — it appends leftovers in input order.
    assert {c.id for c in plan} == {"A", "B"}

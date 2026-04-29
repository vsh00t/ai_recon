"""Dynamic adapter and technique registry via importlib entry_points."""

from __future__ import annotations

import importlib
import importlib.metadata
from pathlib import Path
from typing import Any, Type

from ai_recon.core.errors import AdapterNotFound


class Registry:
    """Loads adapters and techniques from entry_points and local packages."""

    # Group → {kind: class}
    _adapters: dict[str, dict[str, Any]] = {}
    _techniques: dict[str, Any] = {}
    _loaded: bool = False

    @classmethod
    def load(cls) -> None:
        if cls._loaded:
            return
        cls._loaded = True
        cls._load_entry_points()
        cls._auto_discover_techniques()

    @classmethod
    def _load_entry_points(cls) -> None:
        groups = [
            "ai_recon.adapters.siem",
            "ai_recon.adapters.repo",
            "ai_recon.adapters.secrets",
        ]
        for group in groups:
            cls._adapters.setdefault(group, {})
            try:
                eps = importlib.metadata.entry_points(group=group)
                for ep in eps:
                    cls._adapters[group][ep.name] = ep.load()
            except Exception:
                pass

    @classmethod
    def _auto_discover_techniques(cls) -> None:
        """Walk the techniques package and register all Technique subclasses."""
        from ai_recon.techniques.base import Technique

        base = Path(__file__).parent.parent / "techniques"
        for py in base.rglob("*.py"):
            if py.name.startswith("_"):
                continue
            rel = py.relative_to(base.parent.parent)
            module_name = ".".join(rel.with_suffix("").parts)
            try:
                mod = importlib.import_module(module_name)
                for attr in vars(mod).values():
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, Technique)
                        and attr is not Technique
                        and hasattr(attr, "id")
                    ):
                        cls._techniques[attr.id] = attr
            except Exception:
                pass

    @classmethod
    def get_adapter(cls, group: str, kind: str) -> Any:
        cls.load()
        adapters = cls._adapters.get(group, {})
        if kind not in adapters:
            raise AdapterNotFound(kind, group)
        return adapters[kind]

    @classmethod
    def list_adapters(cls, group: str) -> list[str]:
        cls.load()
        return list(cls._adapters.get(group, {}).keys())

    @classmethod
    def get_technique(cls, technique_id: str) -> Any:
        cls.load()
        if technique_id not in cls._techniques:
            raise AdapterNotFound(technique_id, "technique")
        return cls._techniques[technique_id]

    @classmethod
    def list_techniques(cls) -> list[str]:
        cls.load()
        return sorted(cls._techniques.keys())

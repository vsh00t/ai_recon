"""Lookups against the ai_recon library: techniques, catalogs, profiles, adapters."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ai_recon.core.registry import Registry

_LIB_ROOT = Path(__file__).resolve().parents[4] / "ai_recon" / "ai_recon"
_CATALOGS_DIR = _LIB_ROOT / "catalogs"
_PROFILES_DIR = _LIB_ROOT / "profiles"
_SCHEMAS_DIR = _LIB_ROOT / "schemas"

_ADAPTER_GROUPS = {
    "siem": "ai_recon.adapters.siem",
    "repo": "ai_recon.adapters.repo",
    "secrets": "ai_recon.adapters.secrets",
}


def _ensure_loaded() -> None:
    Registry.load()


def list_technique_ids() -> list[str]:
    _ensure_loaded()
    return Registry.list_techniques()


def get_technique_meta(technique_id: str) -> dict[str, Any]:
    _ensure_loaded()
    cls = Registry.get_technique(technique_id)
    kind = technique_id.split(".", 1)[0] if "." in technique_id else "unknown"
    return {
        "id": technique_id,
        "kind": kind,
        "intrusiveness": getattr(cls, "intrusiveness", "passive"),
        "requires": sorted(getattr(cls, "requires", set()) or []),
        "produces": sorted(getattr(cls, "produces", set()) or []),
        "doc": (cls.__doc__ or "").strip(),
        "module": cls.__module__,
        "class_name": cls.__name__,
    }


def list_techniques() -> list[dict[str, Any]]:
    return [get_technique_meta(t) for t in list_technique_ids()]


def list_catalog_files() -> list[str]:
    if not _CATALOGS_DIR.exists():
        return []
    out: list[str] = []
    for f in sorted(_CATALOGS_DIR.iterdir()):
        if f.is_file() and f.suffix in {".yaml", ".yml"}:
            out.append(f.stem)
    return out


def get_catalog(name: str) -> Any:
    target = _CATALOGS_DIR / f"{name}.yaml"
    if not target.exists():
        target = _CATALOGS_DIR / f"{name}.yml"
    if not target.exists():
        raise FileNotFoundError(name)
    return yaml.safe_load(target.read_text()) or {}


def list_builtin_profiles() -> list[str]:
    if not _PROFILES_DIR.exists():
        return []
    return [f.stem for f in sorted(_PROFILES_DIR.iterdir()) if f.suffix in {".yaml", ".yml"}]


def get_builtin_profile(name: str) -> dict[str, Any]:
    target = _PROFILES_DIR / f"{name}.yaml"
    if not target.exists():
        raise FileNotFoundError(name)
    doc = yaml.safe_load(target.read_text()) or {}
    return doc


def list_adapters() -> dict[str, list[str]]:
    _ensure_loaded()
    return {alias: Registry.list_adapters(group) for alias, group in _ADAPTER_GROUPS.items()}


def adapter_group_alias_to_full(alias: str) -> str:
    if alias not in _ADAPTER_GROUPS:
        raise KeyError(alias)
    return _ADAPTER_GROUPS[alias]


@lru_cache(maxsize=8)
def get_schema(name: str) -> dict[str, Any]:
    target = _SCHEMAS_DIR / f"{name}.schema.json"
    if not target.exists():
        raise FileNotFoundError(name)
    return json.loads(target.read_text())

"""Run orchestrator: builds a DAG of techniques and executes them.

Responsibilities:
  - Load profile YAML and select enabled techniques.
  - Topologically order them by `requires`/`produces`.
  - Enforce intrusiveness ceiling and authorization rules.
  - Run each technique through the pre-flight gate (if evasion enabled).
  - Aggregate findings and model/RAG profiles into a Report.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from ulid import ULID

from ai_recon.core.errors import (
    AIReconError,
    AuthorizationMissing,
    IntrusivenessExceeded,
    ScopeViolation,
    TechniqueAborted,
)
from ai_recon.core.events import EventBus
from ai_recon.core.http import AIReconClient
from ai_recon.core.models import (
    Finding,
    IntrusivenessLevel,
    ModelProfile,
    RAGProfile,
    Report,
    RunContext,
    ScopeDocument,
    Target,
)
from ai_recon.core.ratelimit import TokenBucket
from ai_recon.core.registry import Registry
from ai_recon.core.scope import ScopeGuard

_INTR_ORDER: dict[str, int] = {"passive": 0, "low": 1, "medium": 2, "high": 3}


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

class Profile:
    def __init__(
        self,
        name: str,
        intrusiveness_max: IntrusivenessLevel,
        enable: list[str],
        disable: list[str],
        options: dict[str, Any],
    ) -> None:
        self.name = name
        self.intrusiveness_max = intrusiveness_max
        self.enable = enable
        self.disable = disable
        self.options = options

    @classmethod
    def from_yaml(cls, path: Path) -> "Profile":
        with path.open() as fh:
            data = yaml.safe_load(fh) or {}
        techniques = data.get("techniques", {}) or {}
        return cls(
            name=data.get("name", path.stem),
            intrusiveness_max=data.get("intrusiveness_max", "low"),
            enable=list(techniques.get("enable", []) or []),
            disable=list(techniques.get("disable", []) or []),
            options=data.get("options", {}) or {},
        )

    @classmethod
    def find(cls, profile_name: str) -> "Profile":
        """Resolve a profile by name from packaged profiles or path."""
        p = Path(profile_name)
        if p.exists():
            return cls.from_yaml(p)
        pkg = Path(__file__).parent.parent / "profiles" / f"{profile_name}.yaml"
        if pkg.exists():
            return cls.from_yaml(pkg)
        raise FileNotFoundError(f"Profile not found: {profile_name}")


# ---------------------------------------------------------------------------
# Plan builder (topological order over requires/produces)
# ---------------------------------------------------------------------------

def build_plan(technique_classes: list[type]) -> list[type]:
    """Topologically order techniques so that each runs after producers
    of any capability it `requires`. Falls back to declaration order
    when no dependency is declared.
    """
    by_id: dict[str, type] = {t.id: t for t in technique_classes}
    producers: dict[str, set[str]] = defaultdict(set)
    for t in technique_classes:
        for cap in getattr(t, "produces", set()):
            producers[cap].add(t.id)

    indegree: dict[str, int] = {t.id: 0 for t in technique_classes}
    edges: dict[str, set[str]] = defaultdict(set)
    for t in technique_classes:
        for need in getattr(t, "requires", set()):
            for prod in producers.get(need, set()):
                if prod == t.id:
                    continue
                if t.id not in edges[prod]:
                    edges[prod].add(t.id)
                    indegree[t.id] += 1

    # Stable Kahn's algorithm: iterate in declaration order so equal-rank
    # techniques keep input order.
    order: list[type] = []
    ready = [t.id for t in technique_classes if indegree[t.id] == 0]
    while ready:
        # Preserve input order among equals
        ready.sort(key=lambda x: [t.id for t in technique_classes].index(x))
        nxt = ready.pop(0)
        order.append(by_id[nxt])
        for v in edges[nxt]:
            indegree[v] -= 1
            if indegree[v] == 0:
                ready.append(v)

    if len(order) != len(technique_classes):
        # Cycle: degrade gracefully — append leftovers in declaration order.
        seen = {t.id for t in order}
        for t in technique_classes:
            if t.id not in seen:
                order.append(t)
    return order


# ---------------------------------------------------------------------------
# Target builder
# ---------------------------------------------------------------------------

def targets_from_scope(scope: ScopeDocument) -> list[Target]:
    """Build Target objects from scope.allow entries that have a host."""
    targets: list[Target] = []
    for entry in scope.scope.allow:
        if entry.host is None:
            continue
        ports = entry.ports or [443]
        for port in ports:
            scheme = "https" if port in (443, 8443) else "http"
            t = Target(host=entry.host, port=port, scheme=scheme)
            targets.append(t)
    return targets


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class Runner:
    """Executes a profile against a scope and emits a Report."""

    def __init__(
        self,
        scope: ScopeDocument,
        profile: Profile,
        cache_dir: Path,
        seed: int = 42,
        allow_intrusive: IntrusivenessLevel | None = None,
        dry_run: bool = False,
        max_concurrency: int = 4,
        logger: logging.Logger | None = None,
    ) -> None:
        self.scope = scope
        self.profile = profile
        self.cache_dir = cache_dir
        self.seed = seed
        self.allow_intrusive = allow_intrusive
        self.dry_run = dry_run
        self.max_concurrency = max_concurrency
        self.log = logger or logging.getLogger("ai_recon.runner")

    # ------------------------------------------------------------------
    # Plan
    # ------------------------------------------------------------------

    def _resolve_techniques(self) -> list[type]:
        Registry.load()
        all_ids = set(Registry.list_techniques())
        enabled = list(self.profile.enable) if self.profile.enable else sorted(all_ids)
        enabled = [t for t in enabled if t not in self.profile.disable]

        classes: list[type] = []
        missing: list[str] = []
        for tid in enabled:
            try:
                classes.append(Registry.get_technique(tid))
            except Exception:
                missing.append(tid)
        if missing:
            self.log.warning("Profile references unimplemented techniques: %s", missing)
        return classes

    def _intrusiveness_ceiling(self) -> IntrusivenessLevel:
        prof = self.profile.intrusiveness_max
        scope_max = self.scope.intrusiveness_max
        cli = self.allow_intrusive
        # Effective max = min(profile, scope, allow_intrusive_or_max)
        candidates = [prof, scope_max]
        if cli is not None:
            candidates.append(cli)
        return min(candidates, key=lambda x: _INTR_ORDER[x])  # type: ignore[arg-type]

    def _check_authorization(self, technique_classes: list[type]) -> None:
        auth_ref = (self.scope.engagement.authorization_ref or "").strip()
        if auth_ref:
            return
        for t in technique_classes:
            if _INTR_ORDER.get(getattr(t, "intrusiveness", "passive"), 0) >= _INTR_ORDER["medium"]:
                raise AuthorizationMissing(t.id)

    def _filter_by_intrusiveness(self, techniques: list[type]) -> list[type]:
        ceiling = self._intrusiveness_ceiling()
        ceiling_n = _INTR_ORDER[ceiling]
        kept: list[type] = []
        for t in techniques:
            t_n = _INTR_ORDER.get(getattr(t, "intrusiveness", "passive"), 0)
            if t_n <= ceiling_n:
                kept.append(t)
            else:
                self.log.info(
                    "Skipping %s (intrusiveness=%s > ceiling=%s)",
                    t.id, t.intrusiveness, ceiling,
                )
        return kept

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run(self) -> Report:
        run_id = str(ULID())
        started = datetime.utcnow()
        ctx = RunContext(
            run_id=run_id,
            seed=self.seed,
            cache_dir=self.cache_dir,
            started_at=started,
            scope=self.scope,
            intrusiveness_max=self._intrusiveness_ceiling(),
        )
        ctx.event_bus = EventBus()
        ctx.logger = self.log

        # HTTP client wired with scope guard + rate limit
        guard = ScopeGuard(self.scope)
        bucket = TokenBucket(
            rps=self.scope.rate_limit.rps,
            jitter_seconds=self.scope.rate_limit.jitter_seconds,
            seed=self.seed,
        )
        ctx.http_client = AIReconClient(
            guard=guard,
            bucket=bucket,
            stealth=self.scope.stealth,
            seed=self.seed,
        )

        # Resolve & order techniques
        classes = self._resolve_techniques()
        # Filter by intrusiveness ceiling FIRST, then check authorization only
        # against techniques that will actually run. Otherwise a passive run on
        # a profile that lists medium/high techniques would fail the auth gate
        # even when those techniques are skipped.
        classes = self._filter_by_intrusiveness(classes)
        self._check_authorization(classes)
        ordered = build_plan(classes)

        targets = targets_from_scope(self.scope)
        findings: list[Finding] = []
        model_profiles: dict[str, ModelProfile] = {}
        rag_profiles: dict[str, RAGProfile] = {}

        if self.dry_run:
            self.log.info(
                "[dry-run] Plan: %s targets × %s techniques",
                len(targets), len(ordered),
            )
            for t in ordered:
                self.log.info("  - %s (intr=%s)", t.id, t.intrusiveness)
            return Report(
                run_id=run_id,
                scope=self.scope,
                profile=self.profile.name,
                started_at=started,
                finished_at=datetime.utcnow(),
                findings=[],
            )

        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(tech_cls: type, target: Target) -> list[Finding]:
            async with sem:
                tech = tech_cls(ctx)
                tech_opts = self.profile.options.get(tech_cls.id.split(".", 1)[-1], {})
                if tech_opts:
                    setattr(tech, "options", tech_opts)
                try:
                    if not await tech.applicable(target):
                        return []
                    await ctx.event_bus.emit(
                        "technique.started",
                        technique=tech_cls.id, target=target.id,
                    )
                    out = await tech.run(target)
                    await ctx.event_bus.emit(
                        "technique.finished",
                        technique=tech_cls.id, target=target.id,
                        findings=len(out),
                    )
                    # Capture aggregator side effects
                    mp = getattr(ctx, "model_profile", None)
                    if isinstance(mp, ModelProfile):
                        model_profiles[target.id] = mp
                    rp = getattr(ctx, "rag_profile", None)
                    if isinstance(rp, RAGProfile):
                        rag_profiles[target.id] = rp
                    return out
                except (ScopeViolation, IntrusivenessExceeded, AuthorizationMissing):
                    raise
                except TechniqueAborted as exc:
                    self.log.warning("Aborted %s on %s: %s", tech_cls.id, target.id, exc)
                    return []
                except AIReconError as exc:
                    self.log.warning("Error in %s on %s: %s", tech_cls.id, target.id, exc)
                    return []
                except Exception as exc:  # pragma: no cover - defensive
                    self.log.exception("Unhandled error in %s: %s", tech_cls.id, exc)
                    return []

        # Sequential per technique to respect requires/produces; concurrent across targets.
        for tech_cls in ordered:
            results = await asyncio.gather(
                *(run_one(tech_cls, t) for t in targets), return_exceptions=False
            )
            for r in results:
                findings.extend(r)

        await ctx.http_client.aclose()

        return Report(
            run_id=run_id,
            scope=self.scope,
            profile=self.profile.name,
            started_at=started,
            finished_at=datetime.utcnow(),
            findings=findings,
            model_profiles=model_profiles,
            rag_profiles=rag_profiles,
        )

"""Central data models (Pydantic v2) shared across the entire framework."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

class ScopeAllowEntry(BaseModel):
    cidr: str | None = None
    host: str | None = None
    ports: list[int] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_one(self) -> "ScopeAllowEntry":
        if self.cidr is None and self.host is None:
            raise ValueError("Each scope entry must have either 'cidr' or 'host'.")
        return self


class ScopeSpec(BaseModel):
    allow: list[ScopeAllowEntry]
    deny: list[ScopeAllowEntry] = Field(default_factory=list)


class DiscoverySpec(BaseModel):
    enabled: bool = True
    methods: list[str] = Field(default_factory=lambda: ["tcp_scan", "robots_txt", "sitemap"])
    tcp_ports: list[int] = Field(default_factory=lambda: [80, 443, 8000, 8080, 5601, 9200, 11434])


class EngagementSpec(BaseModel):
    name: str
    authorization_ref: str = ""
    contact: str = ""


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

AuthKind = Literal[
    "none", "bearer", "apikey_header", "apikey_query",
    "oauth2_cc", "mtls", "cookie", "basic",
]


class AuthSpec(BaseModel):
    kind: AuthKind = "none"
    secret_ref: str | None = None
    header_name: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class AuthOverride(BaseModel):
    host: str
    kind: AuthKind
    secret_ref: str | None = None
    header_name: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class AuthConfig(BaseModel):
    default: AuthSpec = Field(default_factory=AuthSpec)
    overrides: list[AuthOverride] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Adapter config
# ---------------------------------------------------------------------------

class AdapterConfig(BaseModel):
    kind: str
    base_url: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class AdaptersConfig(BaseModel):
    siem: AdapterConfig = Field(default_factory=lambda: AdapterConfig(kind="noop"))
    repo: AdapterConfig = Field(default_factory=lambda: AdapterConfig(kind="local"))
    secrets: AdapterConfig = Field(default_factory=lambda: AdapterConfig(kind="env"))


# ---------------------------------------------------------------------------
# Rate-limit
# ---------------------------------------------------------------------------

class RateLimitConfig(BaseModel):
    rps: float = 2.0
    jitter_seconds: tuple[float, float] = (1.0, 5.0)


# ---------------------------------------------------------------------------
# Scope document (top-level scope.yaml)
# ---------------------------------------------------------------------------

IntrusivenessLevel = Literal["passive", "low", "medium", "high"]


class ScopeDocument(BaseModel):
    schema_version: int = 1
    engagement: EngagementSpec
    scope: ScopeSpec
    discovery: DiscoverySpec = Field(default_factory=DiscoverySpec)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    intrusiveness_max: IntrusivenessLevel = "low"
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    stealth: bool = False


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------

TargetClassification = Literal["chat", "rag", "gateway", "repo", "siem", "agent", "mcp", "unknown"]


class Target(BaseModel):
    id: str = ""
    host: str
    port: int
    scheme: Literal["http", "https", "ws", "wss", "grpc"] = "http"
    classification: set[TargetClassification] = Field(default_factory=lambda: {"unknown"})
    auth: AuthSpec = Field(default_factory=AuthSpec)
    notes: str = ""

    @model_validator(mode="after")
    def _set_id(self) -> "Target":
        if not self.id:
            raw = f"{self.host}:{self.port}"
            self.id = hashlib.sha1(raw.encode()).hexdigest()[:12]
        return self

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


# ---------------------------------------------------------------------------
# LLM wire types
# ---------------------------------------------------------------------------

class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str | list[dict[str, Any]]
    name: str | None = None
    tool_call_id: str | None = None


class Usage(BaseModel):
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class ChatResponse(BaseModel):
    text: str
    model: str | None = None
    finish_reason: str | None = None
    usage: Usage | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Delta(BaseModel):
    text: str = ""
    finish_reason: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Findings & profiles
# ---------------------------------------------------------------------------

class DocumentRef(BaseModel):
    title: str
    chunk_id: str | None = None
    snippet: str | None = None
    vector_score: float | None = None
    bm25_score: float | None = None
    combined_score: float | None = None


class Finding(BaseModel):
    id: str
    technique: str
    target_id: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    title: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    intrusiveness: IntrusivenessLevel = "passive"


class ModelProfile(BaseModel):
    vendor: str | None = None
    family: str | None = None
    size_hint: str | None = None
    knowledge_cutoff: str | None = None
    context_window: int | None = None
    tokenizer: str | None = None
    verbosity_score: float | None = None
    code_style_signature: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.0


class RAGProfile(BaseModel):
    detected: bool = False
    chunking: dict[str, Any] | None = None
    retrieval: dict[str, Any] | None = None
    vector_store: str | None = None
    embedding_model: str | None = None
    exposure_level: Literal["none", "minimal", "moderate", "detailed"] = "none"
    documents: list[DocumentRef] = Field(default_factory=list)
    inferred_threshold: float | None = None


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class Report(BaseModel):
    run_id: str
    scope: ScopeDocument
    profile: str
    started_at: datetime
    finished_at: datetime = Field(default_factory=datetime.utcnow)
    findings: list[Finding] = Field(default_factory=list)
    model_profiles: dict[str, ModelProfile] = Field(default_factory=dict)
    rag_profiles: dict[str, RAGProfile] = Field(default_factory=dict)
    diff_vs: str | None = None


# ---------------------------------------------------------------------------
# RunContext (non-serialised runtime state)
# ---------------------------------------------------------------------------

class RunContext:
    """Runtime context injected into every technique and adapter."""

    def __init__(
        self,
        run_id: str,
        seed: int,
        cache_dir: Path,
        started_at: datetime,
        scope: ScopeDocument,
        intrusiveness_max: IntrusivenessLevel,
    ) -> None:
        self.run_id = run_id
        self.seed = seed
        self.cache_dir = cache_dir
        self.started_at = started_at
        self.scope = scope
        self.intrusiveness_max = intrusiveness_max
        # Injected later by the orchestrator:
        self.http_client: Any = None
        self.event_bus: Any = None
        self.logger: Any = None
        self._rng_state: int = seed

    def rng_int(self, lo: int = 0, hi: int = 100) -> int:
        import random
        rng = random.Random(self._rng_state)
        val = rng.randint(lo, hi)
        self._rng_state = rng.randint(0, 2**32)
        return val

    def rng_float(self, lo: float = 0.0, hi: float = 1.0) -> float:
        import random
        rng = random.Random(self._rng_state)
        val = rng.uniform(lo, hi)
        self._rng_state = rng.randint(0, 2**32)
        return val

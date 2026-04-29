# ai-recon

**Universal AI Reconnaissance & Red-Teaming Framework.**

`ai-recon` is an adapter-driven, catalog-driven, plugin-driven CLI and library
that automates reconnaissance, fingerprinting, and security assessment of AI
systems — LLM endpoints, RAG pipelines, MCP servers, and A2A agents — across
SaaS, internal, and lab environments.

> **Status:** Alpha (0.1) — see [`Recon_ToDo.md`](../Recon_ToDo.md) for the
> full design plan and roadmap.

## Principles

- **Scope-first** — nothing executes outside `scope.yaml`. The `ScopeGuard`
  is implemented as an `httpx.AsyncBaseTransport` so isolation is enforced by
  construction, not monkey-patching.
- **Read-only by default** — every technique declares an
  `INTRUSIVENESS = passive | low | medium | high`; ≥ medium requires
  `--allow-intrusive`.
- **Deterministic** — each run has a `run_id`, a fixed RNG seed, and a
  SQLite-backed HTTP cache to support `--replay`.
- **Detection-aware** — the evasion stack queries the SIEM adapter for live
  detection rules, compiles them to regex, and pre-flights every prompt.
- **Plugin-first** — the core knows nothing about vendors, frameworks, or
  rules. Adapters and techniques are discovered via Python entry points.

## Quick start

```bash
pipx install ai-recon  # once published
# or, locally:
pip install -e .

# Validate an engagement scope:
ai-recon scope validate scope.yaml

# Run a profile:
ai-recon run --scope scope.yaml --profile single_endpoint

# Inspect available techniques and adapters:
ai-recon technique list
ai-recon adapter list

# Browse a previous run:
ai-recon report show <run_id>
```

## Repository layout

```
ai_recon/
├── core/        # scope guard, runner, http client, models, registry, report
├── adapters/    # llm_protocol, repo, secrets, siem, transport
├── catalogs/    # vendors, frameworks, prompts, jailbreaks, etc. (YAML data)
├── techniques/  # passive / active / safety / infra / evasion
├── profiles/    # named presets that select techniques
├── schemas/     # JSON Schema for scope/profile/report
└── plugins/     # 3rd-party drop-in plugins
```

## Safety

- `engagement.authorization_ref` is mandatory for any technique
  ≥ medium intrusiveness. Without it, the run aborts.
- Honeypot/canary credentials are detected and **blocked** — never used.
- Logs redact `Authorization`, `api-key`, and any value matched by
  `catalogs/pii_patterns.yaml` automatically.

## License

MIT.

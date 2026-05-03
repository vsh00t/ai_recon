# ToDoGUI.md — Plan detallado: Interface Web Premium para `ai-recon`

> Documento de diseño + plan de implementación de una GUI web moderna,
> profesional y de calidad premium que expone **toda** la funcionalidad
> del CLI y librería `ai-recon` (ver `Recon_ToDo.md`). Pensado para ser
> seguido por un desarrollador full-stack sin contexto previo del proyecto.

---

## 0. Resumen ejecutivo

Construir una aplicación web con dos componentes:

1. **`ai-recon-api`** — servidor FastAPI (Python async) que envuelve la
   librería `ai_recon` existente y expone REST + WebSocket.
2. **`ai-recon-web`** — frontend Next.js 15 (App Router) + TypeScript +
   Tailwind + shadcn/ui + TanStack Query, con un sistema de diseño
   propio inspirado en Linear / Vercel / Raycast (denso, oscuro por
   defecto, microinteracciones, tipografía técnica).

La GUI debe permitir **ejecutar, monitorear en tiempo real y analizar**
todas las técnicas, perfiles, scopes, adapters, catálogos y reportes que
hoy se controlan por CLI, sin renunciar a poder. Es decir: no es un
"wizard simplificado", es una **superficie completa** del framework.

---

## 1. Objetivos y no-objetivos

### 1.1 Objetivos

- Paridad funcional 1:1 con el CLI (`run`, `recon`, `scope`,
  `technique`, `catalog`, `adapter`, `report`).
- Ejecuciones en vivo con streaming de eventos, logs, hallazgos y
  progreso por técnica.
- Editor visual de **scope** (hosts, puertos, clasificaciones, ASN, CIDR)
  con validación contra `scope.schema.json`.
- Editor visual de **profiles** con autocompletado de IDs de técnica
  desde la registry, validado contra `profile.schema.json`.
- Visor de reportes premium con filtros, agrupaciones, gráficos,
  diff entre reportes, exportación a PDF/HTML/JSON/SARIF.
- Panel de adapters: configurar SIEM, repos, secrets y health-check.
- Catálogo navegable: vendors, frameworks, vector DBs, inference servers,
  honeypot signals, prompt templates, PII patterns, severity.
- Multi-usuario opcional con autorización por scope (RBAC ligero).
- Modo oscuro/claro con tema premium consistente.
- Accesible (WCAG 2.1 AA), responsive, atajos de teclado por toda la app.

### 1.2 No-objetivos (v1)

- No reemplaza al CLI: el CLI sigue siendo soporte de primera clase.
- No corre técnicas dentro del navegador (todo server-side).
- No es un orquestador distribuido (no multi-worker en v1, ver §17).
- No reimplementa la lógica de scoring / motor — es **solo** una capa de
  presentación + control sobre `ai_recon.*`.

---

## 2. Principios de UX

1. **Density over chrome.** Linear-style: información densa, mucha
   keyboard control, panels colapsables, breadcrumbs en cada vista.
2. **Determinismo visible.** Cada acción que toca tráfico real (técnica
   activa) muestra el scope que enforce, RPS efectivo, intrusiveness y
   autorización antes de ejecutar.
3. **Reversibilidad.** Borrar reportes, cancelar runs, deshacer cambios
   en profiles via historial local.
4. **Streaming first.** Todo lo largo (run, recon, técnicas) muestra
   progreso en vivo; nada de "spinners ciegos".
5. **Copia técnica honesta.** Tono directo, sin hype: "Run failed:
   ScopeViolation on host x" mejor que "Oops! Something went wrong."
6. **Premium = restricción.** Pocos colores, una sola tipografía,
   espaciados consistentes, motion sutil (<200 ms), shadows discretas.

---

## 3. Arquitectura general

```
┌────────────────────────────────────────────────────────────────┐
│  Browser (Next.js SSR + RSC + client islands)                  │
│  - TanStack Query cache                                         │
│  - WebSocket client (run events)                                │
│  - Zustand stores (UI state)                                    │
└──────────────┬───────────────────────────┬─────────────────────┘
               │ REST (JSON)               │ WS (events)
               ▼                           ▼
┌────────────────────────────────────────────────────────────────┐
│  ai-recon-api (FastAPI, uvicorn, Python 3.11+)                 │
│  - REST routers: scope/profile/run/report/catalog/adapter      │
│  - WS: /ws/runs/{run_id}                                        │
│  - Auth: JWT (httponly cookie) + CSRF                           │
│  - Background runner: asyncio task per run + queue              │
└──────────────┬───────────────────────────┬─────────────────────┘
               │                           │
               ▼                           ▼
┌──────────────────────────────┐  ┌─────────────────────────────┐
│  ai_recon (existing lib)     │  │  Persistence                │
│  - Registry (techniques)     │  │  - SQLite (runs, reports,   │
│  - HTTP client / scope guard │  │    users, audit)            │
│  - Adapters / Profiles       │  │  - FS for reports JSON +    │
│                              │  │    SARIF + cache            │
└──────────────────────────────┘  └─────────────────────────────┘
```

### 3.1 Decisiones clave

- **Mismo proceso, no microservicios.** API en Python re-usa la lib
  directamente — sin gRPC, sin colas externas en v1.
- **WebSocket dedicado por run.** `/ws/runs/{run_id}` emite eventos
  (`technique.started`, `finding.emitted`, `progress`, `error`,
  `completed`). Reconexión automática con `lastEventId` para resume.
- **Cancelación cooperativa.** Cada run lleva un `asyncio.Event` que
  las técnicas chequean entre fases.
- **Sin SSR para vistas dinámicas calientes** (run en vivo, reports):
  se renderizan en cliente con prefetch RSC del shell.
- **App Router con route groups** para separar `(authed)` y `(public)`.

---

## 4. Stack tecnológico

### 4.1 Backend (`ai-recon-api`)

| Capa | Tecnología | Razón |
|------|------------|-------|
| Runtime | Python 3.11+ | Mismo que la lib |
| Framework | FastAPI 0.115+ | Async-native, OpenAPI gratis |
| ASGI | Uvicorn (uvloop) | Estándar |
| WebSocket | FastAPI nativo | Sin dep extra |
| Auth | `python-jose` + `passlib[bcrypt]` | JWT + hashing |
| DB | SQLite + SQLAlchemy 2.0 (async) | Embebido, suficiente v1 |
| Migrations | Alembic | Versionado de esquema |
| Schedulers | `apscheduler` opcional | Runs programados (v2) |
| Validation | Pydantic v2 | Ya usado por la lib |
| Observabilidad | structlog + OpenTelemetry | Trazas y logs estructurados |
| Tests | pytest + httpx.AsyncClient | Coherente con lib |

### 4.2 Frontend (`ai-recon-web`)

| Capa | Tecnología | Razón |
|------|------------|-------|
| Framework | Next.js 15 (App Router) | RSC + streaming + DX |
| Lenguaje | TypeScript 5.6 strict | Tipado fuerte |
| UI kit | shadcn/ui (Radix + Tailwind) | Premium accesible |
| Estilos | Tailwind CSS 4 | Tokens custom |
| Iconos | lucide-react | Pack consistente |
| Forms | react-hook-form + zod | Validación cliente |
| Data | TanStack Query v5 + TanStack Table | Cache + tablas densas |
| State | Zustand | UI state ligero |
| Charts | Recharts (líneas/área) + Visx (treemap, force) | Premium analítico |
| Code editor | Monaco (lazy) | YAML/JSON edit |
| Graph | React Flow | Topology / RAG / agent tools |
| Markdown | react-markdown + remark-gfm | Findings con MD |
| WebSocket | nativo + `partysocket` (reconnect) | Resiliente |
| A11y | Radix + axe en CI | WCAG AA |
| Animation | Framer Motion (sutil) | Micro-interacciones |
| Tests | Vitest + Playwright | Unit + E2E |

### 4.3 Tooling compartido

- pnpm workspace con `apps/web` y `apps/api` (api solo carpeta Python).
- `Taskfile.yml` o `Justfile` con targets: `dev`, `lint`, `test`, `build`.
- Pre-commit: ruff + mypy + eslint + prettier + typecheck.
- Docker compose para `dev` (api + web + opcional Postgres futuro).

---

## 5. Diseño de la API (REST)

Base path: `/api/v1`. Todo JSON. Errores en formato RFC 7807
(`application/problem+json`).

### 5.1 Auth

| Verbo | Path | Descripción |
|-------|------|-------------|
| POST  | `/auth/login` | Email + password → JWT en cookie httpOnly |
| POST  | `/auth/logout` | Limpia cookie |
| GET   | `/auth/me` | Usuario actual |
| POST  | `/auth/api-keys` | Genera API key (para CLI/CI) |
| DELETE| `/auth/api-keys/{id}` | Revoca |

### 5.2 Scope

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/scopes` | Lista scopes guardados |
| POST  | `/scopes` | Crea (valida vs `scope.schema.json`) |
| GET   | `/scopes/{id}` | Detalle |
| PUT   | `/scopes/{id}` | Update |
| DELETE| `/scopes/{id}` | Elimina (si no está en run activo) |
| POST  | `/scopes/{id}/validate` | Re-valida sin guardar |
| POST  | `/scopes/import` | Importa YAML/JSON |
| GET   | `/scopes/{id}/export?format=yaml\|json` | Exporta |

### 5.3 Profiles

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/profiles` | Built-in + custom |
| POST  | `/profiles` | Custom |
| GET   | `/profiles/{name}` | Resuelto: técnicas finales tras enable/disable |
| PUT   | `/profiles/{name}` | Update (solo custom) |
| DELETE| `/profiles/{name}` | Delete (solo custom) |
| POST  | `/profiles/{name}/preview` | Devuelve técnicas que se ejecutarían contra un scope dado, con intrusiveness gate aplicado |

### 5.4 Runs

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/runs?status=&from=&to=&profile=` | Lista paginada |
| POST  | `/runs` | Lanza run: `{scope_id, profile, overrides, intrusiveness, dry_run}` |
| GET   | `/runs/{id}` | Estado actual (sin streaming) |
| POST  | `/runs/{id}/cancel` | Cancelación cooperativa |
| GET   | `/runs/{id}/events?cursor=` | Polling fallback (si WS no disponible) |
| GET   | `/runs/{id}/findings?severity=&technique=` | Findings con filtros |
| GET   | `/runs/{id}/artifacts` | Lista de artefactos (logs, raw HTTP, etc.) |
| GET   | `/runs/{id}/artifacts/{name}` | Descarga |

### 5.5 Recon (single target)

| Verbo | Path | Descripción |
|-------|------|-------------|
| POST  | `/recon` | `{url, profile?, intrusiveness?}` — atajo equivalente a `ai-recon recon <url>` |

### 5.6 Reports

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/reports?run_id=` | Lista |
| GET   | `/reports/{id}` | Cabecera + summary |
| GET   | `/reports/{id}/findings` | Paginado, filtros |
| GET   | `/reports/{id}/render?format=html\|md\|json\|sarif\|pdf` | Renderiza |
| POST  | `/reports/diff` | `{a_id, b_id}` → diff de findings |
| DELETE| `/reports/{id}` | Borra (con confirmación) |

### 5.7 Catalogs

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/catalogs` | Lista todos los catálogos disponibles |
| GET   | `/catalogs/{name}` | Contenido (vendors, frameworks, etc.) |
| GET   | `/catalogs/{name}/search?q=` | Búsqueda fulltext |

### 5.8 Techniques

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/techniques` | Listado completo (id, kind, intrusiveness, requires_auth) |
| GET   | `/techniques/{id}` | Metadatos + schema de config |
| POST  | `/techniques/{id}/dry-run` | Validación sin ejecutar |

### 5.9 Adapters

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/adapters` | Lista por grupo (siem, repo, secrets) |
| GET   | `/adapters/{group}/{kind}` | Schema de config |
| POST  | `/adapters/{group}/{kind}/test` | Health check con creds |
| GET   | `/adapter-instances` | Instancias guardadas |
| POST  | `/adapter-instances` | Crea (creds vía secrets adapter) |

### 5.10 Secrets

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/secrets/refs` | Lista referencias (sin valores) |
| POST  | `/secrets/refs` | Registra ref (env / vault / file) |
| DELETE| `/secrets/refs/{name}` | Elimina |

### 5.11 System

| Verbo | Path | Descripción |
|-------|------|-------------|
| GET   | `/health` | Liveness |
| GET   | `/version` | Versiones lib + api |
| GET   | `/metrics` | Prometheus |
| GET   | `/audit?from=&to=&actor=` | Audit log |

### 5.12 WebSocket

`GET /ws/runs/{run_id}` (auth via cookie o `?token=`). Mensajes JSON:

```jsonc
// server → client
{ "type": "run.started", "run_id": "...", "ts": 1700000000 }
{ "type": "technique.started", "id": "passive.header_fingerprint" }
{ "type": "technique.progress", "id": "...", "pct": 0.42, "msg": "scanning host 3/12" }
{ "type": "finding.emitted", "finding": { ...Finding } }
{ "type": "log", "level": "info", "msg": "..." }
{ "type": "technique.completed", "id": "...", "duration_ms": 1234, "findings": 5 }
{ "type": "run.completed", "report_id": "..." }
{ "type": "error", "where": "technique.X", "message": "..." }

// client → server (opcional)
{ "type": "ping" }
{ "type": "pause" }    // futuro
{ "type": "cancel" }
```

Reconexión: el cliente envía `?since=<event_seq>` y la API rehidrata
desde un buffer (last 1000 eventos) o desde la BD.

---

## 6. Modelo de datos persistente

SQLite v1, esquema preparado para migrar a Postgres en v2.

```sql
-- usuarios
CREATE TABLE user (
  id TEXT PRIMARY KEY,        -- ULID
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,         -- admin | operator | viewer
  created_at TIMESTAMP NOT NULL,
  last_login_at TIMESTAMP
);

CREATE TABLE api_key (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES user(id),
  prefix TEXT NOT NULL,       -- 8 chars visibles
  hash TEXT NOT NULL,
  name TEXT,
  created_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP
);

-- contenidos
CREATE TABLE scope (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  doc_json TEXT NOT NULL,     -- ScopeDoc serializado
  created_by TEXT REFERENCES user(id),
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

CREATE TABLE profile_custom (
  name TEXT PRIMARY KEY,
  doc_yaml TEXT NOT NULL,
  description TEXT,
  created_by TEXT REFERENCES user(id),
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

-- ejecuciones
CREATE TABLE run (
  id TEXT PRIMARY KEY,
  scope_id TEXT REFERENCES scope(id),
  profile_name TEXT NOT NULL,
  status TEXT NOT NULL,       -- queued|running|completed|failed|canceled
  intrusiveness TEXT NOT NULL,
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  error_message TEXT,
  triggered_by TEXT REFERENCES user(id),
  options_json TEXT NOT NULL
);

CREATE TABLE run_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  ts TIMESTAMP NOT NULL,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE finding (
  id TEXT PRIMARY KEY,        -- ULID original
  run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  technique_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  doc_json TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_finding_run ON finding(run_id);
CREATE INDEX idx_finding_severity ON finding(severity);
CREATE INDEX idx_finding_technique ON finding(technique_id);

CREATE TABLE report (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
  format TEXT NOT NULL,
  path TEXT NOT NULL,         -- en disco
  size_bytes INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL
);

-- adapters
CREATE TABLE adapter_instance (
  id TEXT PRIMARY KEY,
  group_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  config_json TEXT NOT NULL,
  secret_refs_json TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  last_test_at TIMESTAMP,
  last_test_ok INTEGER
);

-- audit
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TIMESTAMP NOT NULL,
  actor_id TEXT REFERENCES user(id),
  action TEXT NOT NULL,       -- run.start, scope.update, etc.
  target TEXT,
  meta_json TEXT
);
```

---

## 7. Información Architecture (frontend)

```
/                        Dashboard (KPIs + últimos runs + alertas)
/runs                    Lista de runs (tabla, filtros)
  /runs/new              Wizard: scope → profile → review → launch
  /runs/[id]             Vista en vivo / histórica
    /runs/[id]/findings    Findings tab
    /runs/[id]/timeline    Timeline de eventos
    /runs/[id]/logs        Log stream
    /runs/[id]/artifacts   Descargas
/reports                 Lista de reportes
  /reports/[id]          Visor (resumen + findings + gráficos)
  /reports/diff?a=&b=    Diff
/scopes                  Lista
  /scopes/new            Editor visual
  /scopes/[id]           Editor / detalle
/profiles                Lista (built-in + custom)
  /profiles/new          Editor
  /profiles/[name]       Editor (built-in es read-only, "duplicate to edit")
/catalogs                Hub de catálogos
  /catalogs/[name]       Browser
/techniques              Listado completo
  /techniques/[id]       Detalle técnico (qué hace, intrusiveness, schema config, ejemplos)
/adapters                Hub
  /adapters/instances    Instancias configuradas
  /adapters/[group]/[kind]  Form / test
/settings                Cuenta, API keys, tema, atajos, secrets refs, integrations
/audit                   Audit log (admin)
```

Layout principal:

- **Sidebar izquierdo** colapsable (240 → 64 px) con secciones agrupadas
  (Operate / Library / System).
- **Topbar** con breadcrumbs, command palette (`⌘K`), quick run (`⌘⇧R`),
  notifications, theme toggle, avatar.
- **Detail panes** lateralizables (slide-over) para inspeccionar un
  finding, una técnica o un evento sin perder contexto.

---

## 8. Vistas en detalle

### 8.1 Dashboard (`/`)

- **Hero strip**: 4 KPI cards densas (Runs últimos 7d, Findings críticos
  abiertos, Mean run duration, Coverage de técnicas). Sparkline en cada
  una (Visx).
- **Recent runs** tabla compacta (status, profile, scope, started, dur,
  findings por severidad como mini-stack bars).
- **Severity breakdown** treemap (Visx) por técnica → severidad.
- **Watchlist**: hosts/objetivos marcados con últimos hallazgos.
- Estado vacío premium con ilustración SVG sutil + CTAs claros.

### 8.2 Run wizard (`/runs/new`)

Steps con `<Stepper>`:

1. **Scope** — elegir existente o "New scope" inline (drawer con editor).
2. **Profile** — preset cards con descripción, intrusiveness pill,
   conteo de técnicas; "Customize" abre tab con enable/disable + diff.
3. **Authorization** — checkbox "I have authorization for these targets"
   (obligatorio para intrusiveness > passive), referencia escrita a
   ticket/contract opcional.
4. **Review** — resumen completo: técnicas finales, RPS efectivo,
   adapters requeridos, estimación de duración, costos (si infra.cost_oracle
   habilitado).
5. **Launch** — botón primario deshabilitado hasta que (4) esté verde;
   secondary "Save as scheduled" (v2).

Validaciones cliente con zod replicadas server-side.

### 8.3 Vista de run en vivo (`/runs/[id]`)

Layout 3 columnas (desktop ≥1280):

```
┌─────────────────┬──────────────────────────┬──────────────────┐
│ Technique list  │ Stream (timeline + log)  │ Inspector (lat.) │
│ (sidebar 280)   │ (centro flexible)        │ (380, opcional)  │
└─────────────────┴──────────────────────────┴──────────────────┘
```

- **Technique list**: cada técnica como row con estado (pending/running/
  done/failed), spinner si activa, mini progress bar, contador de
  findings, duración. Click → filtra el stream.
- **Stream center**: tabs `Timeline | Findings | Logs | Artifacts`.
  - Timeline: lista virtual (TanStack Virtual) de eventos con icon por
    tipo, "follow tail" toggle.
  - Findings: TanStack Table con filtros (severidad, técnica, hash de
    target), búsqueda, agrupación, multi-select con bulk actions
    (mark false-positive, add note, copy as JSON).
  - Logs: terminal-like (xterm.js opcional) con búsqueda.
  - Artifacts: tabla con preview (HTTP raw, screenshots si hubiera).
- **Inspector** (slide-over): cuando se selecciona un finding muestra
  detalles, evidencias, request/response (con resaltado), CWE/MITRE
  mappings, sugerencias de remediación.

Acciones: **Pause** (v2), **Cancel** (con confirm), **Export** (drop-down
formatos), **Re-run with same config**, **Compare with previous run**.

Estado conectividad: badge `live` verde con dot pulsing, cae a `degraded`
si WS reconecta y a `offline (polling)` si fallback.

### 8.4 Reports (`/reports/[id]`)

- **Hero** con título, scope, profile, fecha, duración, severity
  distribution (donut + counts).
- **Tabs**: `Overview | Findings | Coverage | Raw`.
- **Coverage**: matriz técnicas × hosts (heatmap) con `hit/miss/error`.
- **Findings tab**: igual que en run pero con filtros persistentes en
  URL (`?severity=high&technique=active.tokenizer_probe`).
- **Export menu**: HTML, JSON, SARIF, PDF, Markdown.
- **Share**: link público read-only firmado (TTL configurable, ver §16).

### 8.5 Diff de reportes (`/reports/diff`)

- Selector de reportes A y B.
- Tres listas: `Only in A`, `Common`, `Only in B`.
- Heatmap de severidad por técnica para ambos lado-a-lado.
- Útil para ver regresiones tras un fix.

### 8.6 Scope editor (`/scopes/new`)

Layout 2 columnas: form a la izquierda, **YAML preview live** a la derecha
(Monaco read-only sincronizado). Toggle "Edit YAML directly" intercambia
modos sin perder estado, validando contra `scope.schema.json` en cada
keystroke (debounced 250 ms). Componentes:

- **Targets**: tabla editable con add/delete, columnas `host`,
  `port`, `scheme`, `classification` (multi-pill). Validación regex
  para host, integer 1-65535 para port.
- **CIDR ranges**: lista con checks de RFC1918 y warning si público.
- **ASN**: input con autocomplete (catalog vendors si aplica).
- **Exclusions**: misma estructura.
- **Authorization**: textarea con metadatos (ticket, contract, signed-by).
- **Test scope**: botón que valida + corre dry-run con
  `passive.header_fingerprint` contra el primer target para confirmar
  conectividad.

### 8.7 Profile editor (`/profiles/[name]`)

- Lista de **todas las técnicas** agrupadas por kind (passive/active/
  safety/infra/evasion) con toggle on/off.
- Indicador de intrusiveness por técnica (color-coded).
- Panel "Effective set" muestra IDs finales tras enable/disable.
- Secciones de **config por técnica** que aparecen condicionalmente al
  habilitar (forms generadas desde el JSON Schema de cada técnica).
- Built-in profiles son read-only — botón "Duplicate to edit".

### 8.8 Catalogs (`/catalogs/[name]`)

- Buscador y filtros por columna.
- Vista tabla (TanStack Table) + vista detalle al hacer click.
- Específicos:
  - **Vendors**: tabla con vendor, modelos, endpoints, headers, auth.
  - **Frameworks**: nombre, versión típica, indicadores de fingerprint.
  - **Vector DBs**: nombre, ports, signatures.
  - **Inference servers**: name, default port, health endpoints.
  - **Honeypot signals**: signal, severity score.
  - **Prompt templates**: editor con preview Markdown.
  - **PII patterns**: regex con tester inline.
  - **Severity**: matriz read-only.

### 8.9 Techniques (`/techniques/[id]`)

- Cabecera: id, kind, intrusiveness pill, requires_auth, config schema
  link.
- Descripción larga (Markdown).
- Ejemplos de uso (snippets CLI + curl + ejemplo de finding).
- Inputs/outputs (modelo Pydantic visualizado).
- Botón **Try in sandbox** → abre run wizard con esa técnica
  pre-seleccionada en perfil temporal.

### 8.10 Adapters (`/adapters`)

- Tabs por grupo (SIEM / Repo / Secrets).
- Cada instancia: card con health (verde/amarillo/rojo), `Last tested`
  timestamp, botones `Test`, `Edit`, `Delete`.
- Al crear: form generado del JSON Schema del adapter, secret refs
  con dropdown desde `/secrets/refs`.

### 8.11 Settings (`/settings`)

- Profile (avatar, password change, 2FA — v2)
- API keys (crear, listar, revocar, copiar UNA vez)
- Theme (dark / light / system) + accent color (3 opciones premium:
  `cobalt`, `violet`, `emerald`)
- Keyboard shortcuts (cheat sheet + customizar — v2)
- Secrets refs
- Integrations (webhook URL para `run.completed`, Slack — v2)

---

## 9. Sistema de diseño (premium)

### 9.1 Tokens

- **Colores neutros (dark, default)**:
  - `bg.0` `#0A0A0B` (page) · `bg.1` `#101013` (surface)
  - `bg.2` `#16161B` (elevated) · `bg.3` `#1D1D24` (hover)
  - `border.subtle` `#23232C` · `border.strong` `#2E2E3A`
  - `fg.muted` `#8C8CA1` · `fg.default` `#E4E4EC` · `fg.bold` `#FFFFFF`
- **Light** simétrico con base `#FAFAFB`, `#FFFFFF`.
- **Accent (cobalt default)**: `#3B82F6` con escala 50-900.
- **Severities**:
  - `critical` `#EF4444`, `high` `#F97316`, `medium` `#F59E0B`,
  - `low` `#10B981`, `info` `#6B7280`.
- **Status**:
  - `running` `#3B82F6`, `done` `#10B981`,
  - `failed` `#EF4444`, `canceled` `#6B7280`.

### 9.2 Tipografía

- UI: **Inter** (variable, 400/500/600/700) — fallback `system-ui`.
- Mono: **JetBrains Mono** (400/500/600) para code, hashes, IDs.
- Escala (rem): 0.75 · 0.8125 · 0.875 · 1 · 1.125 · 1.25 · 1.5 · 1.875 · 2.25.
- Tracking: `-0.01em` en headings ≥ 1.25 rem, `0` en body.
- Line-height: 1.45 default, 1.25 en headings.

### 9.3 Espaciado / radio / sombra

- Spacing scale (px): 2, 4, 6, 8, 12, 16, 20, 24, 32, 40, 48, 64.
- Radii: `sm 4` · `md 6` · `lg 8` · `xl 12` · `2xl 16` · `pill 9999`.
- Shadows discretas: `sm 0 1px 2px rgba(0,0,0,.4)`,
  `md 0 4px 12px rgba(0,0,0,.35)`,
  `lg 0 12px 32px rgba(0,0,0,.45)`.

### 9.4 Componentes (inventario shadcn-based)

- **Primitivos**: Button, Input, Textarea, Select, Combobox, Checkbox,
  Switch, RadioGroup, Slider, Tooltip, Popover, Dialog, Drawer, Sheet,
  Tabs, Accordion, Alert, Badge, Pill, Avatar, Spinner, ProgressBar,
  Stepper.
- **Compuestos**:
  - `<DataTable>` (TanStack Table) con sticky header, virtualización,
    column visibility, density toggle, CSV export.
  - `<KbdHint>` para `⌘K`.
  - `<CommandMenu>` (cmdk) global.
  - `<EmptyState>` con ilustración + 1 acción primaria + 1 secundaria.
  - `<StatusBadge>` (running/done/failed/canceled) con dot pulsing.
  - `<SeverityChip>` con color del token.
  - `<Codeblock>` con syntax highlighting (Shiki) + copy button.
  - `<JsonViewer>` colapsable.
  - `<Sparkline>` y `<Donut>` accesibles.
  - `<TimelineItem>` con icono, tiempo relativo + tooltip absoluto.
  - `<DiffView>` para diff de findings/configs.
  - `<TopologyGraph>` (React Flow) reusable para scope, MCP, RAG.

### 9.5 Movimiento

- Duración base 120 ms (microinteracciones), 200 ms (transiciones de
  panel), 320 ms (overlays).
- Easing: `cubic-bezier(0.2, 0, 0, 1)` para entrar, `cubic-bezier(0.4, 0, 1, 1)` para salir.
- Reduce-motion respetado (`prefers-reduced-motion`).

### 9.6 Iconografía

Lucide únicamente. Tamaños 14/16/20. Sin mezclar con otro pack.

### 9.7 Vacío y errores

Cada lista tiene:

- Empty state premium: heading corto, sub-texto, 1 CTA primario.
- Error state con `<Alert variant="destructive">` + retry y, si aplica,
  link al audit log o issue tracker interno.

---

## 10. Real-time UX detalles

- **Connection state machine** en cliente:
  `idle → connecting → connected → degraded → reconnecting → closed`.
- Indicador en topbar y en cada run vivo.
- Buffer cliente: agrupa eventos en frames de 100 ms para no saturar React.
- Auto-scroll inteligente: si el usuario scrollea arriba, se pausa
  follow-tail; chip "↓ N new events" para volver al final.
- Reconnect exponencial 1s→30s con jitter (mismo TokenBucket aproach).
- Persistencia local (IndexedDB) opcional de últimos 50k eventos para
  no perder al refresh.

---

## 11. Seguridad

- Auth: JWT en cookie httpOnly + Secure + SameSite=Lax. CSRF token en
  header `X-CSRF-Token` para mutaciones.
- API keys: prefijo visible (`akr_…`) + hash bcrypt en BD; mostrado **una
  sola vez** al crear.
- RBAC v1: `admin` (todo), `operator` (run + read), `viewer` (read).
- Audit log inmutable de toda mutación.
- Secrets nunca viajan al frontend; sólo se manejan refs.
- Sanitización: salidas del servidor a HTML siempre via React (sin
  `dangerouslySetInnerHTML` salvo en visor de reporte HTML donde se
  inyecta en `<iframe sandbox>`).
- CSP estricta (`default-src 'self'`, sin inline excepto nonces SSR).
- CORS: API y Web mismo origen en prod (reverse proxy).
- Rate limit en endpoints de mutación (1 r/s por usuario default).
- Validación contra **scope** server-side en `/runs` antes de iniciar
  (no confiar en cliente).
- Confirmación con typed-name para borrar reportes/scopes/profiles
  (`type the name to delete`).

---

## 12. Observabilidad

- Logs estructurados con `structlog` (JSON) + correlation id.
- Métricas Prometheus en `/metrics`: runs activos, duración p50/p95,
  findings/min, errores por técnica.
- Tracing OTel opcional (export a stdout o OTLP).
- Frontend: Sentry (opt-in), web-vitals enviados al backend.

---

## 13. Errores y recuperación

- API responde RFC 7807 con `type`, `title`, `status`, `detail`,
  `instance`, `errors[]` cuando aplica.
- En vivo, errores por técnica no abortan el run completo a menos que
  el profile lo marque `fail_fast: true`.
- Cancel: el runner espera `ScopeGuard` y `TokenBucket` flush, marca
  estado `canceled`, persiste eventos hasta el corte.
- Crash recovery: al arrancar la API, runs en estado `running` >5 min
  sin eventos se marcan `failed (orphaned)` con flag para reintentar.

---

## 14. Accesibilidad

- WCAG 2.1 AA: contraste ≥ 4.5:1 en texto, focus visible custom (no
  outline default eliminada), navegación con teclado completa.
- Atajos: `⌘K` palette, `g r` go runs, `g s` go scopes, `g p` profiles,
  `c` create context-aware, `?` help, `j/k` mover lista, `enter` abrir.
- Screen reader: `aria-live="polite"` para events streams; resúmenes
  textuales para gráficos.
- Test con axe-core en CI (Playwright).

---

## 15. i18n

Estructura lista para multi-idioma con `next-intl`. v1: en + es.
Strings en JSON namespaced (`runs.json`, `reports.json`, ...).

---

## 16. Compartir reportes (read-only links)

- POST `/reports/{id}/shares` → genera link firmado HMAC con TTL
  (1 h / 1 d / 7 d), opcionalmente protegido por password.
- Vista pública minimalista en `/r/[token]` con marca de agua y badge
  "Read-only · expires in …".
- Auditado, revocable.

---

## 17. Escalabilidad / futuro

- v2: cola Redis + workers para correr varios runs simultáneos.
- v2: Postgres con `LISTEN/NOTIFY` para eventos.
- v2: scheduler (`apscheduler` o `temporal`) para runs recurrentes.
- v2: webhooks salientes (`run.completed`, `finding.critical`).
- v2: multi-tenant con organizaciones.

---

## 18. Estructura de carpetas

```
ai_recon/                       # repo existente
├── ai_recon/                   # lib (sin cambios)
├── apps/
│   ├── api/                    # nuevo backend
│   │   ├── pyproject.toml
│   │   ├── alembic/
│   │   ├── ai_recon_api/
│   │   │   ├── __init__.py
│   │   │   ├── main.py
│   │   │   ├── settings.py
│   │   │   ├── deps.py
│   │   │   ├── auth/
│   │   │   ├── db/
│   │   │   │   ├── models.py
│   │   │   │   ├── session.py
│   │   │   │   └── migrations/
│   │   │   ├── routers/
│   │   │   │   ├── auth.py
│   │   │   │   ├── scopes.py
│   │   │   │   ├── profiles.py
│   │   │   │   ├── runs.py
│   │   │   │   ├── reports.py
│   │   │   │   ├── catalogs.py
│   │   │   │   ├── techniques.py
│   │   │   │   ├── adapters.py
│   │   │   │   ├── secrets.py
│   │   │   │   └── system.py
│   │   │   ├── ws/
│   │   │   │   └── runs.py
│   │   │   ├── services/
│   │   │   │   ├── runner.py        # bridge a ai_recon
│   │   │   │   ├── reports.py
│   │   │   │   └── catalog.py
│   │   │   └── schemas/             # Pydantic API DTOs
│   │   └── tests/
│   └── web/                    # nuevo frontend
│       ├── package.json
│       ├── next.config.ts
│       ├── tailwind.config.ts
│       ├── postcss.config.js
│       ├── tsconfig.json
│       ├── public/
│       │   ├── icons/
│       │   └── illustrations/
│       └── src/
│           ├── app/
│           │   ├── layout.tsx
│           │   ├── (public)/
│           │   │   ├── login/page.tsx
│           │   │   └── r/[token]/page.tsx
│           │   ├── (authed)/
│           │   │   ├── layout.tsx
│           │   │   ├── page.tsx              # dashboard
│           │   │   ├── runs/
│           │   │   │   ├── page.tsx
│           │   │   │   ├── new/page.tsx
│           │   │   │   └── [id]/{page,findings,timeline,logs,artifacts}.tsx
│           │   │   ├── reports/
│           │   │   ├── scopes/
│           │   │   ├── profiles/
│           │   │   ├── catalogs/
│           │   │   ├── techniques/
│           │   │   ├── adapters/
│           │   │   ├── settings/
│           │   │   └── audit/page.tsx
│           ├── components/
│           │   ├── ui/                  # shadcn primitives
│           │   ├── data-table/
│           │   ├── command-menu/
│           │   ├── code-block/
│           │   ├── topology-graph/
│           │   ├── stream/              # run live components
│           │   └── charts/
│           ├── features/                # feature folders
│           │   ├── runs/
│           │   ├── reports/
│           │   ├── scopes/
│           │   ├── profiles/
│           │   ├── catalogs/
│           │   ├── techniques/
│           │   └── adapters/
│           ├── lib/
│           │   ├── api/                 # generated client (orval/openapi-ts)
│           │   ├── ws/
│           │   ├── auth/
│           │   ├── theme/
│           │   └── utils/
│           ├── hooks/
│           ├── stores/                  # zustand
│           ├── styles/
│           └── tests/
│               ├── unit/
│               └── e2e/                 # playwright
├── docker/
│   ├── api.Dockerfile
│   ├── web.Dockerfile
│   └── nginx.conf
├── docker-compose.yml
└── ToDoGUI.md (este archivo)
```

---

## 19. Plan por fases / milestones

### Fase 0 — Bootstrap (semana 1)

- [ ] Crear `apps/api` con FastAPI mínimo, healthcheck, settings.
- [ ] Crear `apps/web` Next.js + Tailwind + shadcn init + tema base.
- [ ] Auth básico (login, JWT cookie, /me).
- [ ] CI: lint + typecheck + tests stub en GH Actions.
- [ ] OpenAPI generation → `lib/api` cliente tipado en web.

### Fase 1 — Lectura (semana 2-3)

- [ ] Endpoints GET: techniques, catalogs, profiles, adapters.
- [ ] Páginas de browse (tablas + detalle): techniques, catalogs.
- [ ] Layout principal + sidebar + topbar + command palette.
- [ ] Theme dark/light, tokens Tailwind.

### Fase 2 — Scope & profile (semana 4)

- [ ] CRUD de scopes con editor visual + YAML side-by-side.
- [ ] CRUD de profiles custom con duplicate-from-builtin.
- [ ] Validación con JSON Schema en cliente y servidor.

### Fase 3 — Ejecución (semana 5-6)

- [ ] Runner async en API: lanza `ai_recon` y emite eventos.
- [ ] WebSocket `/ws/runs/{id}` con buffer + reconexión.
- [ ] Wizard `/runs/new`.
- [ ] Vista live `/runs/[id]` (timeline + findings + logs).
- [ ] Cancelación.

### Fase 4 — Reportes (semana 7)

- [ ] Persistencia + listing.
- [ ] Visor `/reports/[id]` con tabs y exports.
- [ ] Diff `/reports/diff`.
- [ ] Share links firmados.

### Fase 5 — Adapters & secrets (semana 8)

- [ ] Instancias de adapters + test conectividad.
- [ ] Secrets refs (sin valores en frontend).

### Fase 6 — Polish premium (semana 9)

- [ ] Microinteracciones, empty states, illustraciones.
- [ ] Atajos de teclado + cheat sheet.
- [ ] A11y pass con axe + Playwright.
- [ ] Performance: code splitting, RSC streaming, bundle <250 kB initial.
- [ ] Documentación operativa.

### Fase 7 — Hardening (semana 10)

- [ ] Audit log UI, RBAC enforcement E2E.
- [ ] Backup/restore de SQLite + reportes.
- [ ] Docker images + compose + reverse proxy nginx.
- [ ] Smoke tests en staging.

---

## 20. Testing

- **Backend**: pytest async, fixtures con SQLite tmp; cobertura
  ≥ 80 % en routers; tests de runner que mockean técnicas.
- **Frontend unit**: Vitest + React Testing Library para hooks,
  reducers, componentes puros.
- **E2E**: Playwright contra `docker-compose up` con seed determinista.
  Flujos críticos: login, crear scope, crear profile, lanzar run,
  ver findings en vivo, exportar reporte, diff.
- **Visual regression**: Playwright snapshots en CI (linux only) para
  componentes clave (tabla, timeline, donut).
- **Contract tests**: `schemathesis` valida OpenAPI vs implementación.

---

## 21. CI/CD

- GitHub Actions:
  - `web-ci`: install (pnpm), lint, typecheck, vitest, build.
  - `api-ci`: ruff, mypy, pytest, alembic check.
  - `e2e`: build images, compose up, playwright run.
  - `release`: tag → build images → push GHCR → release notes.
- Versionado SemVer separado para `api` y `web` con changelog auto
  (changesets en web, towncrier en api).

---

## 22. Despliegue

### 22.1 Local dev

```bash
# api
cd apps/api
uv sync
uv run uvicorn ai_recon_api.main:app --reload --port 8000

# web
cd apps/web
pnpm i
pnpm dev          # http://localhost:3000, proxy /api → 8000
```

### 22.2 Docker

- `api.Dockerfile` (python:3.12-slim, multistage con uv).
- `web.Dockerfile` (node:22-alpine, multistage standalone).
- `nginx.conf` para reverse-proxy + WS upgrade + gzip/br.
- `docker-compose.yml` para `dev`/`prod` con volúmenes para SQLite y
  reports.

### 22.3 Producción

- Nginx (o Caddy) en frente. TLS (LE).
- Variables de entorno: `AI_RECON_DB_URL`, `AI_RECON_JWT_SECRET`,
  `AI_RECON_REPORTS_DIR`, `AI_RECON_LOG_LEVEL`, `AI_RECON_ALLOWED_ORIGINS`.
- Backups: cron diario `sqlite3 .backup` + tar de `reports/`.

---

## 23. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| Runs largos consumen memoria con buffer de eventos | Medio | Persistir eventos a SQLite + buffer corto en RAM |
| Frontend con 50k findings ahoga la tabla | Alto | Virtualización + paginación server-side |
| Streaming via WS tras NAT/proxy se cae | Medio | Fallback a long-polling de `/events?cursor=` |
| Secretos accidentalmente en logs UI | Crítico | Redactor server-side por regex (PII catalog) antes de emitir |
| Built-in profiles editados por usuario | Medio | Read-only + duplicate; tests de no-mutación |
| WebSocket sin auth | Crítico | Auth obligatoria, token en query firmado, rotado por run |
| Carga inicial lenta | Medio | RSC, code-splitting por ruta, prefetch de quick paths |
| YAML con anchors maliciosos | Medio | `yaml.safe_load` siempre + tamaño máx 256 KB |

---

## 24. Decisiones abiertas (requieren aprobación del usuario)

1. **Idioma por defecto** de la UI: ES o EN.
2. **Single-user** vs multi-user desde v1.
3. **Telemetría opt-in** (anónima, métricas de uso del CLI/UI) sí o no.
4. **Hospedaje preferido** (autohospedado docker-compose vs paquete con
   binario único embebido tipo Tauri/Electron).
5. **Branding** (logo, nombre comercial si difiere de `ai-recon`,
   palette accent default).

---

## 25. Definition of Done v1

La GUI v1 se considera lista cuando:

- [ ] Todos los comandos CLI tienen equivalente UI funcional.
- [ ] Lighthouse ≥ 95 en Performance, A11y, Best Practices.
- [ ] axe-core 0 violaciones serias en flujos principales.
- [ ] E2E suite verde en CI.
- [ ] Documentación de usuario (`docs/ui.md`) y operación (`docs/ops.md`).
- [ ] Imagen Docker publicada y `docker-compose up` levanta todo.
- [ ] Demo recorded de 3 minutos cubriendo: login → scope → profile →
      run → findings → report → diff.

---

*Fin del documento.* Cualquier desviación contra este plan debe
registrarse como ADR (`docs/adr/NNNN-*.md`) en el repo.

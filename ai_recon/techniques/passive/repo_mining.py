"""Passive repository mining technique — scans source repos for AI/ML signals."""
from __future__ import annotations

import ast
import re
import shutil
import tempfile
from pathlib import Path
from typing import ClassVar, Any

import yaml

from ai_recon.core.models import Finding, RunContext, Target
from ai_recon.techniques.base import Technique

# Keywords used to filter repos worth cloning
_SEARCH_KEYWORDS: list[str] = [
    "langchain", "rag", "embedding", "crewai", "llm", "prompt",
    "vector", "openai", "anthropic",
]

# Packages recognised as secrets / API-key holders
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""(?:sk-[a-zA-Z0-9]{20,}|key-[a-zA-Z0-9]{20,})"""), "api_key_generic"),
    (re.compile(r"""(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY)\s*=\s*["'][^"']+["']""", re.IGNORECASE), "provider_api_key"),
    (re.compile(r"""(?:Bearer\s+[A-Za-z0-9+/=]{20,})"""), "bearer_token"),
    (re.compile(r"""(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})"""), "github_token"),
    (re.compile(r"""(?:xoxb-|xoxp-|xoxa-)[a-zA-Z0-9-]+"""), "slack_token"),
    (re.compile(r"""(?:AIza[0-9A-Za-z_-]{35})"""), "google_api_key"),
]

# Patterns that flag system/role prompt content in text files
_PROMPT_MARKERS: list[str] = ["You are", "Your role", "Do not", "Never", "Your task is", "You must"]

# Decorator/class patterns for tool detection
_TOOL_DECORATOR_RE = re.compile(r"@tool\b|@\w+\.tool\b")
_TOOL_CONSTRUCTOR_RE = re.compile(r"\bTool\s*\(")


# ── Catalog loading ────────────────────────────────────────────────────────────

def _load_catalog(catalog_dir: Path, filename: str) -> list[dict]:
    """Load a YAML catalog file and return the first list-valued key."""
    path = catalog_dir / filename
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        # Return the first top-level list in the doc
        for v in data.values():
            if isinstance(v, list):
                return v
        return []
    except Exception:
        return []


# ── Sub-parsers ────────────────────────────────────────────────────────────────

def _parse_requirements(repo_path: Path, frameworks: list[dict]) -> list[tuple[str, str, str, str]]:
    """Return list of (package, version, category, risk_notes) from dep files."""
    known: dict[str, dict] = {fw["package_name"].lower(): fw for fw in frameworks}
    results: list[tuple[str, str, str, str]] = []
    dep_files = (
        list(repo_path.glob("requirements*.txt"))
        + list(repo_path.glob("setup.py"))
        + list(repo_path.glob("pyproject.toml"))
    )
    for dep_file in dep_files:
        try:
            text = dep_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # Simple line-by-line scan for requirements.txt style
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            # Extract package name (strip version specifiers)
            pkg_raw = re.split(r"[>=<!;\[\]]", line)[0].strip().lower()
            if pkg_raw in known:
                fw = known[pkg_raw]
                version = ""
                ver_match = re.search(r"[>=<]{1,2}([^\s,;]+)", line)
                if ver_match:
                    version = ver_match.group(1)
                results.append((
                    fw.get("package_name", pkg_raw),
                    version,
                    fw.get("category", "unknown"),
                    fw.get("risk_notes", ""),
                ))
    return results


def _parse_yaml_configs(repo_path: Path) -> dict[str, Any]:
    """Scan YAML/YML files for AI-relevant configuration keys."""
    interesting_keys = {
        "chunking", "retrieval", "embeddings", "vector_store", "model",
        "system_prompt", "safety", "llm", "prompt_template", "memory",
        "chain_type", "tools",
    }
    found: dict[str, Any] = {}
    for yaml_path in list(repo_path.glob("**/*.yaml")) + list(repo_path.glob("**/*.yml")):
        try:
            with yaml_path.open("r", encoding="utf-8", errors="replace") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for k, v in data.items():
            if k.lower() in interesting_keys:
                rel = str(yaml_path.relative_to(repo_path))
                found[f"{rel}::{k}"] = v
    return found


def _parse_python_tools(repo_path: Path) -> list[dict[str, Any]]:
    """AST-scan Python files for tool definitions."""
    tools: list[dict[str, Any]] = []
    for py_file in repo_path.glob("**/*.py"):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except Exception:
            continue

        for node in ast.walk(tree):
            # @tool decorated functions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                has_tool_decorator = any(
                    (isinstance(d, ast.Name) and d.id == "tool")
                    or (isinstance(d, ast.Attribute) and d.attr == "tool")
                    for d in node.decorator_list
                )
                if has_tool_decorator:
                    docstring = ast.get_docstring(node) or ""
                    args = [a.arg for a in node.args.args]
                    tools.append({
                        "name": node.name,
                        "kind": "decorated_function",
                        "docstring": docstring[:200],
                        "parameters": args,
                        "file": str(py_file.relative_to(repo_path)),
                    })

            # Lists/variables named "tools"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.lower() == "tools":
                        if isinstance(node.value, (ast.List, ast.Tuple)):
                            tool_names = []
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Call):
                                    if isinstance(elt.func, ast.Name):
                                        tool_names.append(elt.func.id)
                                    elif isinstance(elt.func, ast.Attribute):
                                        tool_names.append(elt.func.attr)
                                elif isinstance(elt, ast.Name):
                                    tool_names.append(elt.id)
                            if tool_names:
                                tools.append({
                                    "name": target.id,
                                    "kind": "tool_list",
                                    "items": tool_names,
                                    "file": str(py_file.relative_to(repo_path)),
                                })
    return tools


def _parse_prompt_files(repo_path: Path) -> list[tuple[str, str]]:
    """Find and return (relative_path, content_sample) for prompt files."""
    results: list[tuple[str, str]] = []
    prompt_globs = [
        "prompts/**/*.txt",
        "prompts/**/*.md",
        "**/*system*.txt",
        "**/*system_prompt*.txt",
        "**/*system_message*.txt",
        "**/prompts/*.txt",
        "**/prompts/*.md",
    ]
    seen: set[Path] = set()
    for pattern in prompt_globs:
        for path in repo_path.glob(pattern):
            if path in seen:
                continue
            seen.add(path)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if any(marker in content for marker in _PROMPT_MARKERS):
                rel = str(path.relative_to(repo_path))
                results.append((rel, content[:1000]))
    return results


def _scan_secrets_in_repo(repo_path: Path) -> list[tuple[str, int, str]]:
    """Regex-scan all text files for secret patterns. Returns (file, line_no, pattern_name)."""
    results: list[tuple[str, int, str]] = []
    text_extensions = {".py", ".txt", ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".sh"}
    for fpath in repo_path.rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in text_extensions:
            continue
        # Skip large files
        try:
            if fpath.stat().st_size > 1_000_000:
                continue
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, start=1):
            for pattern, label in _SECRET_PATTERNS:
                if pattern.search(line):
                    results.append((str(fpath.relative_to(repo_path)), lineno, label))
                    break  # One hit per line is enough
    return results


def _scan_git_history(repo_path: Path) -> list[tuple[str, str, str]]:
    """Use GitPython to scan last 100 commits for secret-looking diff content."""
    results: list[tuple[str, str, str]] = []
    try:
        import git  # type: ignore[import]
        repo = git.Repo(repo_path)
        commits = list(repo.iter_commits("HEAD", max_count=100))
        for commit in commits:
            try:
                if commit.parents:
                    diff = commit.parents[0].diff(commit, create_patch=True)
                else:
                    diff = commit.diff(git.NULL_TREE, create_patch=True)
                for d in diff:
                    patch_text = d.diff.decode("utf-8", errors="replace") if d.diff else ""
                    for pattern, label in _SECRET_PATTERNS:
                        m = pattern.search(patch_text)
                        if m:
                            results.append((
                                commit.hexsha[:8],
                                label,
                                m.group(0)[:60],
                            ))
                            break
            except Exception:
                continue
    except Exception:
        pass
    return results


# ── Main technique ─────────────────────────────────────────────────────────────

class RepoMiningTechnique(Technique):
    id: ClassVar[str] = "passive.repo_mining"
    intrusiveness: ClassVar = "low"
    produces: ClassVar[set[str]] = {
        "ai.framework",
        "ai.vector_db",
        "ai.system_prompt",
        "ai.tools",
        "secrets.hardcoded",
    }

    async def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # Determine catalog dir relative to the package
        catalog_dir = Path(__file__).parent.parent.parent / "catalogs"
        frameworks = _load_catalog(catalog_dir, "frameworks.yaml")
        vector_dbs = _load_catalog(catalog_dir, "vector_dbs.yaml")

        # Repo adapter from context
        repo_adapter = getattr(self.ctx, "repo_adapter", None)
        if repo_adapter is None:
            return findings

        # Fetch matching repos
        try:
            repos = await repo_adapter.search(keywords=_SEARCH_KEYWORDS)
        except Exception:
            return findings

        for repo in repos:
            clone_dir = self.ctx.cache_dir / self.ctx.run_id / "repos" / getattr(repo, "id", "unknown")
            clone_dir.mkdir(parents=True, exist_ok=True)

            # Clone or use existing working copy
            try:
                await repo_adapter.clone(repo, clone_dir)
            except Exception:
                continue

            repo_path = clone_dir

            # ── Framework detection ───────────────────────────────────────────
            detected_packages = _parse_requirements(repo_path, frameworks)
            for pkg, version, category, risk_notes in detected_packages:
                findings.append(
                    self._make_finding(
                        target,
                        severity="info",
                        confidence="high",
                        title=f"AI framework identified: {pkg}",
                        evidence={
                            "package": pkg,
                            "version": version,
                            "category": category,
                            "risk_notes": risk_notes[:300],
                            "repo": getattr(repo, "id", ""),
                        },
                    )
                )

            # Check for vector DB packages
            vdb_known = {vdb.get("package_name", "").lower(): vdb for vdb in vector_dbs if isinstance(vdb, dict)}
            for pkg, version, category, _ in detected_packages:
                if pkg.lower() in vdb_known:
                    vdb = vdb_known[pkg.lower()]
                    findings.append(
                        self._make_finding(
                            target,
                            severity="info",
                            confidence="high",
                            title=f"Vector database identified: {vdb.get('canonical_name', pkg)}",
                            evidence={
                                "package": pkg,
                                "version": version,
                                "repo": getattr(repo, "id", ""),
                            },
                        )
                    )

            # ── YAML configs ──────────────────────────────────────────────────
            yaml_configs = _parse_yaml_configs(repo_path)
            if yaml_configs:
                findings.append(
                    self._make_finding(
                        target,
                        severity="medium",
                        confidence="medium",
                        title="RAG/AI configuration exposed in YAML files",
                        evidence={
                            "repo": getattr(repo, "id", ""),
                            "config_entries": {k: str(v)[:200] for k, v in yaml_configs.items()},
                        },
                    )
                )

            # ── Tool enumeration ──────────────────────────────────────────────
            tools = _parse_python_tools(repo_path)
            if tools:
                findings.append(
                    self._make_finding(
                        target,
                        severity="low",
                        confidence="medium",
                        title=f"AI tools enumerated in repository ({len(tools)} found)",
                        evidence={
                            "repo": getattr(repo, "id", ""),
                            "tools": tools[:20],  # cap to avoid oversized findings
                        },
                    )
                )

            # ── System prompt files ───────────────────────────────────────────
            prompt_files = _parse_prompt_files(repo_path)
            for rel_path, content_sample in prompt_files:
                findings.append(
                    self._make_finding(
                        target,
                        severity="high",
                        confidence="high",
                        title=f"System prompt exposed in repository: {rel_path}",
                        evidence={
                            "repo": getattr(repo, "id", ""),
                            "file": rel_path,
                            "content_sample": content_sample,
                        },
                    )
                )

            # ── Hardcoded secrets (file scan) ─────────────────────────────────
            secret_hits = _scan_secrets_in_repo(repo_path)
            for file_path, lineno, pattern_name in secret_hits:
                findings.append(
                    self._make_finding(
                        target,
                        severity="critical",
                        confidence="medium",
                        title=f"Potential hardcoded secret in repository: {pattern_name}",
                        evidence={
                            "repo": getattr(repo, "id", ""),
                            "file": file_path,
                            "line": lineno,
                            "pattern": pattern_name,
                        },
                    )
                )

            # ── Git history secret scan ────────────────────────────────────────
            git_hits = _scan_git_history(repo_path)
            for commit_sha, pattern_name, snippet in git_hits:
                findings.append(
                    self._make_finding(
                        target,
                        severity="critical",
                        confidence="medium",
                        title=f"Secret pattern found in git history: {pattern_name}",
                        evidence={
                            "repo": getattr(repo, "id", ""),
                            "commit": commit_sha,
                            "pattern": pattern_name,
                            "snippet": snippet,
                        },
                    )
                )

        return findings

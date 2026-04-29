"""Translate SIEM detection queries (KQL/SPL/Sigma/Lucene) into Python regex patterns.

This is intentionally lossy and conservative: when the structure cannot be
mapped 1:1, we emit a regex that errs on matching MORE than the original
query (so pre-flight blocks more, not less). False positives are acceptable;
false negatives are not.

Supported subset:
  - String literals: "foo", 'foo' → escaped substring match.
  - Field equality:  field:"value" / field="value" → "value" substring.
  - Wildcards:       *foo* → ".*foo.*"; foo* → "foo.*".
  - Boolean:         AND/OR (lowered to alternation/all-of), NOT not modelled
                     (returns None for that branch — pre-flight will treat as
                     "unknown" → safe-side block).
  - Parentheses:     respected via recursive descent.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Literal


QueryLanguage = Literal["kql", "spl", "kusto", "lucene", "sigma"]


@dataclass
class CompiledRule:
    rule_id: str
    language: QueryLanguage
    regex: re.Pattern[str]
    raw_query: str


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r'''
    \s*(
        "(?:\\.|[^"\\])*"        # double-quoted string
      | '(?:\\.|[^'\\])*'        # single-quoted string
      | \(                       # paren open
      | \)                       # paren close
      | (?:AND|OR|NOT)\b         # boolean (case-sensitive)
      | (?:and|or|not)\b
      | [^\s()]+                 # bare token (field:value, value, etc.)
    )
    ''',
    re.VERBOSE,
)


def _tokens(q: str) -> list[str]:
    return [m.group(1) for m in _TOKEN_RE.finditer(q)]


def _strip_quotes(t: str) -> str:
    if len(t) >= 2 and t[0] in '"\'' and t[-1] == t[0]:
        return t[1:-1]
    return t


def _wildcard_to_regex(s: str) -> str:
    parts = s.split("*")
    return ".*".join(re.escape(p) for p in parts)


# ---------------------------------------------------------------------------
# Parser → regex
# ---------------------------------------------------------------------------

def _term_to_regex(token: str) -> str | None:
    """Convert a single search term into a regex fragment."""
    if not token:
        return None
    # field:value or field=value
    m = re.match(r'^([A-Za-z_.][\w.\-]*)\s*[:=]\s*(.+)$', token)
    if m:
        value = _strip_quotes(m.group(2))
    else:
        value = _strip_quotes(token)
    if not value:
        return None
    if "*" in value:
        return _wildcard_to_regex(value)
    return re.escape(value)


def _parse(tokens: list[str], pos: int = 0) -> tuple[str | None, int]:
    """Recursive descent parser → regex string. Returns (regex, next_pos)."""
    out: list[str] = []
    op: str = "AND"  # default conjunction

    while pos < len(tokens):
        t = tokens[pos]
        up = t.upper()

        if t == "(":
            inner, pos = _parse(tokens, pos + 1)
            if inner:
                out.append(f"(?:{inner})")
            else:
                out.append("(?:.*)")
            continue
        if t == ")":
            return _combine(out, op), pos + 1
        if up == "AND":
            op = "AND"
            pos += 1
            continue
        if up == "OR":
            op = "OR"
            pos += 1
            continue
        if up == "NOT":
            # Skip negated term — pre-flight cannot rephrase NOT safely.
            pos += 2
            continue

        frag = _term_to_regex(t)
        if frag:
            out.append(frag)
        pos += 1

    return _combine(out, op), pos


def _combine(parts: list[str], op: str) -> str | None:
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    if op == "OR":
        return "(?:" + "|".join(parts) + ")"
    # AND: lookahead conjunction so order doesn't matter
    return "".join(f"(?=.*{p})" for p in parts) + ".*"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def query_to_regex(query: str, language: QueryLanguage = "kql") -> re.Pattern[str] | None:
    """Compile a SIEM query to a Python regex matching content that the rule
    would likely flag. Returns ``None`` when the query is empty or unparsable.
    """
    q = (query or "").strip()
    if not q:
        return None
    try:
        tokens = _tokens(q)
        pattern, _ = _parse(tokens)
        if not pattern:
            return None
        return re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except Exception:
        return None

"""Case-scoped host identity dictionary.

See `specs/host-identity-normalization-2026-04-24.md` Rev 5 for the full
model. Key pins this file implements:

- **SC-1:** `resolve()` is pure — no side-effect writes, no unmapped
  append. Mutation is exclusive to batch-discovery (Commit B) and CLI
  (Commit D). Makes per-parser concurrent calls safe on shared dicts.
- **SC-2:** Levenshtein threshold 0.85 (covers wksn01/wkstn01 typo).
- **SC-3:** Proposal ties broken alphabetically by canonical.
- **SC-4:** `resolve("")` / `resolve(None)` / whitespace-only → None
  no-op (empty Computer is a parse anomaly, not an identity).
- **SC-5:** Trailing-dot FQDN normalized.
- **SC-6:** Schema `version: 1` only; others raise UnsupportedHostDictVersion.
- **SC-7:** yaml.safe_load exclusively.
- **SC-8:** `save()` and `add_alias()` shaped here as stubs — Commit D
  fills them in when the CLI needs to persist edits.

OD1 auto-accept (confidence=1.00) lives OUTSIDE `resolve()` — the flag is
stored on the dict, but the auto-accept action happens in Commit B's
single-threaded batch-discovery phase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = 1
_TRIAGE_SUFFIXES = ("-triage", "_triage")


class UnsupportedHostDictVersion(Exception):
    """Raised when a loaded host-dictionary.yaml carries a non-matching version."""


def _normalize(raw: str | None) -> str:
    """Canonicalize an input hostname for lookup/compare.

    Returns "" (not None) for empty/whitespace/None inputs — callers use
    that as the no-op sentinel. Lowercases, strips whitespace, strips
    trailing FQDN dot (SC-5). Case is preserved in storage only; lookup
    never sees the original case.
    """
    if not raw:
        return ""
    s = raw.strip().lower()
    if s.endswith("."):
        s = s[:-1]
    return s


def _strip_for_proposal(raw: str, domains: list[str]) -> str:
    """Strip domain + triage suffix + lowercase for propose_canonical matching."""
    s = _normalize(raw)
    if not s:
        return ""
    for suf in _TRIAGE_SUFFIXES:
        if s.endswith(suf):
            s = s[: -len(suf)]
            break
    for d in domains:
        dn = d.lower().lstrip(".")
        suf = "." + dn
        if s.endswith(suf):
            s = s[: -len(suf)]
            break
    return s


def _levenshtein(a: str, b: str) -> int:
    """Iterative DP Levenshtein. Small strings only (hostnames) — O(len(a)*len(b))."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            )
        prev = curr
    return prev[-1]


def _similarity(a: str, b: str) -> float:
    """0.0–1.0 similarity derived from Levenshtein. 1.0 = identical."""
    if not a and not b:
        return 1.0
    d = _levenshtein(a, b)
    longer = max(len(a), len(b))
    return 1.0 - d / longer if longer else 1.0


class HostDictionary:
    """Load / lookup / propose over a case's host-dictionary.yaml.

    See module docstring for the SC-pin list. Commit A ships only the
    read side; write helpers are stubs raising NotImplementedError so
    Commit D can fill them in without refactoring this class's shape.
    """

    def __init__(
        self,
        hosts: dict[str, dict[str, Any]] | None = None,
        unmapped: list[dict[str, Any]] | None = None,
        domains: list[str] | None = None,
        auto_accept_high_confidence: bool = True,
        path: Path | None = None,
    ):
        self.hosts = hosts or {}
        self.unmapped = unmapped or []
        self.domains = list(domains) if domains else []
        self.auto_accept_high_confidence = auto_accept_high_confidence
        self.path = path
        # Lookup map built from all aliases (normalized) → canonical.
        # Canonical itself is also an alias of itself.
        self._alias_to_canonical: dict[str, str] = {}
        self._rebuild_alias_map()

    def _rebuild_alias_map(self) -> None:
        self._alias_to_canonical = {}
        for canonical, entry in self.hosts.items():
            norm_can = _normalize(canonical)
            if norm_can:
                self._alias_to_canonical[norm_can] = canonical
            for alias in entry.get("aliases", []) or []:
                na = _normalize(alias)
                if na:
                    self._alias_to_canonical[na] = canonical

    @classmethod
    def load(cls, path: Path) -> HostDictionary:
        """Load a host-dictionary.yaml. Raises UnsupportedHostDictVersion on
        any version other than SCHEMA_VERSION (SC-6 pin).
        """
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}  # SC-7: safe_load only
        version = data.get("version")
        if version != SCHEMA_VERSION:
            raise UnsupportedHostDictVersion(
                f"host-dictionary.yaml at {path} has version={version!r}; "
                f"this opensearch-mcp supports version={SCHEMA_VERSION} only. "
                "Upgrade the dictionary via migration, or use a compatible "
                "opensearch-mcp release."
            )
        return cls(
            hosts=data.get("hosts") or {},
            unmapped=data.get("unmapped") or [],
            domains=data.get("domains") or [],
            auto_accept_high_confidence=bool(data.get("auto_accept_high_confidence", True)),
            path=path,
        )

    def to_yaml(self) -> str:
        """Serialize to YAML matching load shape. Used by save() / tests."""
        payload: dict[str, Any] = {
            "version": SCHEMA_VERSION,
            "auto_accept_high_confidence": self.auto_accept_high_confidence,
            "domains": self.domains,
            "hosts": self.hosts,
            "unmapped": self.unmapped,
        }
        return yaml.safe_dump(payload, default_flow_style=False, sort_keys=False)

    def resolve(self, raw: str | None) -> str | None:
        """Pure lookup — NO side effects (SC-1 pin).

        Does not mutate `unmapped[]`, does not auto-learn, does not write
        back. Returns the canonical id on exact normalized-alias match,
        or None on no match / empty input (SC-4).
        """
        key = _normalize(raw)
        if not key:
            return None
        return self._alias_to_canonical.get(key)

    def has_alias(self, key_normalized: str) -> bool:
        """Public lookup companion to resolve() — checks if a pre-normalized
        key is a known alias. Callers that have already normalized the
        input can skip the re-normalize inside resolve(). Same contract:
        pure, no side effects.
        """
        return bool(key_normalized) and key_normalized in self._alias_to_canonical

    def get_canonical_for_alias(self, key_normalized: str) -> str | None:
        """Public lookup for a pre-normalized key. Returns canonical or None."""
        if not key_normalized:
            return None
        return self._alias_to_canonical.get(key_normalized)

    def __contains__(self, canonical: str) -> bool:
        return canonical in self.hosts

    def save(self) -> None:
        """Atomic temp+rename write — Commit A stub. Commit D fills it in."""
        raise NotImplementedError(
            "HostDictionary.save() is a Commit A stub. Wait for Commit D "
            "(vhir case host ... CLI) to implement persistence."
        )

    def add_alias(self, raw: str, canonical: str) -> None:
        """Add raw as alias of canonical — Commit A stub. Commit D fills it in."""
        raise NotImplementedError(
            "HostDictionary.add_alias() is a Commit A stub. Wait for Commit D."
        )


def propose_canonical(raw: str | None, host_dict: HostDictionary) -> tuple[str | None, float]:
    """Suggest a canonical id for an unmapped raw + a confidence score.

    Algorithm:
      - Strip trailing dot, domain, and -triage/_triage suffix; lowercase.
      - If stripped form exactly matches a dict canonical or alias →
        return (canonical, 1.00). Exact-strip equality is algebraic
        identity; OD1 auto-accepts at this score.
      - Else, highest Levenshtein similarity ≥ 0.85 (SC-2) against any
        existing canonical wins. Ties broken alphabetically (SC-3).
      - Else (None, 0.0).
    """
    if not raw or not _normalize(raw):
        return None, 0.0

    stripped = _strip_for_proposal(raw, host_dict.domains)

    if host_dict.has_alias(stripped):
        return host_dict.get_canonical_for_alias(stripped), 1.00

    best_canonicals: list[str] = []
    best_score = 0.0
    for canonical in sorted(host_dict.hosts.keys()):
        score = _similarity(stripped, _normalize(canonical))
        if score < 0.85:
            continue
        if score > best_score:
            best_canonicals = [canonical]
            best_score = score
        elif score == best_score:
            best_canonicals.append(canonical)

    if best_canonicals:
        return best_canonicals[0], best_score  # sorted → alphabetically earliest
    return None, 0.0

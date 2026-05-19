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
- **SC-8:** `save()`, `add_alias()`, and `add_canonical()` mutate the
  dictionary. `save()` writes via atomic temp+rename. Callers decide
  when to persist; mutation is sequenced before persistence.

OD1 auto-accept (confidence=1.00) lives OUTSIDE `resolve()` — the flag is
stored on the dict, but the auto-accept action happens in the preflight
discovery phase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = 1
_TRIAGE_SUFFIXES = ("-triage", "_triage")


class UnsupportedHostDictVersion(Exception):
    """Raised when a loaded host-dictionary.yaml carries a non-matching version."""


class InvalidHostnameValue(ValueError):
    """Raised when a hostname value is unsafe to store in the dictionary.

    yaml.safe_dump escape-encodes NULL bytes and ASCII control chars
    rather than raising — adversarial values would survive into
    host-dictionary.yaml as escape-encoded strings and contaminate
    downstream queries. The dict primitives gate at the write boundary
    so every mutation path (preflight, case_host_fix, future CLI) is
    covered.
    """


def detect_host_id_mapping_type(props: dict) -> str | None:
    """Detect host.id mapping type across flat-dotted vs nested forms.

    OpenSearch dynamic mapping can store `host.id` in two shapes:
      1. Flat dotted property: `properties["host.id"] = {"type": ...}`
         — what our v1 templates declare.
      2. Nested object: `properties["host"]["properties"]["id"] = {...}`
         — what default dynamic mapping creates for pre-v1 docs.

    Returns the type string (e.g. "keyword", "text") or None if the
    field is genuinely absent from both forms.

    Lives in host_dictionary (not ingest_cli) because both server.py's
    case_host_fix and ingest_cli's preflight need it; lazy-import from
    ingest_cli created a stale-loaded-code surface where a long-running
    MCP gateway could miss this detector.
    """
    # Flat dotted form (v1 template shape).
    flat = props.get("host.id")
    if isinstance(flat, dict) and "type" in flat:
        return flat.get("type")
    # Nested form (default dynamic mapping shape).
    host_node = props.get("host")
    if isinstance(host_node, dict):
        host_props = host_node.get("properties") or {}
        id_node = host_props.get("id")
        if isinstance(id_node, dict) and "type" in id_node:
            return id_node.get("type")
    return None


def _validate_hostname_for_storage(value: str | None, context: str) -> None:
    """Reject NULL byte / ASCII control characters at the dict-write boundary.

    Allowed: anything with no NULL byte and no ASCII control char below
    0x20 except tab. Lucene metacharacters, Unicode, and Punycode pass
    through — they're safe under the term-DSL query path.
    """
    if not isinstance(value, str):
        raise InvalidHostnameValue(
            f"{context}: hostname must be a string, got {type(value).__name__}"
        )
    if not value:
        raise InvalidHostnameValue(f"{context}: hostname must not be empty")
    if "\x00" in value:
        raise InvalidHostnameValue(f"{context}: hostname contains NULL byte")
    for ch in value:
        if ord(ch) < 0x20 and ch != "\t":
            raise InvalidHostnameValue(
                f"{context}: hostname contains ASCII control char {ord(ch):#04x}"
            )


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

    def save(self, *, merge: bool = False) -> None:
        """Atomic temp+rename write to self.path, serialized under a
        per-case `fcntl.LOCK_EX` file lock.

        Two modes (closes WSL2 Test B2 — concurrent last-write-wins):

        - **`merge=False` (default, replacing semantics)**: the
          in-memory state IS the operator's intent. Save writes it
          verbatim. Use for `case_host_fix` where deletions and
          remappings must take effect (caller is responsible for
          calling load() under the same lock if needed for atomicity).

        - **`merge=True` (additive semantics)**: before write, re-read
          the file from disk and union hosts/aliases. Use for preflight
          where multiple concurrent ingests may have applied different
          ADDITIONS to the same case dict. Union prevents Run A's adds
          from being clobbered by Run B's save.

        The lock is `fcntl.LOCK_EX` on `<path>.lock`. POSIX only.
        Windows hosts never call save() directly.

        Atomicity: write to `<path>.tmp`, then `os.replace`. A crash
        between open and replace leaves the prior file intact.
        """
        if self.path is None:
            raise ValueError("HostDictionary.save() requires path; got None")
        import fcntl
        import os

        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        # M2: open in 'a+b' — atomic create-if-missing + append-mode, no
        # TOCTOU race between touch() and open().
        with open(lock_path, "a+b") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                if merge and self.path.exists():
                    self._merge_from_disk()
                tmp = self.path.with_suffix(self.path.suffix + ".tmp")
                tmp.write_text(self.to_yaml(), encoding="utf-8")
                os.replace(tmp, self.path)
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def _merge_from_disk(self) -> None:
        """Union hosts/aliases AND preserve disk-only non-list fields.

        Called from save() under file lock. Other savers' changes get
        preserved — in-memory copy is treated as the latest delta, not
        as authoritative replacement.

        Merge policy:
          - canonical on disk but not in self.hosts → copy disk's entry verbatim.
          - canonical in both → union aliases; for any non-list field
            (role, notes, rename_history, ...) present on disk but
            absent in in-memory → copy from disk. In-memory wins on
            conflict (same key with different value).

        This closes the M3 silent-overwrite gap: if Process A sets
        `role: workstation` and Process B saves (with merge=True) at
        the same time, Process B's save preserves Process A's role
        rather than dropping it.
        """
        try:
            other = HostDictionary.load(self.path)
        except (OSError, UnsupportedHostDictVersion):
            return  # Disk file unreadable; in-memory wins.
        for canonical, entry in other.hosts.items():
            if canonical not in self.hosts:
                self.hosts[canonical] = entry
                continue
            mine = self.hosts[canonical]
            mine_aliases = mine.setdefault("aliases", [])
            for alias in entry.get("aliases", []) or []:
                if alias not in mine_aliases:
                    mine_aliases.append(alias)
            # M3: preserve disk-only non-list fields (role, notes,
            # rename_history, etc). In-memory wins on key conflict.
            for key, value in entry.items():
                if key == "aliases":
                    continue
                if key not in mine:
                    mine[key] = value
        self._rebuild_alias_map()

    def add_alias(self, raw: str, canonical: str) -> None:
        """Add `raw` as an alias of an existing `canonical`.

        Mutates `self.hosts` and rebuilds the lookup map. Does NOT write
        to disk — caller decides when to `save()`. If `canonical` is not
        in `self.hosts`, raises ValueError; use `add_canonical` to create
        a new canonical.

        Idempotent: re-adding an existing alias is a no-op.
        Inputs are validated via `_validate_hostname_for_storage` — gate
        applies regardless of caller (preflight, case_host_fix, CLI).
        """
        _validate_hostname_for_storage(raw, "add_alias raw")
        _validate_hostname_for_storage(canonical, "add_alias canonical")
        if canonical not in self.hosts:
            raise ValueError(
                f"add_alias: canonical {canonical!r} not in dictionary; "
                f"use add_canonical to create it"
            )
        aliases = self.hosts[canonical].setdefault("aliases", [])
        if raw not in aliases:
            aliases.append(raw)
        self._rebuild_alias_map()

    def add_canonical(self, raw: str) -> None:
        """Create a new canonical entry with `raw` as its first alias.

        Used when preflight discovers a host that has no close match in
        the existing dictionary — `raw` becomes its own canonical. Also
        used by `case_host_fix` when the operator targets a new
        canonical that doesn't exist yet.

        Mutates `self.hosts` and rebuilds the lookup map. Idempotent —
        duplicate-check normalizes case to prevent `ADMIN01` from
        creating a second canonical when `admin01` exists.

        Inputs validated via `_validate_hostname_for_storage`.
        """
        _validate_hostname_for_storage(raw, "add_canonical raw")
        if raw in self.hosts:
            return
        # Normalize duplicate check so case variants don't create
        # redundant canonicals.
        norm_raw = _normalize(raw)
        if norm_raw and norm_raw in {_normalize(k) for k in self.hosts}:
            return
        self.hosts[raw] = {"aliases": [raw]}
        self._rebuild_alias_map()


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

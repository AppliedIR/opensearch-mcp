"""A case's pre-0.6.4 host dictionary (`host-dictionary.yaml`), read only.

Host identity now lives in the case's host logs (sift_common.host_identity);
this file is no longer written. It is read once, when a case from before
0.6.4 is first opened, to seed those logs, and parsers still resolve a raw
name through it. `resolve()` is a pure lookup: it lowercases, strips and
drops a trailing dot, and returns the canonical or None.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = 1


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

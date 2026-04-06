"""Structured return types for ingest operations."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ArtifactResult:
    """Result of ingesting a single artifact type for one host."""

    artifact: str  # "amcache", "shimcache", etc.
    index: str  # "case-INC001-amcache-rd01"
    indexed: int = 0
    skipped: int = 0
    bulk_failed: int = 0
    existing_before: int = 0  # client.count() before ingest
    source_files: list[str] = field(default_factory=list)
    error: str = ""  # non-empty if the tool failed
    note: str = ""  # informational (e.g., "parsed with Plaso fallback")


@dataclass
class HostResult:
    """Result of ingesting all artifacts for one host."""

    hostname: str
    volume_root: str = ""
    artifacts: list[ArtifactResult] = field(default_factory=list)

    @property
    def total_indexed(self) -> int:
        return sum(a.indexed for a in self.artifacts)


@dataclass
class IngestResult:
    """Result of a full ingest operation (one or more hosts)."""

    hosts: list[HostResult] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    pipeline_version: str = ""

    @property
    def total_indexed(self) -> int:
        return sum(h.total_indexed for h in self.hosts)

    def to_dict(self) -> dict:
        """Serialize for MCP JSON response."""
        return {
            "hosts": [
                {
                    "hostname": h.hostname,
                    "volume_root": h.volume_root,
                    "artifacts": [
                        {
                            "artifact": a.artifact,
                            "index": a.index,
                            "indexed": a.indexed,
                            "skipped": a.skipped,
                            "bulk_failed": a.bulk_failed,
                            "existing_before": a.existing_before,
                            "error": a.error,
                            "note": a.note,
                        }
                        for a in h.artifacts
                    ],
                }
                for h in self.hosts
            ],
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "total_indexed": self.total_indexed,
            "pipeline_version": self.pipeline_version,
        }

    def print_summary(self) -> None:
        """Print human-readable CLI summary."""
        for host in self.hosts:
            print(f"\n  {host.hostname}:")
            for a in host.artifacts:
                if a.error:
                    print(f"    {a.artifact}: FAILED — {a.error}")
                    continue
                new = a.indexed - min(a.indexed, a.existing_before)
                if a.existing_before > 0 and new == 0:
                    label = f"overlapping ({a.existing_before:,} existing, 0 new)"
                elif a.existing_before > 0:
                    label = f"extended ({new:,} new + {a.existing_before:,} existing)"
                else:
                    label = f"{a.indexed:,} entries"
                parts = [label]
                if a.skipped:
                    parts.append(f"{a.skipped} skipped")
                if a.bulk_failed:
                    parts.append(f"{a.bulk_failed} bulk failed")
                print(f"    {a.artifact}: {', '.join(parts)}")

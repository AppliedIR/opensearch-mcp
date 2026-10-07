"""The names scan: which evidence units an ingest is about to read, and which
host names each one gives.

Every ingest scans before it writes anything: the CLI and every
`idx_ingest*` run (a dry run returns the summary). Each unit and every name
found in it is recorded in the case's host-observation log, with where it
was found and its origin, so the examiner can confirm the machines.

The scan reads what the ingest has already made available. It never
mounts, never calls sudo and never extracts.

Names by input:
- a host folder: the folder name; the SYSTEM hive's ComputerName (active and
  set), Tcpip Hostname / NV Hostname and their Domain; SOFTWARE's
  MachineGuid; the `Computer` of a sample of each event log; and the host
  columns of the first rows of every CSV and JSON file;
- a Velociraptor collection: its client's hostname and FQDN, and client id;
- a disk image: each volume a reader covers is a host folder (or a volume
  Plaso reads); one it can't read is an unnamed candidate, with why;
- a memory image: its file name, its archive's name, and a host name the
  caller gave;
- log files: the host columns of their first rows, host names in their file
  names, and a host name the caller gave.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from sift_common import host_identity

logger = logging.getLogger(__name__)

ROWS = 50  # first rows of each CSV/JSON file read for host columns
EVTX_SAMPLE = 50  # records read from each event log for its Computer

ARTIFACT = host_identity.ARTIFACT
FOLDER = host_identity.FOLDER
ARGUMENT = "argument"
FILE_NAME = "file-name"
AI_WRITTEN = "ai"  # a file the AI can write: never confirms a machine

# Case folders the AI's tools write into.
_AI_WRITABLE = ("extractions",)


@dataclass
class Name:
    raw: str
    evidence: str
    origin: str


@dataclass
class Unit:
    locator: str
    source: str
    names: list[Name] = field(default_factory=list)
    attrs: dict = field(default_factory=dict)
    note: str = ""

    @property
    def key(self) -> str:
        return host_identity.unit_key(self.locator)

    def add(self, raw, evidence: str, origin: str) -> None:
        if not isinstance(raw, str):
            return
        raw = raw.strip()
        if not raw or len(raw) > 255 or any(ord(c) < 0x20 for c in raw):
            return
        if not any(n.raw == raw and n.evidence == evidence for n in self.names):
            self.names.append(Name(raw, evidence, origin))

    def summary(self) -> dict:
        out = {
            "unit": self.key,
            "locator": self.locator,
            "source": self.source,
            "names": sorted({n.raw for n in self.names}),
        }
        if self.attrs:
            out.update(self.attrs)
        if self.note:
            out["note"] = self.note
        return out


def file_origin(case_dir: Path | None, path: Path) -> str:
    """ARTIFACT for evidence the examiner put in the case; AI_WRITTEN for a
    file in a folder the AI's tools write into."""
    if case_dir is None:
        return ARTIFACT
    try:
        rel = Path(path).resolve().relative_to(Path(case_dir).resolve())
    except ValueError:
        return ARTIFACT
    return AI_WRITTEN if rel.parts and rel.parts[0] in _AI_WRITABLE else ARTIFACT


def _rel(case_dir: Path | None, path: Path) -> str:
    return host_identity.unit_locator(path, case_dir)


# --------------------------------------------------------------------------
# Readers


def registry_names(volume_root: Path) -> tuple[list[tuple[str, str]], dict]:
    """[(name, where)] from a volume's SYSTEM hive and {"machine_guid": …}
    from its SOFTWARE hive."""
    from opensearch_mcp.paths import resolve_case_insensitive

    names: list[tuple[str, str]] = []
    attrs: dict = {}
    try:
        from regipy.registry import RegistryHive
    except ImportError:
        return names, attrs

    def values(reg, path):
        try:
            return {v.name: v.value for v in reg.get_key(path).iter_values()}
        except Exception:
            return {}

    system = resolve_case_insensitive(volume_root, "Windows/System32/config/SYSTEM")
    if system:
        try:
            reg = RegistryHive(str(system))
        except Exception as e:
            logger.debug("SYSTEM hive unreadable at %s: %s", system, e)
            reg = None
        for cs in ("ControlSet001", "ControlSet002") if reg else ():
            for sub in ("ActiveComputerName", "ComputerName"):
                v = values(reg, f"\\{cs}\\Control\\ComputerName\\{sub}").get("ComputerName")
                if v:
                    names.append((str(v), f"SYSTEM {sub}"))
            tcpip = values(reg, f"\\{cs}\\Services\\Tcpip\\Parameters")
            for host_key, domain_key in (("Hostname", "Domain"), ("NV Hostname", "NV Domain")):
                host = tcpip.get(host_key)
                if host:
                    names.append((str(host), f"SYSTEM Tcpip {host_key}"))
                    if tcpip.get(domain_key):
                        names.append(
                            (
                                f"{host}.{tcpip[domain_key]}",
                                f"SYSTEM Tcpip {host_key}+{domain_key}",
                            )
                        )
            if names:
                break
    software = resolve_case_insensitive(volume_root, "Windows/System32/config/SOFTWARE")
    if software:
        try:
            guid = values(RegistryHive(str(software)), "\\Microsoft\\Cryptography").get(
                "MachineGuid"
            )
        except Exception:
            guid = None
        if guid:
            attrs["machine_guid"] = str(guid)
    return names, attrs


def evtx_computers(evtx_dir: Path) -> list[tuple[str, str]]:
    """[(Computer, log name)] from the first records of each event log."""
    out: list[tuple[str, str]] = []
    try:
        from evtx import PyEvtxParser
    except ImportError:
        return out
    try:
        files = sorted(f for f in Path(evtx_dir).iterdir() if f.suffix.lower() == ".evtx")
    except OSError:
        return out
    for f in files:
        seen: set[str] = set()
        try:
            for n, record in enumerate(PyEvtxParser(str(f)).records_json()):
                if n >= EVTX_SAMPLE:
                    break
                try:
                    system = json.loads(record["data"])["Event"]["System"]
                except (ValueError, KeyError, TypeError):
                    continue
                computer = system.get("Computer") if isinstance(system, dict) else None
                if isinstance(computer, str) and computer and computer not in seen:
                    seen.add(computer)
                    out.append((computer, f"{f.name} Computer"))
        except Exception as e:  # a damaged log: its sample is what was read
            logger.debug("evtx sample stopped in %s: %s", f, e)
    return out


def row_names(path: Path) -> list[str]:
    """Host-column values from the first rows of a CSV/TSV or JSON file."""
    from opensearch_mcp.hostname import extract_host_from_record

    out: list[str] = []
    suffix = path.suffix.lower()
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
            if suffix in (".json", ".jsonl", ".ndjson"):
                head = f.read(1 << 20)
                rows: list = []
                stripped = head.lstrip()
                if stripped.startswith("["):
                    try:
                        rows = json.loads(stripped)
                    except ValueError:
                        rows = []
                else:
                    for line in head.splitlines()[:ROWS]:
                        try:
                            rows.append(json.loads(line))
                        except ValueError:
                            continue
            else:
                dialect = "excel-tab" if suffix == ".tsv" else "excel"
                rows = []
                for n, row in enumerate(csv.DictReader(f, dialect=dialect)):
                    if n >= ROWS:
                        break
                    rows.append(row)
    except (OSError, csv.Error, UnicodeError):
        return out
    for row in rows[:ROWS]:
        if isinstance(row, dict):
            host = extract_host_from_record(row)
            if host and host not in out:
                out.append(host)
    return out


_ROW_SUFFIXES = (".csv", ".tsv", ".json", ".jsonl", ".ndjson")


def _row_files(root: Path) -> list[Path]:
    try:
        return sorted(
            f
            for f in Path(root).rglob("*")
            if f.is_file() and f.suffix.lower() in _ROW_SUFFIXES and not f.name.endswith(".index")
        )
    except OSError:
        return []


# --------------------------------------------------------------------------
# Units


def host_folder_unit(host, case_dir: Path | None) -> Unit:
    """A discovered host folder (or mounted volume)."""
    locator = getattr(host, "unit_locator", "") or _rel(case_dir, host.volume_root)
    unit = Unit(locator=locator, source="host folder")
    origin = getattr(host, "name_origin", "") or FOLDER
    unit.add(
        host.hostname, "the ingest's host name" if origin != FOLDER else "folder name", origin
    )
    names, attrs = registry_names(Path(host.volume_root))
    for raw, where in names:
        unit.add(raw, where, ARTIFACT)
    unit.attrs.update(attrs)
    if getattr(host, "evtx_dir", None):
        for raw, where in evtx_computers(host.evtx_dir):
            unit.add(raw, where, ARTIFACT)
    for f in _row_files(Path(host.volume_root)):
        for raw in row_names(f):
            unit.add(raw, f"{_rel(case_dir, f)} host column", file_origin(case_dir, f))
    return unit


def velociraptor_unit(collection: Path, archive: Path, case_dir: Path | None) -> Unit | None:
    """A Velociraptor collection's client, from its collection_context.json."""
    try:
        ctx = json.loads((Path(collection) / "collection_context.json").read_text())
    except (OSError, ValueError):
        return None
    client = ctx.get("client_info") if isinstance(ctx, dict) else None
    if not isinstance(client, dict):
        return None
    unit = Unit(locator=_rel(case_dir, archive), source="velociraptor collection")
    for key in ("fqdn", "hostname"):
        unit.add(client.get(key), f"collection client {key}", ARTIFACT)
    if client.get("client_id"):
        unit.attrs["client_id"] = str(client["client_id"])
    return unit


def image_candidates(image: Path, leaves: list[dict], case_dir: Path | None) -> list[Unit]:
    """A candidate unit for every volume of a disk image, from the volume
    list read without mounting. Names come once a reader gets to them."""
    units = []
    for leaf in leaves:
        sel = leaf.get("selector") or {}
        # the label an image run of this volume uses, so both name one unit
        label = ":".join(v for v in (sel.get("partitions"), sel.get("volumes")) if v) or "fs"
        unit = Unit(
            locator=host_identity.unit_locator(image, case_dir, member=label),
            source="disk image volume",
        )
        unit.attrs.update({"volume": label, **{k: leaf[k] for k in ("fs", "os") if leaf.get(k)}})
        if not leaf.get("os"):
            unit.note = "no operating system found on this volume"
        units.append(unit)
    return units


def noted_volume_unit(image: Path, offset, note: str, case_dir: Path | None) -> Unit:
    """A volume of a disk image that no reader covered (locked, unmountable,
    or with no operating system): a candidate unit, unnamed, with why."""
    return Unit(
        locator=host_identity.unit_locator(image, case_dir, offset=int(offset)),
        source="disk image volume",
        note=note,
    )


def memory_unit(
    image: Path, given: Path, member: str, hostname: str, case_dir: Path | None
) -> Unit:
    """A memory image (or one image inside an archive)."""
    unit = Unit(
        locator=host_identity.unit_locator(given, case_dir, member=member),
        source="memory image",
    )
    unit.add(hostname, "hostname argument", ARGUMENT)
    unit.add(Path(image).stem, "memory image file name", FILE_NAME)
    if member:
        unit.add(Path(given).stem, "archive file name", FILE_NAME)
    return unit


def filename_host(path: Path) -> str:
    """The host a file's name gives, as written: the stem's last `-` segment
    (Tool-HOST.csv, hayabusa-case-HOST.csv); "" when there is none. The
    auto-hosts detector reads the same segment, lower-cased."""
    parts = Path(path).stem.rsplit("-", 1)
    return parts[1] if len(parts) == 2 and len(parts[1]) >= 2 else ""


def files_unit(path: Path, hostname: str, files: list[Path], case_dir: Path | None) -> Unit:
    """Log files given to one ingest (a file, or a folder of them)."""
    unit = Unit(locator=_rel(case_dir, path), source="log files")
    unit.add(hostname, "hostname argument", ARGUMENT)
    for f in files:
        named = filename_host(f)
        if named:
            unit.add(named, f"{f.name} file name", FILE_NAME)
        if f.suffix.lower() in _ROW_SUFFIXES:
            for raw in row_names(f):
                unit.add(raw, f"{_rel(case_dir, f)} host column", file_origin(case_dir, f))
    return unit


# --------------------------------------------------------------------------
# Recording


def record(case_dir: Path, units: list[Unit]) -> list[dict]:
    """Append each unit and its names to the case's observation log, in one
    locked append, and return the scan summary (one entry per unit: two
    readers of one unit, like a collection and its host folder, are merged)."""
    merged: dict[str, Unit] = {}
    for unit in units:
        into = merged.setdefault(unit.locator, Unit(unit.locator, unit.source))
        for name in unit.names:
            into.add(name.raw, name.evidence, name.origin)
        into.attrs.update(unit.attrs)
        into.note = into.note or unit.note
    units = list(merged.values())
    records: list[dict] = []
    for unit in units:
        rec = {"kind": "unit", "unit": unit.key, "locator": unit.locator, "source": unit.source}
        rec.update({k: v for k, v in unit.attrs.items() if isinstance(v, (str, int))})
        if unit.note:
            rec["note"] = unit.note
        records.append(rec)
        for n in unit.names:
            records.append(
                {"kind": "name", "unit": unit.key, "raw": n.raw, "evidence": n.evidence,
                 "origin": n.origin}
            )  # fmt: skip
    if records:
        host_identity.append_observations(case_dir, records)
    return [u.summary() for u in units]

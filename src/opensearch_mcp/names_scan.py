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
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from sift_common import host_identity

logger = logging.getLogger(__name__)

ROWS = 50  # first rows of each CSV/JSON file read for host columns
SAMPLE_BYTES = 1 << 20  # of a JSON file read for them
ROW_FILES = 200  # CSV/JSON files sampled under one host folder or volume
EVTX_SAMPLE = 50  # records read from each event log for its Computer

ARTIFACT = host_identity.ARTIFACT
FOLDER = host_identity.FOLDER
ARGUMENT = "argument"
FILE_NAME = "file-name"
AI_WRITTEN = "ai"  # a file the AI can write: never confirms a machine

# Case folders the AI's tools write into (what the case-data guard leaves
# writable). A file directly in the case folder is the AI's too: evidence goes
# in evidence/, which only takes new files, and those count by registration.
_AI_WRITABLE = ("extractions", "work", "reports", ".outputs", "DELETE")


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


def file_origin(case_dir: Path | None, path) -> str:
    """ARTIFACT for evidence the examiner put in the case; AI_WRITTEN for a
    file registered as evidence through the AI's tools (`registered_via:
    mcp`, wherever it is), or one in a folder the AI's tools write into (by
    its own path or the one a link leads to)."""
    if case_dir is None or path is None:
        return ARTIFACT
    root = Path(case_dir)
    try:
        resolved = Path(path).resolve()
        case_root = root.resolve()
    except (OSError, RuntimeError):  # a looping link: nothing to read
        return AI_WRITTEN
    if str(resolved) in _registered_by_ai(root):
        return AI_WRITTEN
    given = Path(os.path.normpath(Path(path).absolute()))
    for candidate, base in (
        (resolved, case_root),
        (given, Path(os.path.normpath(root.absolute()))),
    ):
        try:
            rel = candidate.relative_to(base)
        except ValueError:
            continue
        at_root = len(rel.parts) == 1 and candidate.is_file()  # directly in the case folder
        if at_root or (rel.parts and rel.parts[0] in _AI_WRITABLE):
            return AI_WRITTEN
    return ARTIFACT


_registry_cache: dict[str, tuple[tuple, frozenset]] = {}


def _registered_by_ai(case_dir: Path) -> frozenset:
    """Evidence files the AI registered (through MCP), by resolved path; read
    again only when the registry changes."""
    reg = case_dir / "evidence.json"
    try:
        st = reg.stat()
        stamp = (st.st_ino, st.st_mtime_ns, st.st_size)
    except OSError:
        return frozenset()
    hit = _registry_cache.get(str(reg))
    if hit is not None and hit[0] == stamp:
        return hit[1]
    try:
        registry = json.loads(reg.read_text())
    except (OSError, ValueError):
        return frozenset()
    files = registry.get("files") if isinstance(registry, dict) else None
    found = set()
    for f in files or []:
        if isinstance(f, dict) and f.get("registered_via") == "mcp" and f.get("path"):
            try:
                found.add(str((case_dir / str(f["path"])).resolve()))  # as file_origin compares
            except (OSError, RuntimeError):
                continue
    _registry_cache[str(reg)] = (stamp, frozenset(found))
    return frozenset(found)


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


class NotSampled(Exception):
    """A file whose host columns couldn't be read, and why."""


def row_names(path: Path) -> list[str]:
    """Host-column values from the first rows of a CSV/TSV or JSON file.
    Raises NotSampled for a file it couldn't read: never a silent skip."""
    from opensearch_mcp.hostname import extract_host_from_record
    from opensearch_mcp.parse_csv import _detect_encoding

    out: list[str] = []
    suffix = path.suffix.lower()
    try:
        # decoded as the ingest decodes it: PowerShell's Export-Csv (Kansa)
        # writes UTF-16LE with a BOM. JSON stays UTF-8, as its parser reads
        # it: a name from a file the ingest then rejects would hold the gate
        json_file = suffix in (".json", ".jsonl", ".ndjson")
        encoding = "utf-8-sig" if json_file else _detect_encoding(path)
        with open(path, encoding=encoding, errors="replace", newline="") as f:
            if suffix in (".json", ".jsonl", ".ndjson"):
                head = f.read(SAMPLE_BYTES)
                rows: list = []
                stripped = head.lstrip()
                if stripped.startswith("["):
                    try:
                        rows = json.loads(stripped)
                    except RecursionError:
                        raise NotSampled("nested too deeply to read") from None
                    except ValueError:
                        if f.read(1):  # the array goes on past what's sampled
                            raise NotSampled("file too large") from None
                        raise NotSampled("not valid JSON") from None
                else:
                    for line in head.splitlines()[:ROWS]:
                        try:
                            rows.append(json.loads(line))
                        except (ValueError, RecursionError):
                            continue
            else:
                dialect = "excel-tab" if suffix == ".tsv" else "excel"
                rows = []
                for n, row in enumerate(csv.DictReader(f, dialect=dialect)):
                    if n >= ROWS:
                        break
                    rows.append(row)
    except (OSError, csv.Error, UnicodeError) as e:
        raise NotSampled(f"unreadable ({e})") from None
    for row in rows[:ROWS]:
        if isinstance(row, dict):
            host = extract_host_from_record(row)
            if host and host not in out:
                out.append(host)
    return out


_ROW_SUFFIXES = (".csv", ".tsv", ".json", ".jsonl", ".ndjson")


def _row_files(root: Path) -> tuple[list[Path], bool]:
    """CSV/JSON files under `root` to sample, shallowest first, at most
    ROW_FILES of them (a mounted volume is never walked whole), and whether
    more were left out."""
    found: list[Path] = []
    level = [Path(root)]
    while level:
        deeper = []
        for d in sorted(level):
            try:
                entries = sorted(d.iterdir())
            except OSError:
                continue
            for e in entries:
                if e.is_symlink():
                    continue
                if e.is_dir():
                    deeper.append(e)
                elif (
                    e.suffix.lower() in _ROW_SUFFIXES
                    and not e.name.endswith(".index")
                    and e.is_file()  # never a pipe: reading one would block the scan
                ):
                    if len(found) == ROW_FILES:
                        return found, True
                    found.append(e)
        level = deeper
    return found, False


# --------------------------------------------------------------------------
# Units


def host_folder_unit(host, case_dir: Path | None, input_path=None) -> Unit:
    """A discovered host folder (or mounted volume). Its names are the AI's
    when the run's input (`input_path`, else the folder) is."""
    locator = getattr(host, "unit_locator", "") or _rel(case_dir, host.volume_root)
    unit = Unit(locator=locator, source="host folder")
    origin = getattr(host, "name_origin", "") or FOLDER
    unit.add(
        host.hostname, "the ingest's host name" if origin != FOLDER else "folder name", origin
    )
    found = file_origin(case_dir, input_path if input_path is not None else host.volume_root)
    names, attrs = registry_names(Path(host.volume_root))
    for raw, where in names:
        unit.add(raw, where, found)
    unit.attrs.update(attrs)
    if getattr(host, "evtx_dir", None):
        for raw, where in evtx_computers(host.evtx_dir):
            unit.add(raw, where, found)
    files, more = _row_files(Path(host.volume_root))
    _add_row_names(unit, files, case_dir, ai=found == AI_WRITTEN)
    if more:
        unit.attrs["names_sampled"] = f"host columns read from the first {ROW_FILES} files only"
    return unit


def _add_row_names(unit: Unit, files, case_dir: Path | None, ai: bool = False) -> None:
    """Each file's host columns; one that can't be read is listed on the unit,
    as one string the host log keeps ("<file>: <why>; …")."""
    unread = []
    for f in files:
        try:
            raws = row_names(f)
        except NotSampled as e:
            unread.append(f"{_rel(case_dir, f)}: {e}")
            continue
        origin = AI_WRITTEN if ai else file_origin(case_dir, f)
        for raw in raws:
            unit.add(raw, f"{_rel(case_dir, f)} host column", origin)
    if unread:
        unit.attrs["names_not_sampled"] = "; ".join(unread)


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
        unit.add(client.get(key), f"collection client {key}", file_origin(case_dir, archive))
    if client.get("client_id"):
        unit.attrs["client_id"] = str(client["client_id"])
    return unit


def volume_locator(
    image: Path, case_dir: Path | None, offset, label: str = "", prefix: str = ""
) -> str:
    """A disk image's volume as a unit: the image (or the archive it came in,
    with `prefix` its name there), the volume's byte offset, and a sub-volume's
    own name when several share it (APFS). The dry run and the ingest both
    use this, so one volume is one unit in both."""
    # a volume inside a partition (APFS, LVM) has its own name; so does an LVM
    # volume with no partition table, which shares offset 0 with its siblings
    if ":" in label:
        sub = label.split(":", 1)[1]
    else:
        sub = "" if label in ("", "fs") or re.fullmatch(r"p\d+", label) else label
    member = "/".join(x for x in (prefix, sub) if x)
    return host_identity.unit_locator(image, case_dir, member=member, offset=int(offset or 0))


def image_candidates(image: Path, leaves: list[dict], case_dir: Path | None) -> list[Unit]:
    """A candidate unit for every volume of a disk image, from the volume
    list read without mounting. Names come once a reader gets to them."""
    units = []
    for leaf in leaves:
        if leaf.get("type") == "VSHADOW":
            continue  # a volume's shadow copy: the volume itself is listed
        sel = leaf.get("selector") or {}
        # the label an image run of this volume uses, so both name one unit
        label = ":".join(v for v in (sel.get("partitions"), sel.get("volumes")) if v) or "fs"
        unit = Unit(
            locator=volume_locator(image, case_dir, leaf.get("offset", 0), label),
            source="disk image volume",
        )
        unit.attrs.update({"volume": label, **{k: leaf[k] for k in ("fs", "os") if leaf.get(k)}})
        if not leaf.get("os"):
            unit.note = "no operating system found on this volume"
        units.append(unit)
    return units


def noted_volume_unit(
    image: Path, offset, note: str, case_dir: Path | None, prefix: str = ""
) -> Unit:
    """A volume of a disk image that no reader covered (locked, unmountable,
    or with no operating system): a candidate unit, unnamed, with why. An
    image from an archive is named by the archive (`prefix`: its name in it)."""
    return Unit(
        locator=volume_locator(image, case_dir, offset, prefix=prefix),
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


_KANSA_RUN = re.compile(r"Output_\d{14}")
# A DNS name (ASCII labels, the last all letters) or an IPv4 address.
_DOTTED_HOST = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")


def _dotted_host(name: str) -> bool:
    """Whether a name is written like a DNS name or an IPv4 address."""
    if _IPV4.fullmatch(name):
        return all(int(octet) <= 255 for octet in name.split("."))
    return bool(_DOTTED_HOST.fullmatch(name))


def _host_forms(name: str) -> set[str]:
    """A name and its first DNS label, lower-cased, for comparing hosts."""
    name = name.strip().lower()
    return {name, name.split(".")[0]} - {""}


def filename_host(path: Path, known=()) -> str:
    """The host a file's name gives, as written; "" when there is none.

    A stem `<left>-<last>` (split at its last `-`) names one of its parts:
    `<last>` when it is a host this file is known by (its folder's name, or
    one of `known`: a hostname argument, the hosts a run splits by), as in
    Tool-HOST.csv; else `<left>` when that is one, as in Kansa's
    <host>-<Module>.csv; else `<left>` when `<last>` is all digits (a date,
    as in HOST-20261016.evtx: a computer name is never all digits); else
    `<last>` (Tool-HOST.csv, hayabusa-case-HOST.csv). Names compare
    case-insensitively, a part and a known host also by their first DNS
    label (the folder's name whole: it may be a file's). One layout comes
    first: Kansa's <Module>/<host>-<Module>.csv, where `<last>` is the
    folder's name and `<left>` the host. It is told from a host folder of
    Tool-HOST.csv files (`rd01/EvtxECmd-rd01.csv`) by the folder above
    (Output_<14 digits>) or by a `<left>` written as a DNS name (ASCII
    labels, the last all letters) or an IPv4 address. A dotted tool or case
    part (hayabusa-2.16, EvtxECmd.v1, INC2023.001) is neither.
    ingest_cli's split of a folder by host and server's detector read file
    names with this rule too."""
    path = Path(path)
    parts = path.stem.rsplit("-", 1)
    if len(parts) != 2 or len(parts[1]) < 2:
        return ""
    left, last = parts
    folder = path.parent.name.lower()
    if (
        left
        and last.lower() == folder
        and (_KANSA_RUN.fullmatch(path.parent.parent.name) or _dotted_host(left))
    ):
        return left
    hosts = {folder}.union(*(_host_forms(str(h)) for h in known if h))
    if _host_forms(last) & hosts:
        return last
    if left and (_host_forms(left) & hosts or last.isdigit()):
        return left
    return last


def files_unit(path: Path, hostname: str, files: list[Path], case_dir: Path | None) -> Unit:
    """Log files given to one ingest (a file, or a folder of them)."""
    unit = Unit(locator=_rel(case_dir, path), source="log files")
    unit.add(hostname, "hostname argument", ARGUMENT)
    for f in files:
        named = filename_host(f, (hostname,))
        if named:
            unit.add(named, f"{f.name} file name", FILE_NAME)
    _add_row_names(unit, [f for f in files if f.suffix.lower() in _ROW_SUFFIXES], case_dir)
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
        from sift_common import host_proposal

        state = host_identity.load(case_dir)
        known = {host_identity.spelling(raw) for _, raw in state.names}
        new = []  # each name once, the first time any unit gives it
        for r in records:
            spelled = host_identity.spelling(r.get("raw"))
            if r["kind"] == "name" and spelled not in known:
                known.add(spelled)
                new.append((r["unit"], r["raw"]))
        records += host_proposal.near_hints(state, new)
        host_identity.append_observations(case_dir, records)
        # what the examiner's list names confirms now: this scan's units only,
        # never while a host operation is unfinished (the gate then refuses
        # the run, and a later scan applies the list)
        try:
            host_proposal.apply_host_list(case_dir, [u.key for u in units])
        except host_identity.HostOpRunning:
            pass
    return [u.summary() for u in units]

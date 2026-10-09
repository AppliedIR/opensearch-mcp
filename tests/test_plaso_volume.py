"""Plaso over a whole Linux or macOS volume, and its narrow Windows set.

A Linux or macOS host is one Plaso run over its volume: on a disk image as
the examiner with root's read capability only (`sudo -n setpriv`), so files
only root can read are parsed and nothing written is root's; on a folder as
the examiner. Windows hosts get three parsers over Users and Windows/inf.
Every run works in its own folder, gets the host's own time zone when Plaso
can use it, and is killed with all its workers on timeout. Its documents are
keyed on paths relative to the volume, so re-ingesting a volume mounted
somewhere else adds nothing. Plaso is replaced by stubs, except in one row
that runs the installed Plaso when there is one. Data is synthetic.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import sys
import time
from pathlib import Path

import pytest

from opensearch_mcp import parse_plaso
from opensearch_mcp.discover import DiscoveredHost, make_host
from opensearch_mcp.parse_plaso import (
    WINDOWS_PARSERS,
    _ingest_jsonl,
    plaso_runs,
    plaso_status,
    run_plaso_volume,
)

# The runner's argv


@pytest.fixture
def calls(monkeypatch):
    """Record every command; log2timeline "succeeds", psort and pinfo write
    their outputs."""
    seen: list[tuple[list[str], dict]] = []

    class Proc:
        pid = 999999

        def wait(self, timeout=None):
            return 0

    def popen(cmd, **kw):
        seen.append((cmd, kw))
        return Proc()

    def run(cmd, **kw):
        seen.append((cmd, kw))
        out = Path(cmd[cmd.index("-w") + 1])
        out.write_text("{}" if cmd[0] == "pinfo.py" else "")

    monkeypatch.setattr(parse_plaso.subprocess, "Popen", popen)
    monkeypatch.setattr(parse_plaso.subprocess, "run", run)
    return seen


def _l2t(seen):
    ((cmd, kw),) = [(c, k) for c, k in seen if "log2timeline.py" in c]
    return cmd, kw


def test_an_image_volume_is_read_with_roots_read_capability_only(calls, tmp_path):
    run_plaso_volume("linux", tmp_path / "vol1", tmp_path / "wd", read_as_root=True)
    cmd, kw = _l2t(calls)
    prefix = ["sudo", "-n", "setpriv", "--reuid", str(os.getuid()), "--regid"]
    prefix += [str(os.getgid()), "--init-groups", "--inh-caps", "+dac_read_search"]
    prefix += ["--ambient-caps", "+dac_read_search", "log2timeline.py"]
    assert cmd[: len(prefix)] == prefix
    wd = tmp_path / "wd"
    for flag, value in (
        ("--parsers", "linux"),
        ("--logfile", str(wd / "l2t.log.gz")),
        ("--temporary_directory", str(wd / "tmp")),
        ("--storage_file", str(wd / "out.plaso")),
    ):
        assert cmd[cmd.index(flag) + 1] == value
    assert (wd / "tmp").is_dir()  # Plaso refuses a missing one
    assert cmd[-1] == str(tmp_path / "vol1") and "--timezone" not in cmd
    assert kw["cwd"] == wd and kw["start_new_session"] is True
    for cmd, kw in calls[1:]:  # psort and pinfo: the examiner, in the work folder
        assert cmd[0] in ("psort.py", "pinfo.py") and "sudo" not in cmd
        assert kw["cwd"] == wd
    pinfo = calls[2][0]
    assert pinfo[pinfo.index("--sections") + 1] == "events,warnings"


def test_a_folder_is_read_as_the_examiner(calls, tmp_path):
    run_plaso_volume("linux", tmp_path / "srv01", tmp_path / "wd", read_as_root=False)
    cmd, _ = _l2t(calls)
    assert cmd[0] == "log2timeline.py" and "sudo" not in cmd and "setpriv" not in cmd


def test_a_zone_is_passed_when_given(calls, tmp_path):
    run_plaso_volume("linux", tmp_path / "v", tmp_path / "wd", timezone_name="America/New_York")
    cmd, _ = _l2t(calls)
    assert cmd[cmd.index("--timezone") + 1] == "America/New_York"


def _host(tmp_path, os_name, from_image=False):
    h = DiscoveredHost(hostname="h", volume_root=tmp_path)
    h.os, h.from_image = os_name, from_image
    return h


def test_the_runs_for_each_kind_of_host(tmp_path):
    (tmp_path / "Users").mkdir()
    (tmp_path / "Windows/inf").mkdir(parents=True)
    assert plaso_runs(_host(tmp_path, "windows")) == (
        [(WINDOWS_PARSERS, tmp_path / "Users"), (WINDOWS_PARSERS, tmp_path / "Windows/inf")],
        "",
    )
    assert WINDOWS_PARSERS == "sqlite/chrome_27_history,esedb/msie_webcache,text/setupapi"
    # A mounted image keeps filestat; its times are the file system's: no note.
    assert plaso_runs(_host(tmp_path, "linux", True)) == ([("linux", tmp_path)], "")
    assert plaso_runs(_host(tmp_path, "macos", True)) == (
        [("macos,unified_logging", tmp_path)],
        "",
    )
    assert plaso_runs(_host(tmp_path, "macos"))[0] == [("macos,unified_logging", tmp_path)]
    runs, note = plaso_runs(_host(tmp_path, "linux"))
    assert runs == [("linux", tmp_path)]
    assert note == "file times may reflect the copy, not the original system"


def test_a_windows_host_without_users_or_inf_has_no_plaso_artifact(tmp_path):
    (tmp_path / "Windows/System32/config").mkdir(parents=True)
    (tmp_path / "Windows/System32/config/SYSTEM").write_bytes(b"x")
    assert "plaso" not in [a for a, _ in make_host("w", tmp_path).artifacts]
    (tmp_path / "Windows/inf").mkdir()
    assert ("plaso", tmp_path) in make_host("w", tmp_path).artifacts


# The process tree on timeout

STUB = """#!{python}
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pids = []
for _ in range(3):
    pid = os.fork()
    if pid == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(600)
        os._exit(0)
    pids.append(pid)
open(os.environ["STUB_PIDS"], "w").write(" ".join(map(str, [os.getpid()] + pids)))
if os.environ.get("STUB_EXIT"):
    sys.exit(int(os.environ["STUB_EXIT"]))  # the workers outlive their parent
time.sleep(600)
"""


@pytest.fixture
def stub_plaso(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    l2t = bin_dir / "log2timeline.py"
    l2t.write_text(STUB.format(python=sys.executable))
    l2t.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("STUB_PIDS", str(tmp_path / "pids"))
    return tmp_path / "pids"


def _alive(pids_file: Path) -> list[int]:
    deadline = time.time() + 5
    while not pids_file.exists() and time.time() < deadline:
        time.sleep(0.05)
    pids = [int(p) for p in pids_file.read_text().split()]
    time.sleep(0.5)
    alive = []
    for pid in pids:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
        except OSError:
            continue
        if state != "Z":
            alive.append(pid)
    for pid in alive:  # don't leave them behind if the row fails
        os.kill(pid, signal.SIGKILL)
    return alive


def test_on_timeout_every_worker_is_killed(stub_plaso, tmp_path):
    with pytest.raises(RuntimeError, match="killed after 2 s; nothing from this run"):
        run_plaso_volume("linux", tmp_path, tmp_path / "wd", timeout=2)
    assert _alive(stub_plaso) == []


def test_workers_left_by_a_failed_run_are_killed(stub_plaso, tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_EXIT", "1")
    with pytest.raises(RuntimeError, match="log2timeline exited 1; nothing from this run"):
        run_plaso_volume("linux", tmp_path, tmp_path / "wd", timeout=30)
    assert _alive(stub_plaso) == []


# Documents


def _events(root: str) -> str:
    """Plaso json_line records for one volume, with the paths and the
    _event_values_hash a run over `root` gives."""
    rows = []
    for i, (rel, ts) in enumerate(
        [("var/log/auth.log", 1791280801000000), ("var/log/syslog", 1791280798000001)]
    ):
        rows.append(
            {
                "__container_type__": "event",
                "__type__": "AttributeContainer",
                "_event_values_hash": f"{hash(root) & 0xFFFF:x}{i}",
                "data_type": "syslog:line",
                "display_name": f"OS:{root}/{rel}",
                "filename": f"{root}/{rel}",
                "message": f"line {i}",
                "parser": "text/syslog_traditional",
                "pathspec": {"location": f"{root}/{rel}", "type_indicator": "OS"},
                "timestamp": ts,
                "timestamp_desc": "Content Modification Time",
            }
        )
    return "".join(json.dumps(r) + "\n" for r in rows)


@pytest.fixture
def sent(monkeypatch):
    out: list[dict] = []

    def flush(client, actions):
        out.extend(actions)
        return len(actions), 0

    monkeypatch.setattr(parse_plaso, "flush_bulk", flush)
    return out


def _ingest(tmp_path, root: Path, sent) -> list[dict]:
    jsonl = tmp_path / f"{root.name}.jsonl"
    jsonl.write_text(_events(str(root.resolve())))  # Plaso reports the resolved path
    start = len(sent)
    _ingest_jsonl(jsonl, None, "case-c1-plaso-h", "h", volume_root=root)
    return sent[start:]


def test_documents_are_keyed_on_paths_relative_to_the_volume(tmp_path, sent):
    a = tmp_path / "mnt-a" / "vol1"
    b = tmp_path / "mnt-b" / "vol1"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    first, second = _ingest(tmp_path, a, sent), _ingest(tmp_path, b, sent)
    assert [d["_id"] for d in first] == [d["_id"] for d in second]
    for d in first + second:
        src = d["_source"]
        assert src["vhir.source_file"] in ("var/log/auth.log", "var/log/syslog")
        assert src["filename"] == src["vhir.source_file"]
        assert src["display_name"] == f"OS:{src['filename']}"
    assert first[0]["_source"]["@timestamp"] == "2026-10-06T10:00:01+00:00"
    assert first[1]["_source"]["@timestamp"] == "2026-10-06T09:59:58.000001+00:00"


def test_a_time_out_of_range_leaves_at_timestamp_unset(tmp_path, sent):
    jsonl = tmp_path / "far.jsonl"
    record = json.loads(_events(str(tmp_path.resolve())).splitlines()[0])
    jsonl.write_text(json.dumps({**record, "timestamp": 10**18}) + "\n")
    _ingest_jsonl(jsonl, None, "case-c1-plaso-h", "h", volume_root=tmp_path)
    (doc,) = sent
    assert "@timestamp" not in doc["_source"] and doc["_source"]["timestamp"] == 10**18


def test_a_volume_reached_through_a_link_is_stripped_at_its_real_path(tmp_path, sent):
    real = tmp_path / "mnt-a" / "vol1"
    real.mkdir(parents=True)
    link = tmp_path / "link-to-vol1"
    link.symlink_to(real)
    (doc, _) = _ingest(tmp_path, link, sent)
    assert doc["_source"]["vhir.source_file"] == "var/log/auth.log"


def test_the_prefetch_and_srum_path_is_unchanged(tmp_path, sent):
    jsonl = tmp_path / "pf.jsonl"
    jsonl.write_text(_events("/tmp/vhir-plaso-prefetch-x"))
    _ingest_jsonl(jsonl, None, "case-c1-prefetch-h", "h")
    from opensearch_mcp.parse_csv import _doc_id

    for d in sent:
        assert d["_source"]["vhir.source_file"].startswith("/tmp/vhir-plaso-prefetch-x/")
        assert "@timestamp" not in d["_source"]
        record = {k: v for k, v in d["_source"].items() if not k.startswith("vhir.")}
        assert d["_id"] == _doc_id(
            "case-c1-prefetch-h", record, volatile_keys=parse_plaso._PLASO_VOLATILE_KEYS
        )


# The template


def test_the_plaso_template_maps_host_and_time_fields():
    from opensearch_mcp import mappings

    (filename,) = [f for n, f in mappings._TEMPLATES_REGISTRY if n == "vhir-plaso"]
    body = mappings._load_json(mappings._MAPPINGS_DIR / filename)
    assert body["index_patterns"] == ["case-*-plaso-*"]
    assert body["template"]["settings"]["index.number_of_replicas"] == 0
    props = body["template"]["mappings"]["properties"]
    assert props["host.id"] == {"type": "keyword"} and props["host.name"] == {"type": "keyword"}
    assert props["timestamp"] == {"type": "long"} and props["@timestamp"] == {"type": "date"}


def test_every_template_has_its_own_priority():
    """Two templates matching one index at the same priority are refused by
    the cluster, and the installer only logs it (case-a-plaso-prefetch-b
    matches both the plaso and the prefetch pattern)."""
    from opensearch_mcp import mappings

    files = [f for _, f in mappings._TEMPLATES_REGISTRY] + [mappings._EVTX_TEMPLATE_FILE.name]
    priorities = [mappings._load_json(mappings._MAPPINGS_DIR / f)["priority"] for f in files]
    assert len(priorities) == len(set(priorities))


# The status entry

PINFO = {
    "storage_counters": {
        "parsers": {"setupapi": 2374, "total": 6134, "msie_webcache": 648},
        "warnings_by_path_spec": {
            "type: OS, location: {root}/Windows/inf/setupapi.offline.log\n": 129,
            "type: OS, location: {root}/Users/a/AppData/Local/Microsoft/Windows/"
            "WebCache/WebCacheV01.dat\n": 2,
        },
    }
}


def _pinfo(root: Path) -> dict:
    return json.loads(json.dumps(PINFO).replace("{root}", str(root.resolve())))


def test_the_status_lists_unread_files_relative_to_the_volume(tmp_path):
    not_read, note = plaso_status(
        _pinfo(tmp_path), tmp_path, "windows", "America/New_York", "registry"
    )
    assert not_read == [
        "Users/a/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat (2 extraction warnings)",
        "Windows/inf/setupapi.offline.log (129 extraction warnings)",
    ]
    assert note == (
        "events by parser: msie_webcache 648, setupapi 2374; time zone America/New_York (registry)"
    )


def test_unread_files_are_relative_to_a_volume_reached_through_a_link(tmp_path):
    real = tmp_path / "mnt" / "vol1"
    real.mkdir(parents=True)
    link = tmp_path / "link-to-vol1"
    link.symlink_to(real)
    not_read, _ = plaso_status(_pinfo(real), link, "windows", None, "")
    assert not_read[1] == "Windows/inf/setupapi.offline.log (129 extraction warnings)"


def test_an_unknown_zone_and_the_linux_gaps_are_said(tmp_path):
    _, note = plaso_status({}, tmp_path, "linux", None, "")
    assert "time zone unknown: local-time events" in note
    assert "dpkg.log" in note and "Plaso fallback: known gaps" in note


# Routing


def test_a_failed_run_fails_the_artifact_and_the_other_run_is_kept(tmp_path, monkeypatch):
    from opensearch_mcp import ingest
    from opensearch_mcp.results import HostResult

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    vr = tmp_path / "C"
    (vr / "Users").mkdir(parents=True)
    (vr / "Windows/inf").mkdir(parents=True)
    host = _host(vr, "windows")
    host.system_timezone, host.timezone_source = "UTC+12", "registry"
    passed_zones = []

    def run(parsers, source, workdir, read_as_root, zone):
        passed_zones.append((read_as_root, zone))
        assert workdir.parent == tmp_path / "home/.vhir/cases/c1/tmp"
        if source.name == "inf":
            raise RuntimeError("log2timeline exited 1; nothing from this run was indexed")
        jsonl = workdir / "out.jsonl"
        jsonl.write_text(_events(str(source.resolve())))
        return jsonl, _pinfo(vr)

    monkeypatch.setattr(parse_plaso, "run_plaso_volume", run)
    monkeypatch.setattr(parse_plaso, "can_sudo", lambda: pytest.fail("Windows doesn't probe"))
    monkeypatch.setattr(parse_plaso, "flush_bulk", lambda c, a: (len(a), 0))
    monkeypatch.setattr(ingest, "_safe_count", lambda c, i, unit="": 0)
    status = [{"hostname": "h", "artifacts": [{"name": "plaso", "status": "pending"}]}]

    class Audit:
        def _next_audit_id(self):
            return "aid-1"

        def log(self, **kw):
            return kw.get("audit_id")  # written

    result = HostResult(hostname="h")
    ingest._ingest_plaso_volume(
        None, Audit(), "c1", host, 0, result, status, lambda *a, **k: None, lambda: None
    )
    (entry,) = status[0]["artifacts"]
    assert entry["status"] == "failed" and entry["indexed"] == 2
    assert "Windows/inf" in entry["error"] and "exited 1" in entry["error"]
    # UTC+12 is a TZ string Plaso rejects: no flag, and the status says so.
    assert passed_zones == [(False, None), (False, None)]
    assert "time zone unknown" in entry["note"]
    assert not list((tmp_path / "home/.vhir/cases/c1/tmp").iterdir())  # work folders removed


class _Audit:
    def _next_audit_id(self):
        return "aid-1"

    def log(self, **kw):
        return kw.get("audit_id")  # written


@pytest.mark.parametrize(
    "sudo, as_root, note",
    [(True, True, False), (False, False, True)],
    ids=["with sudo: root's read capability", "without: the examiner, said"],
)
def test_a_linux_folder_is_read_with_roots_read_capability_when_sudo_works(
    tmp_path, monkeypatch, sudo, as_root, note
):
    from opensearch_mcp import ingest
    from opensearch_mcp.results import HostResult

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    host = _host(tmp_path / "srv01", "linux")
    host.volume_root.mkdir()
    seen = []

    def run(parsers, source, workdir, read_as_root, zone):
        seen.append((parsers, read_as_root))
        jsonl = workdir / "out.jsonl"
        jsonl.write_text("")
        return jsonl, {}

    monkeypatch.setattr(parse_plaso, "run_plaso_volume", run)
    monkeypatch.setattr(parse_plaso, "can_sudo", lambda: sudo)
    monkeypatch.setattr(ingest, "_safe_count", lambda c, i, unit="": 0)
    status = [{"hostname": "h", "artifacts": [{"name": "plaso", "status": "pending"}]}]
    ingest._ingest_plaso_volume(
        None,
        _Audit(),
        "c1",
        host,
        0,
        HostResult(hostname="h"),
        status,
        lambda *a, **k: None,
        lambda: None,
    )
    assert seen == [("linux", as_root)]
    (entry,) = status[0]["artifacts"]
    assert ("read as the examiner" in entry["note"]) is note
    assert "file times may reflect the copy" in entry["note"]


# The installed Plaso, when there is one

TZ_TREE = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
    "etc/os-release": "ID=ubuntu\n",
    "var/log/auth.log": "Oct  6 10:00:01 lnx sshd[2101]: Accepted password for u from 10.0.0.5\n",
}


@pytest.mark.skipif(not shutil.which("log2timeline.py"), reason="Plaso not installed")
def test_a_new_york_hosts_syslog_lands_at_its_true_utc_time(tmp_path, sent):
    vr = tmp_path / "srv01"
    for rel, text in TZ_TREE.items():
        (vr / rel).parent.mkdir(parents=True, exist_ok=True)
        (vr / rel).write_text(text)
    os.symlink("../usr/share/zoneinfo/America/New_York", vr / "etc/localtime")
    os.utime(vr / "var/log/auth.log", (1791331200, 1791331200))  # the year: 2026
    host = make_host("srv01", vr)
    assert host.system_timezone == "America/New_York"
    jsonl, _ = run_plaso_volume(
        "text/syslog_traditional", vr, tmp_path / "wd", timezone_name=host.system_timezone
    )
    _ingest_jsonl(jsonl, None, "case-c1-plaso-srv01", "srv01", volume_root=vr)
    (doc,) = [d["_source"] for d in sent]
    assert doc["vhir.source_file"] == "var/log/auth.log"
    assert doc["@timestamp"] == "2026-10-06T14:00:01+00:00"  # 10:00:01 EDT

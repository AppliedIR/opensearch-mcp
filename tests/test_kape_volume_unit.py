"""A KAPE-style image (one volume holding C/Windows/System32, as rd01's does)
is a Windows volume in the preview and at ingest, its host is named from
its registry, and its run is the unit the preview lists. dfVFS is a
stand-in in the listing rows (a tree that answers the lookups
volume_inventory makes); the real-image rows read images named in
VHIR_TEST_IMAGES and skip without them."""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import sys
import types
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import regipy.registry
from sift_common import host_identity, host_proposal
from test_image_direct import _image, needs_plaso
from test_names_scan import _Hive, windows_volume

from opensearch_mcp import ingest_cli, names_scan, parse_plaso
from opensearch_mcp import write_context as wc
from opensearch_mcp.discover import DiscoveredHost, find_volume_root, os_of_root


@pytest.fixture(autouse=True)
def hives(monkeypatch):
    monkeypatch.setattr(regipy.registry, "RegistryHive", _Hive)


def case():
    return wc.case_dir_for(f"kape-{uuid.uuid4().hex[:8]}")


# -- the volume listing, with dfVFS a stand-in


class _Entry:
    def __init__(self, name, directory=True, link=None, broken=False):
        self.name, self.directory, self.link, self.broken = name, directory, link, broken
        self.children: list[_Entry] = []

    def IsDirectory(self):  # noqa: N802 - dfVFS's name
        return self.directory

    def IsLink(self):  # noqa: N802
        return self.link is not None

    @property
    def sub_file_entries(self):
        if self.broken:
            raise OSError("listing failed")
        return iter(self.children)


class _Tree:
    """A file system as dfVFS shows it: an entry for each location, written
    with the file system's own separator; any other spelling isn't found."""

    def __init__(self, sep, dirs=(), files=(), links=None, separator_fails=False):
        self.sep, self.separator_fails = sep, separator_fails
        self.entries = {sep: _Entry("")}
        self.asked: list[str] = []
        for path, directory in [(d, True) for d in dirs] + [(f, False) for f in files]:
            self._add(path, directory)
        for path, target in (links or {}).items():
            self._add(path, False).link = target

    def _add(self, path, directory):
        parts = path.split("/")
        parent = self.entries[self.sep]
        for i, name in enumerate(parts):
            loc = self.sep + self.sep.join(parts[: i + 1])
            if loc not in self.entries:
                last = i == len(parts) - 1
                self.entries[loc] = _Entry(name, directory or not last)
                parent.children.append(self.entries[loc])
            parent = self.entries[loc]
        return parent

    def open(self, location):
        self.asked.append(location)
        return self.entries.get(location)


def _dfvfs_modules():
    dd = SimpleNamespace(
        TYPE_INDICATOR_GPT="GPT",
        TYPE_INDICATOR_TSK_PARTITION="TSK_PARTITION",
        TYPE_INDICATOR_APM="APM",
        TYPE_INDICATOR_LVM="LVM",
        TYPE_INDICATOR_APFS_CONTAINER="APFS_CONTAINER",
        TYPE_INDICATOR_RAW="RAW",
        TYPE_INDICATOR_EWF="EWF",
        TYPE_INDICATOR_MODI="MODI",
        TYPE_INDICATOR_OS="OS",
        FILE_SYSTEM_TYPE_INDICATORS=("NTFS", "EXT"),
    )

    def new_path_spec(type_indicator, location=None, parent=None):
        return SimpleNamespace(type_indicator=type_indicator, location=location, parent=parent)

    def open_file_entry(spec):
        return spec.parent.open(spec.location)

    def open_file_system(base):
        if base.parent.separator_fails:
            raise RuntimeError("no file system")
        return SimpleNamespace(PATH_SEPARATOR=base.parent.sep)

    resolver = SimpleNamespace(
        Resolver=SimpleNamespace(OpenFileEntry=open_file_entry, OpenFileSystem=open_file_system)
    )
    mods = {
        "dfvfs": {},
        "dfvfs.helpers": {},
        "dfvfs.helpers.source_scanner": {},
        "dfvfs.lib": {},
        "dfvfs.lib.definitions": vars(dd),
        "dfvfs.path": {},
        "dfvfs.path.factory": {"Factory": SimpleNamespace(NewPathSpec=new_path_spec)},
        "dfvfs.resolver": {},
        "dfvfs.resolver.resolver": vars(resolver),
        "dfvfs.volume": {},
        "dfvfs.volume.factory": {"Factory": SimpleNamespace()},
    }
    out = {}
    for name, attrs in mods.items():
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        out[name] = mod
    for name, mod in out.items():  # each package holds its submodules
        parent, _, child = name.rpartition(".")
        if parent:
            setattr(out[parent], child, mod)
    return out


@pytest.fixture
def inventory(monkeypatch):
    """volume_inventory imported against the stand-in dfVFS, so coverage
    sees the lines Plaso's interpreter runs."""
    for name, mod in _dfvfs_modules().items():
        monkeypatch.setitem(sys.modules, name, mod)
    sys.modules.pop("opensearch_mcp.volume_inventory", None)
    module = importlib.import_module("opensearch_mcp.volume_inventory")
    yield module
    sys.modules.pop("opensearch_mcp.volume_inventory", None)
    import opensearch_mcp

    if getattr(opensearch_mcp, "volume_inventory", None) is module:
        delattr(opensearch_mcp, "volume_inventory")


def _os(inventory, tree):
    return inventory._os_and_zone(SimpleNamespace(type_indicator="NTFS", parent=tree))


NTFS_KAPE = dict(
    dirs=["C/Windows/System32/config", "LongFileNames", "$Extend"],
    files=["2024-01-01T000000_CopyLog.csv"],
)


@pytest.mark.parametrize(
    "tree",
    [
        _Tree("\\", dirs=["Windows/System32/config"]),  # an NTFS C: (dev01)
        _Tree("\\", **NTFS_KAPE),  # rd01: the C: under a drive-letter folder
        _Tree("/", dirs=["Windows/System32"]),
        _Tree("/", dirs=["C/Windows/System32"]),
        _Tree("\\", dirs=["C%3A/Windows/System32"]),  # KAPE's escaped C:
        _Tree("/", dirs=["Windows/System32", "etc"]),  # Windows is checked first
    ],
    ids=["ntfs-root", "ntfs-kape", "slash-root", "slash-kape", "ntfs-kape-escaped", "win-etc"],
)
def test_a_windows_install_is_found_at_the_root_or_under_a_drive_letter_folder(inventory, tree):
    assert _os(inventory, tree) == {"os": "windows"}


def test_a_kape_volume_is_looked_up_with_the_file_systems_own_separator(inventory):
    tree = _Tree("\\", **NTFS_KAPE)
    _os(inventory, tree)
    assert tree.asked == ["\\Windows\\System32", "\\", "\\C\\Windows\\System32"]


def test_a_linux_root_keeps_its_zone(inventory):
    tree = _Tree(
        "/", dirs=["etc"], links={"etc/localtime": "/usr/share/zoneinfo/America/New_York"}
    )
    assert _os(inventory, tree) == {"os": "linux", "localtime": "link", "zone": "America/New_York"}


@pytest.mark.parametrize(
    "tree",
    [
        _Tree("\\", dirs=["etc"]),  # an NTFS volume with an etc folder at its root
        _Tree("/", dirs=["C/etc", "C/System/Library"]),  # only Windows is looked for below
        _Tree("\\", dirs=["Windows"]),  # no System32
        _Tree("\\", dirs=["LongName/Windows/System32", ".C/Windows/System32"]),
    ],
    ids=["ntfs-etc", "slash-kape-etc", "no-system32", "long-or-dot-folder"],
)
def test_no_install_is_found_where_none_is_looked_for(inventory, tree):
    assert _os(inventory, tree) == {}


def test_a_file_named_like_a_drive_letter_is_never_looked_inside(inventory):
    # a file X that the stand-in also answers for under X\Windows\System32
    tree = _Tree("\\", files=["X"])
    tree.entries["\\X\\Windows\\System32"] = _Entry("System32")
    assert _os(inventory, tree) == {}
    assert "\\X\\Windows\\System32" not in tree.asked


def test_an_empty_child_name_is_skipped(inventory):
    tree = _Tree("\\")
    tree.entries["\\"].children.append(_Entry(""))
    tree.entries["\\\\Windows\\System32"] = _Entry("System32")
    assert _os(inventory, tree) == {}


@pytest.mark.parametrize("sep", ["", None])
def test_a_file_system_with_no_separator_is_read_with_slash(inventory, sep):
    tree = _Tree("/", dirs=["Windows/System32"])
    tree.entries[sep] = tree.entries["/"]
    tree.sep = sep
    assert _os(inventory, tree) == {"os": "windows"}


def test_a_file_system_that_does_not_open_is_read_with_slash(inventory):
    assert _os(inventory, _Tree("/", dirs=["C/Windows/System32"], separator_fails=True)) == {
        "os": "windows"
    }
    assert _os(inventory, _Tree("\\", dirs=["Windows/System32"], separator_fails=True)) == {}


def test_a_root_that_cannot_be_listed_or_opened_has_no_drive_letter_install(inventory):
    tree = _Tree("\\", dirs=["C/Windows/System32"])
    tree.entries["\\"].broken = True
    assert _os(inventory, tree) == {}
    del tree.entries["\\"]
    assert _os(inventory, tree) == {}


def test_a_lookup_that_raises_is_not_found(inventory):
    class Raising(_Tree):
        def open(self, location):
            raise OSError("bad entry")

    assert _os(inventory, Raising("\\", dirs=["Windows/System32"])) == {}


def _on_disk(root: Path, sep: str, dirs) -> _Tree:
    """The stand-in for a tree also written to disk under root."""
    for d in dirs:
        (root / d).mkdir(parents=True, exist_ok=True)
    return _Tree(sep, dirs=dirs)


@pytest.mark.parametrize(
    "dirs",
    [
        ["Windows/System32/config"],
        ["C/Windows/System32/config", "LongFileNames"],
        ["C%3A/Windows/System32/config"],
        ["Users/Windows/System32/config"],  # Users is 5 characters
        [".C/Windows/System32/config"],
        ["HOST1/C/Windows/System32/config"],
        ["etc"],
    ],
)
@pytest.mark.parametrize("sep", ["\\", "/"])
def test_the_listing_and_the_mount_agree_on_a_windows_volume(inventory, tmp_path, dirs, sep):
    vol = tmp_path / "vol"
    tree = _on_disk(vol, sep, dirs)
    mounted = find_volume_root(vol)
    on_mount = mounted is not None and os_of_root(mounted) == "windows"
    assert (_os(inventory, tree).get("os") == "windows") == on_mount


# -- the volume listing, on real images


def _ext4(tmp_path: Path, dirs) -> Path:
    if not shutil.which("mkfs.ext4"):
        pytest.skip("mkfs.ext4 not installed")
    src = tmp_path / "tree"
    src.mkdir()
    for d in dirs:
        (src / d).mkdir(parents=True)
    (src / "CopyLog.csv").write_text("x\n")
    image = tmp_path / "kape.ext4"
    subprocess.run(
        ["mkfs.ext4", "-q", "-F", "-d", str(src), str(image), "8M"],
        check=True,
        capture_output=True,
    )
    return image


@needs_plaso
@pytest.mark.parametrize(
    "dirs, expected",
    [
        (["C/Windows/System32/config", "LongFileNames"], "windows"),
        (["Windows/System32/config"], "windows"),
        (["C/etc"], None),
    ],
)
def test_a_real_volume_with_a_drive_letter_folder_lists_as_windows(tmp_path, dirs, expected):
    (leaf,), error = parse_plaso.volume_inventory(_ext4(tmp_path, dirs))
    assert error == "" and leaf["kind"] == "filesystem" and leaf.get("os") == expected


@needs_plaso
def test_rd01s_kape_volume_lists_as_windows():
    (leaf,), error = parse_plaso.volume_inventory(_image("rd01-triage.vhdx"))
    assert error == ""
    assert (leaf["selector"], leaf["offset"], leaf["fs"], leaf.get("os")) == (
        {"partitions": "p1"},
        32256,
        "NTFS",
        "windows",
    )
    runs, notes = parse_plaso.plan_image_runs([leaf])
    assert runs == [] and notes == []


@needs_plaso
def test_dev01s_ntfs_c_drive_lists_as_windows():
    leaves, error = parse_plaso.volume_inventory(_image("dev01-c-drive.E01"))
    (fs,) = [leaf for leaf in leaves if leaf["kind"] == "filesystem"]
    assert error == "" and (fs["fs"], fs.get("os")) == ("NTFS", "windows")


# -- the preview's record of an image's volumes


def _summary(image: Path, leaves: list[dict], d: Path) -> dict:
    (entry,) = names_scan.record(d, names_scan.image_candidates(image, leaves, d))
    return entry


def _evidence(d: Path, name: str) -> Path:
    image = d / "evidence" / name
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"\0")
    return image


VSHADOW = {"selector": {}, "offset": 0, "kind": "no_filesystem", "type": "VSHADOW"}
DEV01 = [dict(VSHADOW) for _ in range(10)] + [
    {"selector": {}, "offset": 0, "kind": "filesystem", "fs": "NTFS", "os": "windows"}
]


def test_a_windows_volume_is_recorded_with_its_os_and_the_same_unit():
    d = case()
    image = _evidence(d, "rd01.vhdx")
    leaf = {"selector": {"partitions": "p1"}, "offset": 32256, "kind": "filesystem", "fs": "NTFS"}
    before = names_scan.image_candidates(image, [leaf], d)[0]
    entry = _summary(image, [{**leaf, "os": "windows"}], d)
    assert entry["unit"] == before.key and entry["locator"] == before.locator
    assert entry["os"] == "windows" and "note" not in entry
    stored = host_identity.load(d).units[entry["unit"]]
    assert stored["os"] == "windows" and "note" not in stored


def test_an_ntfs_c_drive_with_shadow_copies_is_recorded_as_windows_with_no_note():
    d = case()
    entry = _summary(_evidence(d, "dev01.E01"), DEV01, d)
    assert entry["os"] == "windows" and "note" not in entry


def test_a_volume_with_no_file_system_keeps_its_note():
    d = case()
    image = _evidence(d, "disk.raw")
    blank = {"selector": {"partitions": "p2"}, "offset": 1048576, "kind": "no_filesystem"}
    entry = _summary(image, [{**blank, "type": "TSK_PARTITION"}], d)
    assert entry["note"] == "no operating system found on this volume" and "os" not in entry
    runs, notes = parse_plaso.plan_image_runs([blank])
    assert notes == [(1048576, "p2 at offset 1048576: no file system found; not parsed")]


def test_an_lvm_volume_with_no_file_system_beside_one_with_keeps_its_note():
    d = case()
    image = _evidence(d, "lvm.raw")
    leaves = [
        {"selector": {"volumes": "lvm1"}, "offset": 0, "kind": "filesystem", "fs": "EXT"},
        {"selector": {"volumes": "lvm2"}, "offset": 0, "kind": "no_filesystem", "type": "LVM"},
    ]
    leaves[0]["os"] = "linux"
    units = names_scan.record(d, names_scan.image_candidates(image, leaves, d))
    by_volume = {u["volume"]: u for u in units}
    assert "note" not in by_volume["lvm1"] and by_volume["lvm1"]["os"] == "linux"
    assert by_volume["lvm2"]["note"] == "no operating system found on this volume"


@pytest.fixture
def no_case_preview(monkeypatch):
    from opensearch_mcp import server

    monkeypatch.setattr(server, "_scan_case_dir", lambda case_id="": None)
    return lambda image: server._container_scan(image, "ewf", "")


def test_the_no_case_preview_lists_a_shadowed_c_drive_once_as_windows(
    no_case_preview, monkeypatch, tmp_path
):
    monkeypatch.setattr(parse_plaso, "volume_inventory", lambda image: (DEV01, ""))
    (volume,) = no_case_preview(tmp_path / "dev01.E01")["volumes"]
    assert volume["os"] == "windows" and "note" not in volume


@needs_plaso
def test_dev01_is_recorded_as_windows_with_no_note():
    image = _image("dev01-c-drive.E01")
    leaves, _ = parse_plaso.volume_inventory(image)
    entry = _summary(image, leaves, case())
    assert entry["os"] == "windows" and "note" not in entry


@needs_plaso
def test_dev01s_no_case_preview_lists_no_shadow_copies(no_case_preview):
    (volume,) = no_case_preview(_image("dev01-c-drive.E01"))["volumes"]
    assert (volume["volume"], volume["fs"], volume["os"]) == ("fs", "NTFS", "windows")
    assert "note" not in volume


# -- the mounted volume


def _kape_mount(root: Path, name: str, computer: str = "DC01") -> Path:
    """A mounted volume holding a KAPE collection: C/Windows/... plus the
    collection's own files."""
    v = root / name
    windows_volume(v / "C", computer)
    (v / "LongFileNames").mkdir()
    (v / "2024-01-01T000000_CopyLog.csv").write_text("x\n")
    return v


def test_a_kape_volumes_host_is_named_from_its_registry(tmp_path, capsys):
    notes: list = []
    v = _kape_mount(tmp_path, "nbd3p1")
    assert ingest_cli._hostname_from_volumes([v], notes, "dc01-triage-c88f4709") == "DC01"
    assert notes == [] and "Hostname from volume registry: DC01" in capsys.readouterr().out


def test_two_kape_volumes_are_each_their_own_host_named_by_their_registry(tmp_path, capsys):
    notes: list = []
    vols = [_kape_mount(tmp_path, "nbd3p1", "WKS1"), _kape_mount(tmp_path, "nbd3p2", "WKS2")]
    assert ingest_cli._hostname_from_volumes(vols, notes, "pair-0a1b2c3d") is None
    ((label, note),) = notes
    assert label == "hostname"
    assert note == (
        "2 OS installs on this image (nbd3p1: windows WKS1, nbd3p2: windows WKS2); each is "
        "ingested as its own host (pair-0a1b2c3d-nbd3p1, pair-0a1b2c3d-nbd3p2). The names "
        "come from the evidence: confirm in the Portal's Hosts tab whether they are one machine"
    )
    assert "--hostname" not in capsys.readouterr().err


def test_a_windows_volume_with_no_readable_name_says_where_names_come_from(tmp_path, capsys):
    v = tmp_path / "nbd3p1"
    (v / "C" / "Windows" / "System32" / "config").mkdir(parents=True)
    assert ingest_cli._hostname_from_volumes([v], [], "img") is None
    err = capsys.readouterr().err
    assert err.strip() == (
        "WARNING: could not detect hostname from registry; the host names come from the "
        "evidence's folder and file names (a weaker signal): confirm them in the Portal's "
        "Hosts tab"
    )


def _image_case(name: str) -> tuple[Path, Path]:
    d = case()
    return d, _evidence(d, name)


def test_a_kape_volumes_run_is_the_unit_the_preview_lists(tmp_path):
    d, image = _image_case("rd01.vhdx")
    v = _kape_mount(tmp_path, "nbd3p1")
    host = DiscoveredHost(hostname="DC01", volume_root=v / "C")
    ingest_cli._set_units([host], d.name, image, tmp_path, "DC01", "artifact", offsets={v: 32256})
    leaf = {"selector": {"partitions": "p1"}, "offset": 32256, "kind": "filesystem", "fs": "NTFS"}
    (candidate,) = names_scan.image_candidates(image, [leaf], d)
    assert host.unit_locator == candidate.locator


def test_hosts_in_their_own_folders_on_one_volume_keep_their_own_units(tmp_path):
    d, image = _image_case("multi.raw")
    v = tmp_path / "nbd3p1"
    hosts = []
    for name in ("HOST1", "HOST2"):
        windows_volume(v / name / "C", name)
        hosts.append(DiscoveredHost(hostname=name, volume_root=v / name / "C"))
    ingest_cli._set_units(hosts, d.name, image, tmp_path, None, None, offsets={v: 1048576})
    assert [h.unit_locator for h in hosts] == [
        names_scan.volume_locator(image, d, 1048576, prefix="HOST1/C"),
        names_scan.volume_locator(image, d, 1048576, prefix="HOST2/C"),
    ]


def test_two_drive_letter_folders_on_one_volume_keep_two_units(tmp_path):
    d, image = _image_case("two.raw")
    v = tmp_path / "nbd3p1"
    hosts = []
    for letter in ("C", "D"):
        windows_volume(v / letter, f"WKS{letter}")
        hosts.append(DiscoveredHost(hostname=f"WKS{letter}", volume_root=v / letter))
    ingest_cli._set_units(hosts, d.name, image, tmp_path, None, None, offsets={v: 32256})
    first = find_volume_root(v)
    expected = {
        h.hostname: names_scan.volume_locator(
            image, d, 32256, prefix="" if h.volume_root == first else h.volume_root.name
        )
        for h in hosts
    }
    assert {h.hostname: h.unit_locator for h in hosts} == expected
    assert len({h.unit_locator for h in hosts}) == 2


def test_a_volume_root_layout_keeps_its_unit(tmp_path):
    d, image = _image_case("disk.raw")
    v = windows_volume(tmp_path / "nbd3p1", "WKS20")
    host = DiscoveredHost(hostname="WKS20", volume_root=v)
    ingest_cli._set_units([host], d.name, image, tmp_path, "WKS20", "artifact", offsets={v: 0})
    assert host.unit_locator == names_scan.volume_locator(image, d, 0)


def test_a_kape_image_is_one_host_named_by_its_registry_not_its_mount(tmp_path):
    d, image = _image_case("dc01-triage.vhdx")
    v = _kape_mount(tmp_path, "nbd3p1")
    notes: list = []
    hostname = ingest_cli._hostname_from_volumes([v], notes, "dc01-triage-c88f4709")
    hosts = ingest_cli._discover_volumes(
        [v], hostname, True, "dc01-triage-c88f4709", notes, offsets={v: 32256}
    )
    ingest_cli._set_units(hosts, d.name, image, tmp_path, hostname, "artifact", offsets={v: 32256})
    assert [(h.hostname, h.name_origin) for h in hosts] == [("DC01", "artifact")]
    assert "dc01-triage-c88f4709-nbd3p1" not in {h.hostname for h in hosts}
    leaf = {"selector": {"partitions": "p1"}, "offset": 32256, "kind": "filesystem"}
    assert hosts[0].unit_locator == names_scan.image_candidates(image, [leaf], d)[0].locator


# -- whose name the detected one is: the run's input decides, at both writers


def _stored_origins(tmp_path, via, given=None, archive=False):
    """An image run on a KAPE volume in the order cmd_scan runs it: the host
    found and its unit set, the names scan recorded, then the write context
    opened. The stored origins of each name, and the groups proposed. With
    `archive`, the image is one of several in a registered archive, extracted
    outside the case."""
    d, image = _image_case("dc01-triage.vhdx")
    inside = None
    if archive:
        inside = (_evidence(d, "pair.zip"), image.name)
        image = tmp_path / "extracted" / image.name
        image.parent.mkdir()
        image.write_bytes(b"\0")
    registered = inside[0] if inside else image
    entry = {"path": str(registered.resolve())} | ({"registered_via": via} if via else {})
    (d / "evidence.json").write_text(json.dumps({"files": [entry]}))
    v = _kape_mount(tmp_path, "nbd3p1")
    notes: list = []
    hostname = given or ingest_cli._hostname_from_volumes([v], notes, "dc01-triage-c88f4709")
    origin = "argument" if given else "artifact"
    hosts = ingest_cli._discover_volumes(
        [v], hostname, True, "dc01-triage-c88f4709", notes, offsets={v: 32256}
    )
    ingest_cli._set_units(
        hosts, d.name, image, tmp_path, hostname, origin, offsets={v: 32256}, archive=inside
    )
    names_scan.record(d, [names_scan.host_folder_unit(h, d, registered) for h in hosts])
    for h in hosts:
        wc.host_context(d, d.name, h, "run-1", input_path=registered)
    state = host_identity.load(d)
    origins: dict = {}
    for (_unit, raw), info in state.names.items():
        origins.setdefault(raw, set()).update(info.get("origins") or [])
    return {raw: sorted(o) for raw, o in origins.items()}, host_proposal.propose(state)


@pytest.mark.parametrize("archive", [False, True], ids=["image", "image in an archive"])
def test_an_image_the_ai_registered_gives_its_detected_name_as_the_ais(tmp_path, archive):
    origins, groups = _stored_origins(tmp_path, "mcp", archive=archive)
    assert origins["DC01"] == [names_scan.AI_WRITTEN]
    (group,) = [g for g in groups if any(raw == "DC01" for _, raw in g.pairs)]
    assert host_proposal.FLAG_AI_ONLY in group.flags


@pytest.mark.parametrize("archive", [False, True], ids=["image", "image in an archive"])
def test_an_image_the_examiner_registered_gives_its_detected_name_as_evidence(tmp_path, archive):
    origins, groups = _stored_origins(tmp_path, None, archive=archive)
    assert origins["DC01"] == [names_scan.ARTIFACT]
    (group,) = [g for g in groups if any(raw == "DC01" for _, raw in g.pairs)]
    assert host_proposal.FLAG_AI_ONLY not in group.flags


def test_a_name_given_for_an_image_the_ai_registered_stays_the_one_given(tmp_path):
    origins, _ = _stored_origins(tmp_path, "mcp", given="SRV-A")
    assert origins["SRV-A"] == ["argument"]
    assert origins["DC01"] == [names_scan.AI_WRITTEN]

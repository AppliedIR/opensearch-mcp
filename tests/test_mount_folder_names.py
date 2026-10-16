"""A mounted image's folder name (the image id and its nbd device, like
dc01-triage-c88f4709-nbd3p1) is not a host name: once a KAPE volume is read
as Windows, its host is named from its registry, the mount folder's name is
never proposed, and confirming what is proposed makes no machine of it. A
plain host folder keeps its folder name, and its flag when the registry
disagrees."""

from __future__ import annotations

import pytest
import regipy.registry
from sift_common import host_gate
from sift_common import host_identity as hi
from sift_common import host_proposal as hp
from test_kape_volume_unit import _image_case, _kape_mount
from test_names_scan import _Hive, windows_volume

from opensearch_mcp import ingest_cli, names_scan
from opensearch_mcp.discover import DiscoveredHost

pytestmark = pytest.mark.host_gate  # the real gate, not the confirmed-hosts stand-in

IMAGE_ID = "dc01-triage-c88f4709"
MOUNT_NAME = f"{IMAGE_ID}-nbd3p1"


@pytest.fixture(autouse=True)
def hives(monkeypatch):
    monkeypatch.setattr(regipy.registry, "RegistryHive", _Hive)


def _kape_image_run(tmp_path):
    """The image run of a KAPE triage VHDX mounted at nbd3p1: its hosts, as
    ingest names them, recorded in the case. Returns the case, hosts and units."""
    d, image = _image_case("dc01-triage.vhdx")
    v = _kape_mount(tmp_path, "nbd3p1")
    notes: list = []
    hostname = ingest_cli._hostname_from_volumes([v], notes, IMAGE_ID)
    hosts = ingest_cli._discover_volumes([v], hostname, True, IMAGE_ID, notes, offsets={v: 32256})
    ingest_cli._set_units(hosts, d.name, image, tmp_path, hostname, "artifact", offsets={v: 32256})
    units = [names_scan.host_folder_unit(h, d, image) for h in hosts]
    names_scan.record(d, units)
    return d, hosts, [u.key for u in units]


def _host_folder_run(tmp_path, folder: str, computer: str):
    """A plain host folder `folder` holding C/Windows whose registry names `computer`."""
    d, _ = _image_case("unused.raw")
    root = tmp_path / "hosts" / folder
    windows_volume(root / "C", computer)
    host = DiscoveredHost(hostname=folder, volume_root=root / "C")
    unit = names_scan.host_folder_unit(host, d, root)
    names_scan.record(d, [unit])
    return d, unit.key


def test_a_mount_folder_name_is_never_recorded_or_proposed(tmp_path):
    d, hosts, units = _kape_image_run(tmp_path)
    state = hi.load(d)
    assert MOUNT_NAME not in {raw for _, raw in state.names}
    assert MOUNT_NAME not in {p[1] for g in hp.propose(state) for p in g.pairs}
    assert MOUNT_NAME not in {e["raw"] for e in host_gate.unresolved(state, units)}


def test_the_images_registry_name_is_proposed_and_held_until_confirmed_with_no_folder_flag(
    tmp_path,
):
    d, hosts, units = _kape_image_run(tmp_path)
    state = hi.load(d)
    groups = [(g.canonical, [p[1] for p in g.pairs], g.flags) for g in hp.propose(state)]
    assert groups == [("DC01", ["DC01"], [])]
    # until the examiner confirms, the gate holds the registry name alone
    held = [(e["raw"], e["reason"]) for e in host_gate.unresolved(state, units)]
    assert held == [("DC01", host_gate.REASON_UNCONFIRMED)]


def test_confirming_what_is_proposed_files_the_run_under_its_registry_name(tmp_path):
    # the release path that filed the image's records under a mount-folder machine
    d, hosts, units = _kape_image_run(tmp_path)
    state = hi.load(d)
    machines = [
        {
            "key": hi.new_machine_key(),
            "canonical": g.canonical,
            "pairs": [list(p) for p in g.pairs],
        }
        for g in hp.propose(state)
    ]
    hi.append_decision(
        d,
        {"action": "confirm", "examiner": "ex1", "args": {"machines": machines}},
        state.obs_offset,
    )
    state = hi.load(d)
    assert [h.hostname for h in hosts] == ["DC01"]
    assert [(m.canonical, [raw for _, raw in m.pairs]) for m in state.machines.values()] == [
        ("DC01", ["DC01"])
    ]
    assert state.machine_of_pair(units[0], "DC01").canonical == "DC01"
    assert host_gate.unresolved(state, units) == []


def test_a_plain_host_folder_keeps_its_folder_name(tmp_path):
    d, unit = _host_folder_run(tmp_path, "HOST1", "HOST1")
    state = hi.load(d)
    assert sorted({(u, raw) for u, raw in state.names if u == unit}) == [(unit, "HOST1")]
    (g,) = hp.propose(state)
    assert g.canonical == "HOST1" and hp.FLAG_FOLDER not in g.flags


def test_a_plain_host_folder_that_names_another_machine_is_still_flagged(tmp_path):
    d, unit = _host_folder_run(tmp_path, "WKS9", "DC01")
    state = hi.load(d)
    assert {raw for u, raw in state.names if u == unit} == {"WKS9", "DC01"}
    assert any(hp.FLAG_FOLDER in g.flags for g in hp.propose(state))

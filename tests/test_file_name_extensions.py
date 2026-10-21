"""A name read from a file or archive-member name never keeps an image or
archive extension: wkstn05-memory.img.7z gives wkstn05-memory, never the name
wkstn05-memory in the domain "img". One rule, every file-name source. Names
are synthetic."""

from __future__ import annotations

from pathlib import Path

import pytest

from opensearch_mcp import ingest_cli, names_scan
from opensearch_mcp.server import _detect_hostnames_from_filenames

EXTS = [".img", ".raw", ".mem", ".vmem", ".dmp", ".lime", ".bin", ".dd", ".e01", ".Ex01",
        ".vhdx", ".vhd", ".vmdk", ".dmg", ".7z", ".zip", ".img.7z", ".raw.zip", ".vhdx.7z",
        ".E01.ZIP", ".mem.tar.gz", ".vmdk.tgz", ".iso", ".iso.7z"]  # fmt: skip
HOSTS = ["wkstn05", "wkstn05-memory", "wkstn05.shieldbase.com"]


def _memory_image(tmp: Path, host: str, ext: str) -> set[str]:
    image = tmp / f"{host}{ext}"
    return {n.raw for n in names_scan.memory_unit(image, image, "", "", None).names}


def _archive_member(tmp: Path, host: str, ext: str) -> set[str]:
    unit = names_scan.memory_unit(tmp / "m.img", tmp / f"{host}{ext}", "m.img", "", None)
    return {n.raw for n in unit.names if n.evidence == "archive file name"}


def _log_file(tmp: Path, host: str, ext: str) -> set[str]:
    f = tmp / f"EvtxECmd-{host}{ext}.csv"
    f.write_text("a,b\n1,2\n")
    unit = names_scan.files_unit(tmp, "", [f], None)
    return {n.raw for n in unit.names if n.evidence.endswith("file name")}


def _folder_split(tmp: Path, host: str, ext: str) -> set[str]:
    return {ingest_cli._filename_host(tmp / f"EvtxECmd-{host}{ext}.csv")}


def _detector(tmp: Path, host: str, ext: str) -> set[str]:
    (tmp / f"EvtxECmd-{host}{ext}.csv").write_text("a,b\n1,2\n")
    return _detect_hostnames_from_filenames(tmp)


SOURCES = [_memory_image, _archive_member, _log_file, _folder_split, _detector]
LOWER = {_folder_split, _detector}  # these read names lower-cased


@pytest.mark.parametrize("ext", EXTS)
@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("source", SOURCES, ids=lambda s: s.__name__.strip("_"))
def test_a_name_from_a_file_name_keeps_no_image_or_archive_extension(tmp_path, source, host, ext):
    if source in (_log_file, _folder_split, _detector) and "-" in host:
        pytest.skip("a dash splits a tool-host file name")
    want = host.lower() if source in LOWER else host
    assert source(tmp_path, host, ext) == {want}


@pytest.mark.parametrize(
    "name, stem",
    [
        ("wkstn05-memory.img.7z", "wkstn05-memory"),
        ("wkstn05-memory.iso.7z", "wkstn05-memory"),
        ("wkstn05.shieldbase.com.E01", "wkstn05.shieldbase.com"),
        ("Tool-HOST.csv", "Tool-HOST"),  # one extension, any kind, as before
        ("WKS70", "WKS70"),
        ("dir/HOST.vmem", "HOST"),
        ("x.csv.gz", "x.csv"),  # a compressed log keeps its log extension
    ],
)
def test_file_name_stem(name, stem):
    assert names_scan.file_name_stem(name) == stem

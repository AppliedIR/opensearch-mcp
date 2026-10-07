"""Container handling: archive extraction and disk image mounting."""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

logger = logging.getLogger(__name__)


def detect_container(path: Path) -> str:
    """Detect container type from file extension.

    Returns: "archive", "ewf", "nbd", "raw", "dmg", "directory", or "unknown".
    A "dmg" (or .sparseimage) is never mounted: Plaso reads it directly.
    """
    suffix = path.suffix.lower()
    suffixes = "".join(path.suffixes[-2:]).lower()
    if suffix in (".zip", ".7z"):
        return "archive"
    if suffixes in (".tar.gz", ".tgz") or suffix == ".tar":
        return "archive"
    if suffix in (".e01", ".ex01"):
        return "ewf"
    if suffix in (".vhdx", ".vhd", ".vmdk"):
        return "nbd"
    if suffix in (".dd", ".raw", ".img", ".iso"):
        return "raw"
    if suffix in (".dmg", ".sparseimage"):
        return "dmg"
    if path.is_dir():
        return "directory"
    return "unknown"


def extract_container(path: Path, dest: Path, password: str | None = None) -> None:
    """Extract archive to dest directory."""
    suffix = path.suffix.lower()
    suffixes = "".join(path.suffixes[-2:]).lower()

    if suffix in (".zip", ".7z"):
        _extract_7z(path, dest, password)
    elif suffixes in (".tar.gz", ".tgz") or suffix == ".tar":
        _extract_tar(path, dest)
    else:
        raise ValueError(f"Unknown archive format: {path.name}")


def _extract_7z(path: Path, dest: Path, password: str | None = None) -> None:
    """Extract archive with 7z."""
    cmd = ["7z", "x", str(path), f"-o{dest}", "-y"]
    if password:
        cmd.append(f"-p{password}")
    result = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL)
    # 7z exit codes: 0=ok, 1=warning (timestamps), 2+=error
    if result.returncode > 1:
        # Sanitize command to strip password before including in error
        safe_cmd = [c if not c.startswith("-p") else "-p***" for c in cmd]
        raise subprocess.CalledProcessError(
            result.returncode, safe_cmd, result.stdout, result.stderr
        )


def _extract_tar(path: Path, dest: Path) -> None:
    """Extract tar/tar.gz archive with path traversal validation."""
    subprocess.run(["tar", "xf", str(path), "-C", str(dest)], check=True)
    # Validate no files escaped destination
    dest_resolved = dest.resolve()
    for root, _dirs, files in os.walk(dest):
        for f in files:
            full = Path(root, f).resolve()
            if not full.is_relative_to(dest_resolved):
                raise ValueError(f"Path traversal detected in archive: {full}")


# ---------------------------------------------------------------------------
# Disk image mounting
# ---------------------------------------------------------------------------


class MountContext:
    """Track mounts for cleanup."""

    def __init__(self) -> None:
        self._mounts: list[Path] = []  # mount points (sudo umount)
        self._fuse_mounts: list[Path] = []  # FUSE mounts (fusermount -u)
        self._nbd_devices: list[str] = []  # qemu-nbd -d
        self._loop_devices: list[str] = []  # losetup -d
        self.failures: list[str] = []  # partitions that were tried and didn't mount
        self.not_mounted: list[str] = []  # partitions left unmounted on purpose (LVM)
        self.offsets: dict[Path, int] = {}  # mount point -> byte offset in the image
        self.vss_sources: dict[str, str] = {}  # shadow copy id -> the volume it came from

    def add_mount(self, mount_point: Path) -> None:
        self._mounts.append(mount_point)

    def add_fuse(self, mount_point: Path) -> None:
        self._fuse_mounts.append(mount_point)

    def add_nbd(self, device: str) -> None:
        self._nbd_devices.append(device)

    def add_loop(self, device: str) -> None:
        self._loop_devices.append(device)

    def cleanup(self) -> None:
        """Unmount everything in reverse order.

        Each entry leaves its list once released, so a second call (the atexit
        hook after the scan's own) retries only what failed.
        """
        for mp in reversed(list(self._mounts)):
            result = subprocess.run(["sudo", "umount", str(mp)], capture_output=True)
            if result.returncode != 0:
                logger.warning(
                    "umount %s failed: %s, trying lazy",
                    mp,
                    result.stderr.decode(errors="replace").strip(),
                )
                result = subprocess.run(["sudo", "umount", "-l", str(mp)], capture_output=True)
            if result.returncode == 0:
                self._mounts.remove(mp)
        for mp in reversed(list(self._fuse_mounts)):
            result = subprocess.run(["fusermount", "-u", str(mp)], capture_output=True)
            if result.returncode != 0:
                logger.warning(
                    "fusermount -u %s failed: %s",
                    mp,
                    result.stderr.decode(errors="replace").strip(),
                )
            else:
                self._fuse_mounts.remove(mp)
        for dev in list(self._nbd_devices):
            result = subprocess.run(["sudo", "qemu-nbd", "-d", dev], capture_output=True)
            if result.returncode == 0:
                self._nbd_devices.remove(dev)
        for dev in list(self._loop_devices):
            result = subprocess.run(["sudo", "losetup", "-d", dev], capture_output=True)
            if result.returncode == 0:
                self._loop_devices.remove(dev)


def check_sudo() -> None:
    """Verify non-interactive sudo is available."""
    result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if result.returncode != 0:
        raise PermissionError(
            "Disk image mounting requires sudo.\n"
            "Run with: sudo vhir ingest <path>\n"
            "Or configure passwordless sudo for mount/umount."
        )


def mount_image(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount a disk image read-only. Returns list of mounted volume paths."""
    suffix = path.suffix.lower()
    if suffix in (".e01", ".ex01"):
        return _mount_ewf(path, dest, ctx)
    elif suffix in (".dd", ".raw", ".img", ".iso"):
        return _mount_raw(path, dest, ctx)
    elif suffix in (".vmdk", ".vhd", ".vhdx"):
        return _mount_nbd(path, dest, ctx)
    else:
        raise ValueError(f"Unknown disk image format: {path.name}")


def _mount_ewf(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount E01/Ex01 via ewfmount (FUSE)."""
    check_sudo()
    ewf_mount = dest / "_ewf"
    ewf_mount.mkdir()
    # Mounted by root so root's loop mount of ewf1 can read it; allow_other
    # keeps it readable by the examiner's own fdisk and VSS scan.
    cmd = ["sudo", "ewfmount", "-X", "allow_other", str(path), str(ewf_mount)]
    subprocess.run(cmd, check=True)
    ctx.add_mount(ewf_mount)
    raw_path = ewf_mount / "ewf1"
    return _mount_raw_partitions(raw_path, dest, ctx)


def _mount_raw(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount raw/dd image via loop device."""
    return _mount_raw_partitions(path, dest, ctx)


# Partition types that hold no filesystem, as fdisk prints them: MBR Ids
# (the first token) for extended containers and swap, and GPT names.
# LVM is never loop-mounted either: the analysis host's udev/lvm2 could
# activate the evidence's volume group. Plaso reads LVM from the image.
_SKIP_MBR_IDS = {"5", "f", "85", "82", "8e"}
_SKIP_GPT_TYPES = {"Microsoft reserved", "BIOS boot", "Linux swap", "Linux LVM"}
_LVM_TYPES = ({"8e"}, {"Linux LVM"})


def _is_lvm_pv(path: Path) -> bool:
    """Whether the image starts with an LVM physical volume (LABELONE in sector 1)."""
    try:
        with open(path, "rb") as f:
            f.seek(512)
            return f.read(8) == b"LABELONE"
    except OSError:
        return False


def _mount_raw_partitions(raw_path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount every filesystem partition of a raw disk image, read-only."""
    check_sudo()
    result = subprocess.run(
        ["fdisk", "-l", str(raw_path)],
        capture_output=True,
        text=True,
    )
    partitions = _parse_fdisk_output(result.stdout)

    # If fdisk found no partitions at all, skip the partition loop —
    # this is likely a volume image (no MBR/GPT), go straight to direct mount.
    mounted = []
    if partitions:
        for idx, part in enumerate(partitions):
            # GPT gives the type name; MBR gives the Id and its name ("7 HPFS/NTFS/exFAT")
            mbr_id = (part["type"].split() or [""])[0]
            offset = part["start"] * part["sector_size"]
            if mbr_id in _LVM_TYPES[0] or part["type"] in _LVM_TYPES[1]:
                ctx.not_mounted.append(f"LVM partition at offset {offset}: read without mounting")
                continue
            if part["type"] in _SKIP_GPT_TYPES or mbr_id in _SKIP_MBR_IDS:
                continue
            mount_point = dest / f"vol{idx}"
            mount_point.mkdir()
            # Bound the loop device to the partition, or the next partition's
            # mount fails ("overlapping loop device exists").
            size = part["sectors"] * part["sector_size"]
            try:
                subprocess.run(
                    [
                        "sudo",
                        "mount",
                        "-o",
                        f"ro,loop,offset={offset},sizelimit={size},noexec",
                        str(raw_path),
                        str(mount_point),
                    ],
                    check=True,
                    capture_output=True,
                )
                ctx.add_mount(mount_point)
                ctx.offsets[mount_point] = offset
                mounted.append(mount_point)
            except subprocess.CalledProcessError as e:
                mount_point.rmdir()
                why = (e.stderr or b"").decode(errors="replace").strip().splitlines()[:1]
                failure = (
                    f"partition type '{part['type']}' at offset {offset} did not mount: "
                    f"{why[0] if why else f'mount exit {e.returncode}'}"
                )
                ctx.failures.append(failure)
                print(f"  WARNING: {failure}", file=sys.stderr)

    # Fallback: direct mount for volume images without partition table
    if not mounted and _is_lvm_pv(raw_path):
        ctx.not_mounted.append("LVM physical volume (the whole image): read without mounting")
    elif not mounted:
        mount_point = dest / "vol0"
        mount_point.mkdir(exist_ok=True)
        try:
            subprocess.run(
                [
                    "sudo",
                    "mount",
                    "-o",
                    "ro,loop,noexec",
                    str(raw_path),
                    str(mount_point),
                ],
                check=True,
                capture_output=True,
            )
            ctx.add_mount(mount_point)
            ctx.offsets[mount_point] = 0
            mounted.append(mount_point)
        except subprocess.CalledProcessError:
            mount_point.rmdir()

    return mounted


def _parse_fdisk_output(output: str) -> list[dict]:
    """Parse fdisk -l output for partition info."""
    partitions = []
    sector_size = 512

    for line in output.splitlines():
        # Parse sector size line: "Sector size (logical/physical): 512 bytes / 512 bytes"
        m = re.match(r"Sector size.*?:\s*(\d+)\s*bytes", line)
        if m:
            sector_size = int(m.group(1))
            continue

        # Parse partition lines — they start with the device path
        # /dev/sda1  *  2048  1023999  1021952  499M  7  HPFS/NTFS/exFAT
        # Or GPT: /dev/sda1  2048  1023999  1021952  499M  Microsoft basic data
        if not line.startswith("/"):
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        # Find the start sector — skip boot flag (*) if present
        try:
            start_idx = 1
            if parts[1] == "*":
                start_idx = 2
            start = int(parts[start_idx])
            sectors = int(parts[start_idx + 2])
        except (ValueError, IndexError):
            continue

        # Type is the last words after the size column
        # For MBR: type ID then name
        # For GPT: just the name
        ptype = " ".join(parts[start_idx + 4 :])

        partitions.append(
            {"start": start, "sectors": sectors, "sector_size": sector_size, "type": ptype}
        )

    return partitions


def _mount_nbd(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount VMDK/VHD/VHDX via qemu-nbd."""
    check_sudo()
    subprocess.run(
        ["sudo", "modprobe", "nbd", "max_part=8"],
        capture_output=True,
    )
    nbd_dev = _find_free_nbd()
    subprocess.run(
        ["sudo", "qemu-nbd", "-r", "-c", nbd_dev, str(path)],
        check=True,
        capture_output=True,
    )
    ctx.add_nbd(nbd_dev)

    # Wait for kernel to detect partitions (retry under concurrent I/O load)
    partitions: list[str] = []
    for _attempt in range(10):
        time.sleep(1)
        partitions = sorted(glob.glob(f"{nbd_dev}p*"))
        if partitions:
            break
    else:
        # Last resort: force kernel to re-read partition table
        subprocess.run(["sudo", "partprobe", nbd_dev], capture_output=True)
        time.sleep(1)
        partitions = sorted(glob.glob(f"{nbd_dev}p*"))

    mounted = []
    for part_dev in partitions:
        mount_point = dest / Path(part_dev).name
        mount_point.mkdir()
        try:
            subprocess.run(
                [
                    "sudo",
                    "mount",
                    "-o",
                    "ro,noexec",
                    part_dev,
                    str(mount_point),
                ],
                check=True,
                capture_output=True,
            )
            ctx.add_mount(mount_point)
            ctx.offsets[mount_point] = _nbd_offset(part_dev)
            mounted.append(mount_point)
        except subprocess.CalledProcessError:
            mount_point.rmdir()

    return mounted


def _nbd_offset(part_dev: str) -> int:
    """A partition's byte offset in its nbd disk, from sysfs (in 512-byte
    sectors whatever the disk's sector size); -1 when it can't be read."""
    try:
        return int(Path(f"/sys/class/block/{Path(part_dev).name}/start").read_text()) * 512
    except (OSError, ValueError):
        return -1


def _find_free_nbd() -> str:
    """Find an unused /dev/nbd* device."""
    for i in range(8):
        dev = f"/dev/nbd{i}"
        size_path = Path(f"/sys/block/nbd{i}/size")
        if size_path.exists():
            size = int(size_path.read_text().strip())
            if size == 0:
                return dev
    raise RuntimeError("No available NBD devices (nbd0-nbd7 all in use)")


# ---------------------------------------------------------------------------
# VSS
# ---------------------------------------------------------------------------


def _is_ntfs(raw_path: Path, offset: int) -> bool:
    """Whether an NTFS boot sector starts `offset` bytes into the image.
    Raises OSError when it can't be read: that's never "not NTFS"."""
    with open(raw_path, "rb") as f:
        f.seek(offset + 3)
        return f.read(8) == b"NTFS    "


def mount_vss(
    raw_path: Path,
    dest: Path,
    ctx: MountContext,
    offsets: dict[str, int] | None = None,
    notes: list[tuple[str, str]] | None = None,
) -> list[tuple[str, Path]]:
    """Mount volume shadow copies. Returns list of (vss_id, mount_path).

    `offsets` names each mounted volume's byte offset in the image: the
    shadow copies of every NTFS one are read at its offset (on a partitioned
    disk, a read of the whole image finds none). Without it, the image is
    one volume. An NTFS volume with none is said in `notes`.
    """
    if offsets is None:
        volumes = {"": 0}
    else:
        volumes = {}
        for name, off in offsets.items():
            try:
                if _is_ntfs(raw_path, off):
                    volumes[name] = off
            except OSError as e:  # unread: unprocessed, never "none found"
                failure = (
                    f"shadow copies on {name} (offset {off}) couldn't be read: "
                    f"its boot sector couldn't be read ({e.strerror or e})"
                )
                ctx.failures.append(failure)
                print(f"  WARNING: {failure}", file=sys.stderr)
    results = []
    for name, offset in sorted(volumes.items(), key=lambda v: v[1]):
        found, unread = _mount_vss_at(
            raw_path, dest, ctx, offset, name if len(volumes) > 1 else ""
        )
        where = f"{name} (offset {offset})" if name else "the image"
        if unread:  # tried and not read: unprocessed, never "none"
            failure = f"shadow copies on {where} couldn't be read: {unread}"
            ctx.failures.append(failure)
            print(f"  WARNING: {failure}", file=sys.stderr)
        elif not found and notes is not None and name:
            notes.append(("vss", f"no shadow copies found on {where}"))
        for vss_id, _ in found:
            ctx.vss_sources[vss_id] = name
        results += found
    return results


def _mount_vss_at(
    raw_path: Path, dest: Path, ctx: MountContext, offset: int, prefix: str
) -> tuple[list[tuple[str, Path]], str]:
    """The shadow copies of the NTFS volume `offset` bytes into the image,
    mounted as `<prefix>-vssN` (`vssN` with no prefix), and why they
    couldn't be read ("" when they could, or there are none)."""
    at = ["-o", str(offset)] if offset else []
    try:
        result = subprocess.run(
            ["vshadowinfo", *at, str(raw_path)],
            capture_output=True,
            text=True,
        )
    except OSError as e:
        return [], f"vshadowinfo didn't run ({e.strerror or e})"
    if result.returncode != 0:
        said = (result.stdout + result.stderr).strip()
        if "No Volume Shadow Snapshots found" in said:
            return [], ""
        return [], said.splitlines()[-1] if said else f"vshadowinfo exit {result.returncode}"

    # Parse number of stores
    num_stores = 0
    for line in result.stdout.splitlines():
        m = re.match(r"Number of stores:\s*(\d+)", line.strip())
        if m:
            num_stores = int(m.group(1))
            break
    if num_stores == 0:
        return [], ""

    # Mount all stores via vshadowmount
    tag = f"{prefix}-" if prefix else ""
    vss_mount = dest / f"_{tag}vss"
    vss_mount.mkdir()
    try:
        subprocess.run(
            ["vshadowmount", *at, str(raw_path), str(vss_mount)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        vss_mount.rmdir()
        why = (e.stderr or b"").decode(errors="replace").strip().splitlines()[-1:]
        return [], f"vshadowmount failed: {why[0] if why else f'exit {e.returncode}'}"
    ctx.add_fuse(vss_mount)

    # Mount each vssN file as a filesystem
    results = []
    for i in range(1, num_stores + 1):
        vss_file = vss_mount / f"vss{i}"
        if not vss_file.exists():
            continue
        vss_id = f"{tag}vss{i}"
        vss_mp = dest / vss_id
        vss_mp.mkdir()
        try:
            subprocess.run(
                [
                    "sudo",
                    "mount",
                    "-o",
                    "ro,loop,noexec",
                    str(vss_file),
                    str(vss_mp),
                ],
                check=True,
                capture_output=True,
            )
            ctx.add_mount(vss_mp)
            results.append((vss_id, vss_mp))
        except subprocess.CalledProcessError:
            vss_mp.rmdir()

    return results, "" if results else f"none of its {num_stores} stores mounted"


# ---------------------------------------------------------------------------
# Velociraptor offline collector
# ---------------------------------------------------------------------------


def is_velociraptor_collection(extract_dir: Path) -> bool:
    """Check if extracted directory is a Velociraptor offline collector."""
    return (extract_dir / "uploads" / "auto").is_dir()


def normalize_velociraptor(extract_dir: Path) -> Path:
    """Normalize Velociraptor offline collector directory structure.

    URL-decodes all path names under uploads/auto/ (e.g., C%3A → C:).
    Returns the auto/ directory for volume root scanning.
    """
    auto_dir = extract_dir / "uploads" / "auto"
    if not auto_dir.is_dir():
        raise ValueError("Not a Velociraptor offline collector (no uploads/auto/)")

    # URL-decode all directory and file names (bottom-up to avoid
    # renaming parents before children).
    for path in sorted(auto_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        decoded = urllib.parse.unquote(path.name)
        if decoded != path.name:
            # Validate decoded name doesn't contain path separators or traversal
            if "/" in decoded or "\\" in decoded or ".." in decoded:
                continue
            new_path = path.parent / decoded
            path.rename(new_path)
            print(f"  Renamed {path.name} -> {decoded}")

    return auto_dir


def read_velociraptor_hostname(extract_dir: Path) -> str | None:
    """Read hostname from Velociraptor collection_context.json."""
    ctx_file = extract_dir / "collection_context.json"
    if not ctx_file.exists():
        return None
    try:
        ctx = json.loads(ctx_file.read_text())
        client = ctx.get("client_info", {})
        return client.get("fqdn") or client.get("hostname")
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Temp directory management
# ---------------------------------------------------------------------------


def make_ingest_tmpdir(case_id: str) -> Path:
    """Create a temp directory for container extraction under the case dir."""
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    from opensearch_mcp.paths import vhir_dir

    case_dir = vhir_dir() / "cases" / case_id
    import os

    tmp = case_dir / "tmp" / f"ingest-{ts}-{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


def cleanup_orphaned_mounts() -> None:
    """Clean up orphaned nbd connections from prior failed ingests.

    Skips cleanup if another ingest is currently running -- avoids
    disconnecting devices held by a concurrent process (B18).

    A device is this user's orphan only when every mount of it is under
    this user's own ingest temp dirs (<vhir>/cases/<case>/tmp/ingest-<ts>-<pid>/)
    and that pid is no longer running. A device mounted anywhere else, not
    mounted at all, or mounted by a live ingest is left alone.

    NOTE: TOCTOU race between reading the mount table and disconnecting.
    Two cleaners started together can act on the same snapshot of an
    orphan, and a new ingest can take the device between the check and the
    disconnect. A full fix needs file-level locking around nbd operations.
    Current risk is low (cleanup only runs at ingest start).
    """
    import sys

    from opensearch_mcp.ingest_status import _is_process_alive, read_active_ingests
    from opensearch_mcp.paths import vhir_dir

    try:
        active = read_active_ingests()
        if any(ing.get("status") == "running" for ing in active):
            return
    except Exception:
        pass

    own = re.compile(
        re.escape(str((vhir_dir() / "cases").resolve()))
        + r"/[^/]+/tmp/ingest-\d{8}T\d{6}-(\d+)/[^/]+"
    )
    try:
        table = Path("/proc/self/mounts").read_text(errors="surrogateescape").splitlines()
    except OSError:
        return

    def _unescape(field: str) -> str:  # the kernel writes " " as \040, etc.
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)

    mounts = [[_unescape(f) for f in line.split()[:2]] for line in table if len(line.split()) > 1]

    for i in range(8):
        size_path = Path(f"/sys/block/nbd{i}/size")
        if size_path.exists():
            try:
                size = int(size_path.read_text().strip())
            except (OSError, ValueError):
                continue
            if size > 0:
                dev = f"/dev/nbd{i}"
                points = [mp for src, mp in mounts if re.fullmatch(rf"{dev}(p\d+)?", src)]
                owners = [own.fullmatch(mp) for mp in points]
                if (
                    not points
                    or not all(owners)
                    or any(_is_process_alive(int(m.group(1)), "") for m in owners)
                ):
                    continue
                for mp in points:
                    subprocess.run(["sudo", "umount", mp], capture_output=True)
                subprocess.run(["sudo", "qemu-nbd", "-d", dev], capture_output=True)
                print(f"  Cleaned orphaned nbd: {dev}", file=sys.stderr)


def cleanup_tmpdir(tmpdir: Path, force: bool = False) -> None:
    """Clean up temp directory. On failure, preserve with warning."""
    try:
        shutil.rmtree(tmpdir)
    except OSError as e:
        if force:
            raise
        import sys

        print(
            f"WARNING: Could not remove temp dir {tmpdir}: {e}\n"
            "  Extracted evidence preserved for re-processing.",
            file=sys.stderr,
        )

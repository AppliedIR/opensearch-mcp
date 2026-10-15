"""Container handling: archive extraction and disk image mounting."""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import shlex
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


def extraction_command(path: Path, dest: Path) -> list[str]:
    """The command extract_container runs for `path` (never the password:
    7z reads it on stdin)."""
    suffix = path.suffix.lower()
    if suffix in (".zip", ".7z"):
        return ["7z", "x", str(path), f"-o{dest}", "-y"]
    return ["tar", "xf", str(path), "-C", str(dest)]


def _extract_7z(path: Path, dest: Path, password: str | None = None) -> None:
    """Extract archive with 7z."""
    cmd = extraction_command(path, dest)
    result = subprocess.run(cmd, capture_output=True, **seven_zip_password(password))
    # 7z exit codes: 0=ok, 1=warning (timestamps), 2+=error
    if result.returncode > 1:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)


def seven_zip_password(password: str | None) -> dict:
    """subprocess.run arguments giving 7z the archive password on its stdin,
    never on its command line (any local user can read that). 7z asks for it
    on its terminal when it has one: in a new session it has none, and reads
    stdin. With no password, stdin is empty, so a prompt fails at once."""
    if password:
        return {"input": f"{password}\n".encode(), "start_new_session": True}
    return {"stdin": subprocess.DEVNULL, "start_new_session": True}


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
        self.failed_offsets: dict[int, str] = {}  # the same, by byte offset
        self.not_mounted: list[str] = []  # partitions left unmounted on purpose (LVM)
        self.offsets: dict[Path, int] = {}  # mount point -> byte offset in the image
        self.vss_sources: dict[str, str] = {}  # shadow copy id -> the volume it came from
        self.audit = None  # the run's writer, which recorded the mounts
        self.recorded: dict[str, object] = {}  # recorded mount point realpath -> mnt_id
        self.streams: dict[str, Path] = {}  # an E01's raw stream (ewfmount's ewf1) -> the E01
        self.extracted = False  # the volumes are folders extracted without NBD, not mounts

    def record(self, image, points: list[dict], tool: str = "mount_image") -> None:
        """Record a mount (the run's writer), and remember its points, whose
        unmounts cleanup records."""
        from opensearch_mcp import ops

        run = ops.current_run()
        if run is None or not points:
            return
        if ops.mount_step(image, points, tool):
            self.audit = run[0]
            for p in points:
                self.recorded[p["realpath"]] = p["mnt_id"]

    def _unmounted(self, mp: Path, identity: tuple | None) -> None:
        """Record the unmount of a recorded point, by what was read before it."""
        if identity is not None and self.audit is not None:
            from opensearch_mcp import ops

            ops.umount_entry(self.audit, *identity)

    def _identity(self, mp: Path) -> tuple | None:
        real = os.path.realpath(mp)
        return (real, self.recorded[real]) if real in self.recorded else None

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
            identity = self._identity(mp)  # read before it unmounts
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
                self._unmounted(mp, identity)
        for mp in reversed(list(self._fuse_mounts)):
            identity = self._identity(mp)
            result = subprocess.run(["fusermount", "-u", str(mp)], capture_output=True)
            if result.returncode != 0:
                logger.warning(
                    "fusermount -u %s failed: %s",
                    mp,
                    result.stderr.decode(errors="replace").strip(),
                )
            else:
                self._fuse_mounts.remove(mp)
                self._unmounted(mp, identity)
        for dev in list(self._nbd_devices):
            result = subprocess.run(["sudo", "qemu-nbd", "-d", dev], capture_output=True)
            if result.returncode == 0:
                self._nbd_devices.remove(dev)
        for dev in list(self._loop_devices):
            result = subprocess.run(["sudo", "losetup", "-d", dev], capture_output=True)
            if result.returncode == 0:
                self._loop_devices.remove(dev)


# what to do when sudo asks for a password: an examiner's own mount is gated
# like any folder, so it passes only once registered from inside the case
SUDO_REMEDY = (
    "Mounting a disk image needs sudo without a password for the user the gateway "
    "runs as. Or mount the image yourself (read-only), link the mount into the case's "
    "evidence/ folder, register that link as evidence, and ingest the mounted folder."
)


def check_sudo() -> None:
    """Verify non-interactive sudo is available."""
    result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if result.returncode != 0:
        raise PermissionError(SUDO_REMEDY)


def mount_image(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount a disk image read-only. Returns list of mounted volume paths.

    The mount is recorded under the open run: the image (by the registry when
    registered) and each volume's mount point, with its st_dev, mount id and
    byte offset; cleanup records each point's unmount."""
    suffix = path.suffix.lower()
    if suffix in (".e01", ".ex01"):
        volumes = _mount_ewf(path, dest, ctx)
    elif suffix in (".dd", ".raw", ".img", ".iso"):
        volumes = _mount_raw(path, dest, ctx)
    elif suffix == ".vhdx":
        try:
            volumes = _mount_nbd(path, dest, ctx)
            why = "no volume mounted"
        except (PermissionError, RuntimeError, subprocess.CalledProcessError, OSError) as e:
            volumes, why = [], str(e).splitlines()[0] if str(e) else type(e).__name__
        if not volumes:  # no sudo or no free NBD device: read it without either
            ctx.cleanup()  # a device attached with nothing mounted is detached first
            print(f"  {path.name}: {why}; {NO_NBD_NOTE}", file=sys.stderr, flush=True)
            volumes = _extract_disk_image(path, dest, ctx)
            ctx.extracted = True
            ctx.not_mounted.append(f"{path.name}: {NO_NBD_NOTE}")
            return volumes  # recorded as an extraction: nothing was mounted
    elif suffix in (".vmdk", ".vhd"):
        volumes = _mount_nbd(path, dest, ctx)
    else:
        raise ValueError(f"Unknown disk image format: {path.name}")
    from opensearch_mcp import ops

    ctx.record(path, [ops.mount_point(v, ctx.offsets.get(v)) for v in volumes])
    return volumes


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
    ctx.streams[str(raw_path)] = path
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
                ctx.failed_offsets[offset] = failure
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


# The format each disk image is opened as, from its name: never probed from
# its content (a VMDK description named .vhdx would make qemu read the files
# it names).
IMAGE_FORMATS = {".vhdx": "vhdx", ".vhd": "vpc", ".vmdk": "vmdk"}


def _mount_nbd(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount VMDK/VHD/VHDX via qemu-nbd, in the format its name says."""
    fmt = IMAGE_FORMATS[path.suffix.lower()]
    check_sudo()
    subprocess.run(
        ["sudo", "modprobe", "nbd", "max_part=8"],
        capture_output=True,
    )
    nbd_dev = _find_free_nbd()
    subprocess.run(
        ["sudo", "qemu-nbd", "-r", "-f", fmt, "-c", nbd_dev, str(path)],
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


NO_NBD_NOTE = (
    "mounted without NBD: extracted with qemu-img + TSK (no sudo); shadow copies not read"
)


def _tool(cmd: list[str], package: str, **kw) -> subprocess.CompletedProcess:
    """Run a tool the extraction needs; its package named when it is missing."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, **kw)
    except FileNotFoundError:
        raise RuntimeError(f"{cmd[0]} not found: install {package}") from None


def _partition_starts(raw: Path) -> tuple[list[tuple[int, int]], list[str]]:
    """``[(start sector, sector size)]`` of each allocated partition mmls lists,
    and the command; one volume at 0 when there is no partition table."""
    cmd = ["mmls", "-a", str(raw)]
    result = _tool(cmd, "sleuthkit")
    sector_size = 512
    starts = []
    for line in result.stdout.splitlines():
        m = re.match(r"Units are in (\d+)-byte sectors", line)
        if m:
            sector_size = int(m.group(1))
        m = re.match(r"\d+:\s+\S+\s+(\d+)\s+\d+\s+\d+\s", line)
        if m:
            starts.append((int(m.group(1)), sector_size))
    return (starts if result.returncode == 0 else []) or [(0, 512)], cmd


def _set_ntfs_end_marker(raw: Path, offset: int) -> bool:
    """Write 55 AA at bytes 510-511 of the volume's boot sector in the derived
    raw when its OEM is NTFS and the marker isn't there: TSK refuses NTFS
    without it, and some collections write it as 00 00. True when written."""
    with open(raw, "r+b") as f:
        f.seek(offset)
        boot = f.read(512)
        if len(boot) < 512 or boot[3:11] != b"NTFS    " or boot[510:512] == b"\x55\xaa":
            return False
        f.seek(offset + 510)
        f.write(b"\x55\xaa")
    return True


def _extract_disk_image(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """A .vhdx read without sudo or NBD: converted to a derived raw by
    qemu-img (the format fixed, never probed), then each partition's allocated
    files written out by tsk_recover into its own folder, ``_x/vol<N>``.

    tsk_recover writes names as the image holds them, so it runs in bwrap
    where only that folder is writable: a crafted name can't write outside
    it. The write it refuses prints an Error line while the exit code stays
    0, so any Error line, or a non-zero exit after something was written,
    refuses the image. A partition TSK can't read at all is a failure, as a
    partition that doesn't mount is. The raw is deleted whatever happens.

    Recorded under the open run before any file is used, as one extraction
    of the image (by its input entry, as a mount records it) with every file
    hashed. No run open, or the entry not written, refuses the image."""
    from opensearch_mcp import ops

    run = ops.current_run()
    if run is None:
        raise RuntimeError(f"{path.name}: no ingest run is open to record its extraction")
    raw_dir, out = dest / "_raw", dest / "_x"
    raw = raw_dir / "disk.raw"
    raw_dir.mkdir()  # never an existing folder: it is removed after
    try:
        convert = ["qemu-img", "convert", "-f", IMAGE_FORMATS[".vhdx"], "-O", "raw", str(path)]
        convert.append(str(raw))
        result = _tool(convert, "qemu-utils")
        if result.returncode != 0:
            raise RuntimeError(f"{path.name}: qemu-img could not read it: {result.stderr.strip()}")
        starts, mmls = _partition_starts(raw)
        commands, volumes, folders = [convert, mmls], [], []
        out.mkdir()
        for n, (start, sector_size) in enumerate(starts, 1):
            offset = start * sector_size
            marker = _set_ntfs_end_marker(raw, offset)
            vol = out / f"vol{n}"
            vol.mkdir()
            cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--bind", str(vol), str(vol),
                   "--unshare-all", "--die-with-parent", "--new-session",
                   "tsk_recover", "-a", "-o", str(start), "-b", str(sector_size), str(raw),
                   str(vol)]  # fmt: skip
            commands.append(cmd)
            result = _tool(cmd, "bubblewrap", stdin=subprocess.DEVNULL)
            lines = result.stderr.splitlines()
            refused = [ln for ln in lines if ln.startswith(("Error", "bwrap:"))]
            if refused or (result.returncode != 0 and any(vol.iterdir())):
                shown = ", ".join(repr(ln) for ln in (refused or lines)[:3])
                raise RuntimeError(
                    f"{path.name}: refused: tsk_recover at offset {offset} (exit "
                    f"{result.returncode}): {shown or 'no message'}"
                )
            if result.returncode != 0:  # nothing written: TSK can't read this partition
                vol.rmdir()
                why = lines[0] if lines else f"tsk_recover exit {result.returncode}"
                failure = f"partition at offset {offset} could not be read: {why}"
                ctx.failures.append(failure)
                ctx.failed_offsets[offset] = failure
                print(f"  WARNING: {failure}", file=sys.stderr)
                continue
            volumes.append({"offset": offset, "end_marker_set": marker})
            folders.append(vol)
            ctx.offsets[vol] = offset
    finally:
        shutil.rmtree(raw_dir, ignore_errors=True)
    audit, case_dir = run
    params = {"method": "qemu-img+tsk_recover", "volumes": volumes}
    try:
        ops.extraction_step(audit, case_dir, path, out, [shlex.join(c) for c in commands], params,
                            input_entry=ops.image_input(case_dir, path))  # fmt: skip
    except ops.NoEntry as e:
        raise RuntimeError(f"{path.name}: its extraction was not recorded: {e}") from None
    return folders


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
    stores: list[tuple] = []
    for name, offset in sorted(volumes.items(), key=lambda v: v[1]):
        found, unread, partial = _mount_vss_at(
            raw_path, dest, ctx, offset, name if len(volumes) > 1 else ""
        )
        where = f"{name} (offset {offset})" if name else "the image"
        if unread:  # tried and not read: unprocessed, never "none"
            failure = f"shadow copies on {where} couldn't be read: {unread}"
            ctx.failures.append(failure)
            print(f"  WARNING: {failure}", file=sys.stderr)
        elif partial:  # some read, some not: say how many weren't
            failure = partial.format(where=where)
            ctx.failures.append(failure)
            print(f"  WARNING: {failure}", file=sys.stderr)
        elif not found and notes is not None and name:
            notes.append(("vss", f"no shadow copies found on {where}"))
        for vss_id, _ in found:
            ctx.vss_sources[vss_id] = name
        results += found
        stores += [(vss_id, path, offset) for vss_id, path in found]
    from opensearch_mcp import ops

    # one point per store, with the volume's offset and the store's id; an
    # E01's stores are read from its raw stream, so the E01 is their input, as
    # it is its volumes' (mount_image)
    image = ctx.streams.get(str(raw_path), raw_path)
    ctx.record(image, [ops.mount_point(p, off, store=v) for v, p, off in stores], "mount_vss")
    return results


def _mount_vss_at(
    raw_path: Path, dest: Path, ctx: MountContext, offset: int, prefix: str
) -> tuple[list[tuple[str, Path]], str, str]:
    """The shadow copies of the NTFS volume `offset` bytes into the image,
    mounted as `<prefix>-vssN` (`vssN` with no prefix); why none could be read
    ("" when some could, or there are none); and, when only some could, a
    note naming how many couldn't and why, with `{where}` for the volume."""
    at = ["-o", str(offset)] if offset else []
    try:
        result = subprocess.run(
            ["vshadowinfo", *at, str(raw_path)],
            capture_output=True,
            text=True,
        )
    except OSError as e:
        return [], f"vshadowinfo didn't run ({e.strerror or e})", ""
    if result.returncode != 0:
        said = (result.stdout + result.stderr).strip()
        if "No Volume Shadow Snapshots found" in said:
            return [], "", ""
        return [], said.splitlines()[-1] if said else f"vshadowinfo exit {result.returncode}", ""

    # Parse number of stores
    num_stores = 0
    for line in result.stdout.splitlines():
        m = re.match(r"Number of stores:\s*(\d+)", line.strip())
        if m:
            num_stores = int(m.group(1))
            break
    if num_stores == 0:
        return [], "", ""

    # Mount all stores via vshadowmount
    tag = f"{prefix}-" if prefix else ""
    vss_mount = dest / f"_{tag}vss"
    vss_mount.mkdir()
    # Mounted by root so root's loop mount of each vssN can read it, as
    # _mount_ewf does; allow_other keeps it readable by the examiner
    try:
        subprocess.run(
            ["sudo", "vshadowmount", "-X", "allow_other", *at, str(raw_path), str(vss_mount)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        vss_mount.rmdir()
        why = (e.stderr or b"").decode(errors="replace").strip().splitlines()[-1:]
        return [], f"vshadowmount failed: {why[0] if why else f'exit {e.returncode}'}", ""
    ctx.add_mount(vss_mount)  # root's mount: unmounted by root, after its stores

    # Mount each vssN file as a filesystem
    results = []
    failed: dict[str, list[str]] = {}  # why -> the stores that didn't mount
    for i in range(1, num_stores + 1):
        vss_file = vss_mount / f"vss{i}"
        if not vss_file.exists():
            failed.setdefault("not presented by vshadowmount", []).append(f"vss{i}")
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
        except subprocess.CalledProcessError as e:
            vss_mp.rmdir()
            said = (e.stderr or b"").decode(errors="replace").strip().splitlines()[-1:]
            # One reason for every store it applies to: the paths in it are each store's own
            why = said[0] if said else f"mount exit {e.returncode}"
            why = why.replace(str(vss_file), "<store>").replace(str(vss_mp), "<mount point>")
            failed.setdefault(why, []).append(f"vss{i}")

    why = "; ".join(f"{', '.join(stores)}: {reason}" for reason, stores in failed.items())
    if not results:
        return [], f"none of its {num_stores} stores mounted ({why})", ""
    if failed:
        n = sum(len(stores) for stores in failed.values())
        note = f"{n} of {num_stores} shadow copies on {{where}} couldn't be mounted: {why}"
        return results, "", note
    return results, "", ""


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

    # Its own folder, every time: two runs in one process and one second (an
    # archive's images) must never share one, or one run's cleanup takes the
    # other's evidence with it
    (case_dir / "tmp").mkdir(parents=True, exist_ok=True)
    import tempfile

    return Path(tempfile.mkdtemp(prefix=f"ingest-{ts}-{os.getpid()}-", dir=case_dir / "tmp"))


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

    from opensearch_mcp.ingest_status import _is_process_alive, active_runs
    from opensearch_mcp.paths import vhir_dir

    try:
        if active_runs():  # a run that waits for its hosts holds its devices too
            return
    except Exception:
        pass

    own = re.compile(
        re.escape(str((vhir_dir() / "cases").resolve()))
        + r"/[^/]+/tmp/ingest-\d{8}T\d{6}-(\d+)(?:-[^/]+)?/[^/]+"  # mkdtemp's suffix
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

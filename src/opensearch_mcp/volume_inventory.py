"""List a disk image's volumes for Plaso: run by Plaso's own interpreter.

Not imported by opensearch-mcp: it needs dfVFS, which the product's venv
doesn't have. ingest runs it as `<plaso python> -I volume_inventory.py
<image>` and reads one JSON line per leaf volume:

  {"selector": {"partitions": "p2", "volumes": "lvm1"}, "offset": 3145728,
   "kind": "filesystem" | "locked" | "no_filesystem", "fs": "EXT",
   "os": "windows" | "macos" | "linux", "zone": "America/New_York",
   "localtime": "link" | "file"}

The OS is checked Windows, then macOS, then Linux, as Plaso does, so a
Windows tree that also has an etc folder is Windows. The zone is the
etc/localtime link's target after zoneinfo/; "file" means it is a copy,
which Plaso can't map to a zone name. Volume-system entries with no
location (an MBR's meta nodes) are left out.
"""

import json
import sys

from dfvfs.helpers import source_scanner
from dfvfs.lib import definitions as dd
from dfvfs.path import factory as path_factory
from dfvfs.resolver import resolver
from dfvfs.volume import factory as volume_factory

_SELECTOR = {
    dd.TYPE_INDICATOR_GPT: "partitions",
    dd.TYPE_INDICATOR_TSK_PARTITION: "partitions",
    dd.TYPE_INDICATOR_APM: "partitions",
    dd.TYPE_INDICATOR_LVM: "volumes",
    dd.TYPE_INDICATOR_APFS_CONTAINER: "volumes",
}
_OFFSET_SYSTEMS = (dd.TYPE_INDICATOR_GPT, dd.TYPE_INDICATOR_TSK_PARTITION)


def _entry(base, location):
    try:
        spec = path_factory.Factory.NewPathSpec(
            base.type_indicator, location=location, parent=base.parent
        )
        return resolver.Resolver.OpenFileEntry(spec)
    except Exception:
        return None


def _os_and_zone(base) -> dict:
    out = {}
    for os_name, marker in (
        ("windows", "/Windows/System32"),
        ("macos", "/System/Library"),
        ("linux", "/etc"),
    ):
        if _entry(base, marker) is not None:
            out["os"] = os_name
            break
    if out.get("os") in ("macos", "linux"):
        for location in ("/etc/localtime", "/private/etc/localtime"):
            fe = _entry(base, location)
            if fe is None:
                continue
            if fe.IsLink():
                out["localtime"] = "link"
                zone = (fe.link or "").partition("zoneinfo/")[2]
                if zone:
                    out["zone"] = zone
            else:
                out["localtime"] = "file"
            break
    return out


def _walk(context, node, selector, offset, out):
    kind = node.type_indicator
    location = getattr(node.path_spec, "location", None)
    if kind in _SELECTOR and location not in (None, "/"):
        selector = {**selector, _SELECTOR[kind]: location.lstrip("/")}
    if context.IsLockedScanNode(node.path_spec):
        out.append({"selector": selector, "offset": offset, "kind": "locked", "type": kind})
        return
    if kind in dd.FILE_SYSTEM_TYPE_INDICATORS:
        leaf = {"selector": selector, "offset": offset, "kind": "filesystem", "fs": kind}
        leaf.update(_os_and_zone(node.path_spec))
        out.append(leaf)
        return
    if not node.sub_nodes:
        meta = kind in _SELECTOR and location in (None, "/")  # an MBR's meta entries
        if kind != dd.TYPE_INDICATOR_OS and not meta:
            leaf = {"selector": selector, "offset": offset, "kind": "no_filesystem", "type": kind}
            out.append(leaf)
        return
    for child in node.sub_nodes:
        child_offset = offset
        child_location = getattr(child.path_spec, "location", None)
        if child.type_indicator in _OFFSET_SYSTEMS and child_location not in (None, "/"):
            try:
                parent = child.path_spec.parent
                system = volume_factory.Factory.NewVolumeSystem(child.type_indicator)
                system.Open(
                    parent if parent.type_indicator == child.type_indicator else child.path_spec
                )
                volume = system.GetVolumeByIdentifier(child_location.lstrip("/"))
                if volume and volume.extents:
                    child_offset = volume.extents[0].offset
            except Exception:
                pass
        _walk(context, child, selector, child_offset, out)


def main() -> None:
    context = source_scanner.SourceScannerContext()
    scanner = source_scanner.SourceScanner()
    context.OpenSourcePath(sys.argv[1])
    scanner.Scan(context)

    def descend(node):  # scan inside every partition, LV and APFS volume
        containers = (dd.TYPE_INDICATOR_RAW, dd.TYPE_INDICATOR_EWF, dd.TYPE_INDICATOR_MODI)
        if node.type_indicator in _SELECTOR or node.type_indicator in containers:
            for child in list(node.sub_nodes):
                if (
                    not child.sub_nodes
                    and not context.IsLockedScanNode(child.path_spec)
                    and child.type_indicator not in dd.FILE_SYSTEM_TYPE_INDICATORS
                ):
                    try:
                        scanner.Scan(context, scan_path_spec=child.path_spec)
                    except Exception:
                        pass
                descend(child)

    descend(context.GetRootScanNode())
    out: list = []
    _walk(context, context.GetRootScanNode(), {}, 0, out)
    for leaf in out:
        print(json.dumps(leaf))


if __name__ == "__main__":
    main()

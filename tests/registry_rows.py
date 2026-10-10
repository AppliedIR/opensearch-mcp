"""Register files in a case's evidence registry, as `vhir evidence register`
records them ({path, sha256}): an ingest only reads registered evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def register(case_dir, *paths) -> None:
    reg = Path(case_dir) / "evidence.json"
    data = json.loads(reg.read_text()) if reg.exists() else {"files": []}
    for p in paths:
        sha = hashlib.sha256(Path(p).read_bytes()).hexdigest()
        data["files"].append({"path": os.path.realpath(p), "sha256": sha})
    reg.write_text(json.dumps(data))


def register_tree(case_dir, root) -> None:
    """Register each regular file under `root` not registered yet: a folder
    given to an ingest is read only when every file in it is evidence."""
    reg = Path(case_dir) / "evidence.json"
    data = json.loads(reg.read_text()) if reg.exists() else {"files": []}
    done = {r.get("path") for r in data["files"]}
    for top, _, names in os.walk(root):
        for n in sorted(names):
            p = os.path.join(top, n)
            if os.path.isfile(p) and not os.path.islink(p) and os.path.realpath(p) not in done:
                register(case_dir, p)

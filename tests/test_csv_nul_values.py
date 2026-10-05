"""A NUL character inside an EZ-tool CSV value is kept and indexed with its row.

Python 3.10's csv module stops at the first NUL ("line contains NUL"), and
that failed the whole artifact; 3.11 and later read the row and keep the NUL.
These rows hold on every version. All data is synthetic.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from opensearch_mcp.parse_csv import ingest_csv
from opensearch_mcp.tools import run_and_ingest

DATA = (
    "KeyName,ValueData,ValueData2\r\n"
    'k1,"Disk Device\x00 Di",plain\r\n'
    'k2,ab\x00cd,"x\r\ny\x00z"\r\n'
    "k3,ok,ok\r\n"
    "k4,a,b,ex\x00tra,more\x00x\r\n"
    "k5,two\x00nul\x00s,ok\r\n"
)
EXPECTED = [
    {"KeyName": "k1", "ValueData": "Disk Device\x00 Di", "ValueData2": "plain"},
    {"KeyName": "k2", "ValueData": "ab\x00cd", "ValueData2": "x\ny\x00z"},
    {"KeyName": "k3", "ValueData": "ok", "ValueData2": "ok"},
    {"KeyName": "k4", "ValueData": "a", "ValueData2": "b", None: ["ex\x00tra", "more\x00x"]},
    {"KeyName": "k5", "ValueData": "two\x00nul\x00s", "ValueData2": "ok"},
]
COLS = ("KeyName", "ValueData", "ValueData2")


def _capture():
    sent = []

    def fake_flush(client, actions):
        sent.extend(a["_source"] for a in actions)
        return len(actions), 0

    return sent, patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=fake_flush)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_a_nul_inside_a_field_is_indexed_with_the_rest_of_the_row(tmp_path, encoding):
    path = tmp_path / "out.csv"
    path.write_bytes(DATA.encode(encoding))
    sent, p = _capture()
    with p:
        count, _, _ = ingest_csv(
            csv_path=path, client=MagicMock(), index_name="case-t-registry-h", hostname="h"
        )
    assert count == 5
    assert [{k: s[k] for k in s if k in COLS or k is None} for s in sent] == EXPECTED


def test_a_nul_in_the_header_names_the_column_as_written(tmp_path):
    path = tmp_path / "out.csv"
    path.write_text("Ke\x00y,V\nk,v\n", encoding="utf-8")
    sent, p = _capture()
    with p:
        ingest_csv(csv_path=path, client=MagicMock(), index_name="case-t-x-h", hostname="h")
    assert sent[0]["Ke\x00y"] == "k"


def test_a_nul_row_in_one_tool_csv_does_not_drop_the_others(tmp_path):
    def fake_run(cmd, label):
        out = Path(cmd[cmd.index("--csv") + 1])
        (out / "20260101000000_Amcache_DeviceContainers.csv").write_text(
            "KeyName,PrimaryCategory\na,one\nb,\x0e\x18\x00\x16\n", encoding="utf-8"
        )
        (out / "20260101000000_Amcache_DriveBinaries.csv").write_text(
            "KeyName,DriverName\nc,x.sys\nd,y.sys\ne,z.sys\n", encoding="utf-8"
        )
        return "", ""

    sent, p = _capture()
    with p, patch("opensearch_mcp.tools._run_tool", side_effect=fake_run):
        count, _, _ = run_and_ingest(
            tool_name="amcache",
            artifact_path=tmp_path / "Amcache.hve",
            client=MagicMock(),
            case_id="t",
            hostname="h",
        )
    assert count == 5
    assert sorted(s["KeyName"] for s in sent) == ["a", "b", "c", "d", "e"]
    assert next(s for s in sent if s["KeyName"] == "b")["PrimaryCategory"] == "\x0e\x18\x00\x16"

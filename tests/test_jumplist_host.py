"""Jumplist docs are attributed to the scanned host; the tracker host stays in its own column."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from opensearch_mcp.tools import run_and_ingest

CSV = (
    "SourceFile,AppId,Hostname,MachineID,Path,LastModified\n"
    "C:\\Users\\u\\a.automaticDestinations-ms,abc,fileserver,fileserver,"
    "S:\\share\\a.docx,2023-01-12 10:00:00\n"
    "C:\\Users\\u\\b.automaticDestinations-ms,abc,,,C:\\b.txt,2023-01-12 11:00:00\n"
    "C:\\Users\\u\\c.automaticDestinations-ms,abc,wkstn,wkstn,C:\\c.txt,2023-01-12 12:00:00\n"
)
# The _id values these three rows had before (case "t", scan host "wkstn", no host
# dictionary): a re-ingest must overwrite the same documents.
GOLDEN = {
    "S:\\share\\a.docx": "1c45cabd3c5f3a6a4bd1",
    "C:\\b.txt": "76efa9b3e610c1802417",
    "C:\\c.txt": "37cca10bacfec74c2e25",
}


def _ingest(tool="jumplists"):
    sent = []

    def fake_flush(client, actions):
        sent.extend(actions)
        return len(actions), 0

    def fake_run(cmd, label):
        out = Path(cmd[cmd.index("--csv") + 1])
        (out / "20260101000000_AutomaticDestinations.csv").write_text(CSV, encoding="utf-8")
        return "", ""

    with (
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=fake_flush),
        patch("opensearch_mcp.tools._run_tool", side_effect=fake_run),
    ):
        run_and_ingest(
            tool_name=tool,
            artifact_path=Path("/nonexistent"),
            client=MagicMock(),
            case_id="t",
            hostname="wkstn",
        )
    return {a["_source"]["Path"]: a for a in sent}


def test_jumplist_rows_take_the_scanned_host_not_the_tracker_host():
    docs = _ingest()
    assert {p: (a["_source"]["host.name"], a["_source"]["host.id"]) for p, a in docs.items()} == {
        p: ("wkstn", "wkstn") for p in docs
    }


def test_jumplist_rows_keep_the_tracker_hostname_column():
    docs = _ingest()
    assert docs["S:\\share\\a.docx"]["_source"]["Hostname"] == "fileserver"
    assert docs["S:\\share\\a.docx"]["_source"]["MachineID"] == "fileserver"


def test_jumplist_doc_ids_are_unchanged_so_reingest_overwrites():
    docs = _ingest()
    assert {p: a["_id"] for p, a in docs.items()} == GOLDEN


def test_the_csv_subcommand_also_takes_the_scanned_host_for_jumplists(tmp_path):
    import argparse

    from opensearch_mcp import ingest_cli as cli

    csv_path = tmp_path / "20260101000000_AutomaticDestinations.csv"
    csv_path.write_text(CSV, encoding="utf-8")
    sent = []

    def fake_flush(client, actions):
        sent.extend(actions)
        return len(actions), 0

    with (
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=fake_flush),
        patch.object(cli, "_resolve_case_id", return_value="t"),
        patch.object(cli, "get_client", return_value=MagicMock()),
        patch.object(cli, "AuditWriter", MagicMock()),
        patch.object(cli, "_load_case_host_dict", return_value=None),
    ):
        cli.cmd_csv(
            argparse.Namespace(
                tool_name="jumplists", csv_path=str(csv_path), hostname="wkstn", case=None
            )
        )
    assert {a["_source"]["host.name"] for a in sent} == {"wkstn"}
    assert {a["_source"]["Path"]: a["_id"] for a in sent} == GOLDEN

"""Jumplist docs are attributed to the scanned host; the tracker host stays in its own column."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from opensearch_mcp import write_context as wc
from opensearch_mcp.tools import run_and_ingest

CSV = (
    "SourceFile,AppId,Hostname,MachineID,Path,LastModified\n"
    "C:\\Users\\u\\a.automaticDestinations-ms,abc,fileserver,fileserver,"
    "S:\\share\\a.docx,2023-01-12 10:00:00\n"
    "C:\\Users\\u\\b.automaticDestinations-ms,abc,,,C:\\b.txt,2023-01-12 11:00:00\n"
    "C:\\Users\\u\\c.automaticDestinations-ms,abc,wkstn,wkstn,C:\\c.txt,2023-01-12 12:00:00\n"
)


def _ingest(tool="jumplists"):
    sent = []

    def fake_flush(client, actions):
        sent.extend(actions)
        return len(actions), 0

    def fake_run(cmd, label):
        out = Path(cmd[cmd.index("--csv") + 1])
        (out / "20260101000000_AutomaticDestinations.csv").write_text(CSV, encoding="utf-8")
        return "", ""

    ctx = wc.open_unit(wc.case_dir_for("t"), "evidence/wkstn", "wkstn", source="test")
    with (
        patch("opensearch_mcp.parse_csv.flush_bulk", side_effect=fake_flush),
        patch("opensearch_mcp.tools._run_tool", side_effect=fake_run),
        wc.writing(ctx),
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


def _ids(docs):
    return {p: a["_id"] for p, a in docs.items()}


def test_jumplist_doc_ids_are_the_same_on_reingest_so_it_overwrites():
    first = _ids(_ingest())
    assert first == _ids(_ingest()) and len(set(first.values())) == 3


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
    # The csv route keeps its ids (no id source, no 0.6.5 marker), while the
    # scan route's now carry the profile: a jumplist ingested both ways is
    # stored twice, until the csv route gets the same id (a 0.6.5 follow-on).
    assert not any("vhir.id_scheme" in a["_source"] for a in sent)
    scanned = _ids(_ingest())
    csv_ids = {a["_source"]["Path"]: a["_id"] for a in sent}
    assert csv_ids.keys() == scanned.keys()
    assert all(csv_ids[p] != scanned[p] for p in scanned)

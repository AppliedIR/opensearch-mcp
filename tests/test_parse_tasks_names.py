"""Scheduled task files are found by content, not by a name suffix."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opensearch_mcp.parse_tasks import parse_tasks_dir

_TASK = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>EXAMPLE\\user1</Author></RegistrationInfo>
  <Actions Context="Author"><Exec><Command>{cmd}</Command></Exec></Actions>
</Task>
"""


def _write_task(path, cmd):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xff\xfe" + _TASK.format(cmd=cmd).encode("utf-16-le"))


def _run(tasks_dir):
    collected = []

    def capture(client, actions, **kw):
        collected.extend(actions)
        return len(actions), 0

    with patch("opensearch_mcp.parse_tasks.flush_bulk", side_effect=capture):
        cnt, skipped, _ = parse_tasks_dir(tasks_dir, MagicMock(), "t", "h")
    docs = {a["_source"]["task.name"]: a["_source"] for a in collected}
    return cnt, skipped, docs


def test_task_without_dot_is_indexed(tmp_path):
    _write_task(tmp_path / "Tasks" / "Updater", r"C:\a.exe")
    cnt, skipped, docs = _run(tmp_path / "Tasks")
    assert (cnt, skipped) == (1, 0)
    assert docs["Updater"]["task.command"] == r"C:\a.exe"


def test_task_with_dot_in_name_is_indexed(tmp_path):
    _write_task(tmp_path / "Tasks" / "Update.Service", r"C:\ProgramData\upd\svc.exe")
    cnt, skipped, docs = _run(tmp_path / "Tasks")
    assert (cnt, skipped) == (1, 0)
    assert docs["Update.Service"]["task.command"] == r"C:\ProgramData\upd\svc.exe"


def test_task_with_version_number_in_name_is_indexed(tmp_path):
    name = ".NET Framework NGEN v4.0.30319 64"
    _write_task(tmp_path / "Tasks" / "Microsoft" / "Windows" / ".NET Framework" / name, "x")
    cnt, skipped, docs = _run(tmp_path / "Tasks")
    assert (cnt, skipped) == (1, 0)
    assert docs[name]["task.is_system"] is True


def test_file_that_is_not_a_task_is_counted_as_skipped(tmp_path):
    tasks = tmp_path / "Tasks"
    _write_task(tasks / "Updater", "x")
    ini = "[.ShellClassInfo]\r\nLocalizedResourceName=@shell32.dll,-1\r\n"
    (tasks / "desktop.ini").write_bytes(b"\xff\xfe" + ini.encode("utf-16-le"))
    cnt, skipped, docs = _run(tasks)
    assert (cnt, skipped) == (1, 1)
    assert set(docs) == {"Updater"}


def test_xml_file_that_is_not_a_task_is_counted_as_skipped(tmp_path):
    tasks = tmp_path / "Tasks"
    _write_task(tasks / "Updater", "x")
    config = '<?xml version="1.0"?>\n<configuration><appSettings/></configuration>\n'
    (tasks / "settings.config").write_text(config)
    cnt, skipped, docs = _run(tasks)
    assert (cnt, skipped) == (1, 1)
    assert set(docs) == {"Updater"}

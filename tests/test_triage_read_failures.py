"""A triage step that could not read or clear everything says it failed."""

from __future__ import annotations

from opensearchpy.exceptions import ConnectionError as OSConnectionError
from opensearchpy.exceptions import NotFoundError

from opensearch_mcp import triage_remote


def _service_hit(i):
    return {"_id": f"d{i}", "_source": {"Name": "Spooler", "Binary": "C:\\x.exe"}}


def _extract(src):
    return src.get("Name"), src.get("Binary")


class _ScrollClient:
    """Answers the first page, then fails the scroll."""

    def __init__(self, first_error=None):
        self.first_error = first_error
        self.cleared = False

    def search(self, **kwargs):
        if self.first_error:
            raise self.first_error
        return {"_scroll_id": "s1", "hits": {"hits": [_service_hit(i) for i in range(3)]}}

    def scroll(self, **kwargs):
        raise OSConnectionError("N/A", "node left the cluster", None)

    def clear_scroll(self, **kwargs):
        self.cleared = True


def test_a_scroll_that_fails_after_its_first_page_is_failed():
    client = _ScrollClient()
    result = triage_remote._enrich_services(client, "case-x-vol-svcscan-*", {}, _extract, "svc")
    assert result["status"] == "failed"
    assert "not every matching document could be read" in result["reason"]
    assert client.cleared


def test_a_missing_index_is_still_skipped():
    client = _ScrollClient(first_error=NotFoundError(404, "index_not_found_exception", {}))
    result = triage_remote._enrich_services(client, "case-x-vol-svcscan-*", {}, _extract, "svc")
    assert result["status"] == "skipped"


class _Tasks:
    def __init__(self, status):
        self.status = status

    def get(self, **kwargs):
        return self.status


class _ClearClient:
    def __init__(self, status):
        self.tasks = _Tasks(status)

    def update_by_query(self, **kwargs):
        return {"task": "node:1"}


def test_failures_inside_the_clear_task_fail_the_clear():
    status = {
        "completed": True,
        "response": {"updated": 5, "failures": [{"cause": {"reason": "version conflict"}}]},
    }
    result = triage_remote._clear_stamps(_ClearClient(status), "x")
    assert result["status"] == "failed"
    assert "1 documents failed" in result["reason"]


def test_an_error_ending_the_clear_task_fails_the_clear():
    status = {"completed": True, "error": {"reason": "search context missing"}}
    result = triage_remote._clear_stamps(_ClearClient(status), "x")
    assert result["status"] == "failed"
    assert "search context missing" in result["reason"]

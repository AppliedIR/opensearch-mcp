"""The depth pre-check on the json and delimited bulk paths.

OpenSearch rejects a record nesting deeper than `index.mapping.depth.limit`,
but it expands a deep dotted key itself before deciding: 3 s and an HTTP 500
at 1,000 segments, over 60 s at 5,000, and `flush_bulk` then retried the
timeout as if it were transient. `flush_bulk(..., depth_limit=True)` refuses
those records before sending, and only those: the rule below was measured on
OpenSearch 3.5.0 at limits 20 and 5, and agreed with the cluster on all 149
measured shapes (fresh index per record).
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from opensearchpy.exceptions import NotFoundError

from opensearch_mcp import bulk

_MAPPINGS_DIR = Path(__file__).parent.parent / "src" / "opensearch_mcp" / "mappings"


def dotted(n: int, pre: str = "k") -> str:
    return ".".join(f"{pre}{i}" for i in range(1, n + 1))


def nested(n: int, leaf: object, pre: str = "k") -> dict:
    """`n` keys, one object per key, `leaf` under the last."""
    for i in reversed(range(1, n + 1)):
        leaf = {f"{pre}{i}": leaf}
    return leaf


def array_of_objects(n: int, pre: str = "k") -> dict:
    leaf: object = "v"
    for i in reversed(range(1, n + 1)):
        leaf = [{f"{pre}{i}": leaf}]
    return leaf[0]


def half_and_half(n: int, dotted_outer: bool) -> dict:
    keys = [f"k{i}" for i in range(1, n + 1)]
    half = n // 2
    if dotted_outer:
        return {".".join(keys[:half]): nested(n - half, "v", "m")}
    inner = {".".join(f"m{i}" for i in range(1, n - half + 1)): "v"}
    return nested(half, inner)


# (label, record with `n` path segments to a scalar leaf)
SCALAR_FORMS = [
    ("nested", lambda n: nested(n, "v")),
    ("dotted", lambda n: {dotted(n): "v"}),
    ("dotted outside nested", lambda n: half_and_half(n, dotted_outer=True)),
    ("nested outside dotted", lambda n: half_and_half(n, dotted_outer=False)),
    ("array of objects", array_of_objects),
    ("trailing dot", lambda n: {dotted(n) + ".": "v"}),
]


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------


class TestTheRule:
    @pytest.mark.parametrize("limit", [20, 5])
    @pytest.mark.parametrize("label,make", SCALAR_FORMS, ids=[f for f, _ in SCALAR_FORMS])
    def test_a_scalar_is_accepted_up_to_limit_segments(self, label, make, limit):
        assert bulk._too_deep(make(limit), limit) is None
        assert bulk._too_deep(make(limit + 1), limit) is not None

    @pytest.mark.parametrize("limit", [20, 5])
    def test_an_empty_object_counts_one_more(self, limit):
        assert bulk._too_deep(nested(limit - 1, {}), limit) is None
        assert bulk._too_deep(nested(limit, {}), limit) is not None
        assert bulk._too_deep({dotted(limit - 1): {}}, limit) is None
        assert bulk._too_deep({dotted(limit): {}}, limit) is not None

    def test_a_null_under_a_dotted_key_is_accepted_at_any_depth(self):
        """Measured: 201 at 1,500 segments (and 1,000 / 2,000 / 5,000)."""
        assert bulk._too_deep({dotted(1500): None}, 20) is None
        assert bulk._too_deep({"a": {dotted(30): None}}, 20) is None

    def test_a_null_does_not_excuse_the_object_holding_it(self):
        """A nested null's objects are real: 21 of them is rejected."""
        assert bulk._too_deep(nested(20, None), 20) is None
        assert bulk._too_deep(nested(21, None), 20) is not None
        assert bulk._too_deep({dotted(20): {"x": None}}, 20) is not None

    @pytest.mark.parametrize("value", ["", [], [None], False, 0], ids=repr)
    def test_every_non_null_value_expands_its_dotted_key(self, value):
        assert bulk._too_deep({dotted(20): value}, 20) is None
        assert bulk._too_deep({dotted(21): value}, 20) is not None

    def test_arrays_add_nothing(self):
        assert bulk._too_deep({dotted(20): [[]]}, 20) is None
        assert bulk._too_deep({dotted(19): [{"x": "v"}]}, 20) is None
        assert bulk._too_deep({dotted(20): [{"x": "v"}]}, 20) is not None

    def test_an_object_under_a_long_key_is_not_refused(self):
        """UAT's over-refusal check: 15 segments and an object value."""
        assert bulk._too_deep({dotted(15): {"a": {"b": "v"}}}, 20) is None

    def test_the_path_names_the_field(self):
        assert bulk._too_deep({"ok": 1, "a": {dotted(20, "q"): "v"}}, 20) == "a." + dotted(20, "q")

    def test_a_record_nested_far_past_the_limit_is_refused_without_recursing(self):
        """5,000 objects deep — past Python's recursion limit. The walk stops
        at the limit instead of measuring the whole record."""
        record = nested(5000, "v")
        started = time.perf_counter()
        assert bulk._too_deep(record, 20) is not None
        assert time.perf_counter() - started < 1.0

    @pytest.mark.parametrize("segments", [1000, 5000])
    def test_a_long_dotted_key_is_refused_quickly(self, segments):
        started = time.perf_counter()
        assert bulk._too_deep({dotted(segments): "v"}, 20) is not None
        assert time.perf_counter() - started < 1.0


def _seconds(fn) -> float:
    """CPU time of this process: wall time also counts time the machine
    gave to others, which on a loaded runner reads as growth."""
    import gc

    gc.collect()
    started = time.process_time()
    fn()
    return time.process_time() - started


def _peak_mib(fn) -> float:
    import gc
    import tracemalloc

    gc.collect()
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 2**20


def _chain(depth: int, key: str) -> dict:
    """`depth` objects, each under `key` beside a scalar under `key`."""
    record: dict = {key: "v"}
    for _ in range(depth):
        record = {key: record, f"{key}_s": "v"}
    return record


# Each sweep doubles the record at every step. The pairs are where the path
# per child grew as a product: key length x children, depth x key length.
# Width x key length is linear either way and anchors the other two.
COST_SWEEPS = [
    (
        "key length x children",
        lambda s: {"K" * (2_000 * s): {f"c{i}": {} for i in range(20_000 * s)}},
        20,
    ),
    ("depth x key length", lambda s: _chain(5_000 * s, "K" * 100), 1_000_000),
    ("width x key length", lambda s: {f"{'K' * 1_000}{i}": "v" for i in range(5_000 * s)}, 20),
]


class TestTheCheckIsLinear:
    """The check runs on every json and delimited record before anything is
    sent, so its cost bound has to hold on hostile input too."""

    def test_a_1_mb_key_over_1000_empty_objects_peaks_under_5_mib(self):
        record = {"K" * 1_000_000: {f"c{i}": {} for i in range(1_000)}}
        peak = _peak_mib(lambda: bulk._too_deep(record, 20))
        assert peak < 5.0, f"{peak:.1f} MiB"

    def test_a_wide_object_is_walked_one_child_at_a_time(self):
        """The walk holds one frame per level, not one per child: 100,000
        empty objects under one key peak near 0.003 MiB, where a frame for
        every child at once peaks near 12 MiB."""
        record = {"k": {f"c{i}": {} for i in range(100_000)}}
        peak = _peak_mib(lambda: bulk._too_deep(record, 20))
        assert peak < 1.0, f"{peak:.3f} MiB"

    @pytest.mark.parametrize("label,make,limit", COST_SWEEPS, ids=[x[0] for x in COST_SWEEPS])
    def test_memory_per_doubling_and_time_per_quadrupling_stay_linear(self, label, make, limit):
        """Memory by tracemalloc, which is exact. Time is measured in rounds,
        the three sizes back to back, and the ratios within each round are
        compared by their median: on a hybrid CPU the scheduler moves the
        process between core types, and the same loop runs 2.2x slower on
        one (measured on the dev box), so a sweep timed size by size can
        straddle a move and read as growth. Time is compared over the whole
        4x sweep against 8: linear reads 4 and quadratic 16, so either can
        be off by 2x; a single doubling against 2.5 left 1.25x, less than
        one such move.
        """
        import statistics

        records = [make(size) for size in (1, 2, 4)]
        for record in records:
            assert bulk._too_deep(record, limit) is None, "control: nothing refused"

        # With a 0.1 MiB floor: two sweeps peak near 0.001 MiB, where
        # allocator noise alone could break a pure ratio.
        peaks = [_peak_mib(lambda r=r: bulk._too_deep(r, limit)) for r in records]
        for m_a, m_b in zip(peaks, peaks[1:]):
            assert m_b <= 2.5 * m_a + 0.1, f"memory MiB {[round(m, 3) for m in peaks]}"

        rounds = [
            [_seconds(lambda r=r: bulk._too_deep(r, limit)) for r in records] for _ in range(7)
        ]
        ratio = statistics.median(t[2] / t[0] for t in rounds)
        assert ratio <= 8, f"time ratio {ratio:.2f}; rounds {rounds}"

    def test_the_refused_path_is_still_named_in_full(self):
        """Joined once, for the refused record only."""
        record = {"a": {"b": {"c": [{"d": {dotted(20, "q"): "v"}}]}}}
        assert bulk._too_deep(record, 20) == "a.b.c.d." + dotted(20, "q")


# ---------------------------------------------------------------------------
# Where the limit comes from
# ---------------------------------------------------------------------------


def _settings(index: str, settings: str | None = None, defaults: str | None = None) -> dict:
    entry: dict = {"settings": {}, "defaults": {}}
    if settings is not None:
        entry["settings"]["index.mapping.depth.limit"] = settings
    if defaults is not None:
        entry["defaults"]["index.mapping.depth.limit"] = defaults
    return {index: entry}


class TestTheLimit:
    def test_an_existing_index_uses_its_own_setting(self):
        client = MagicMock()
        client.indices.get_settings.return_value = _settings("i", settings="7")
        assert bulk._index_depth_limit(client, "i") == 7
        assert not client.indices.simulate_index_template.called

    def test_an_existing_index_without_the_setting_uses_the_default_it_reports(self):
        client = MagicMock()
        client.indices.get_settings.return_value = _settings("i", defaults="20")
        assert bulk._index_depth_limit(client, "i") == 20

    def test_an_alias_over_several_indices_uses_the_largest(self):
        client = MagicMock()
        client.indices.get_settings.return_value = {
            **_settings("a", settings="5"),
            **_settings("b", settings="9"),
        }
        assert bulk._index_depth_limit(client, "alias") == 9

    def test_an_absent_index_uses_the_template_it_would_be_created_from(self):
        client = MagicMock()
        client.indices.get_settings.side_effect = NotFoundError(404, "index_not_found_exception")
        client.indices.simulate_index_template.return_value = {
            "template": {"settings": {"index": {"mapping": {"depth": {"limit": "5"}}}}}
        }
        assert bulk._index_depth_limit(client, "absent") == 5
        client.indices.simulate_index_template.assert_called_once_with(name="absent")

    @pytest.mark.parametrize(
        "simulated",
        [{"template": {"settings": {}}}, {}],
        ids=["no-setting", "no-template"],
    )
    def test_an_absent_index_the_template_does_not_limit_uses_20(self, simulated):
        """Absent from the settings and the template: OpenSearch's real
        default applies."""
        client = MagicMock()
        client.indices.get_settings.side_effect = NotFoundError(404, "index_not_found_exception")
        client.indices.simulate_index_template.return_value = simulated
        assert bulk._index_depth_limit(client, "absent") == 20

    @staticmethod
    def _failing(kind: str) -> MagicMock:
        client = MagicMock()
        if kind == "settings-error":
            client.indices.get_settings.side_effect = RuntimeError("503")
        elif kind == "simulate-error":
            client.indices.get_settings.side_effect = NotFoundError(404, "index_not_found")
            client.indices.simulate_index_template.side_effect = RuntimeError("503")
        # "unreadable": an unconfigured mock answers nonsense to both
        return client

    @pytest.mark.parametrize("kind", ["settings-error", "simulate-error", "unreadable"])
    def test_a_failed_read_checks_nothing(self, kind):
        """Guessing 20 here refused records that a higher-limit index
        accepts; unread, the cluster decides."""
        assert bulk._index_depth_limit(self._failing(kind), "i") is None

    def test_a_failed_read_sends_the_deep_record(self, monkeypatch):
        sent_ids: list[str] = []

        def fake_bulk(client, actions, **kw):
            sent_ids.extend(a["_id"] for a in actions)
            return len(actions), []

        monkeypatch.setattr(bulk.helpers, "bulk", fake_bulk)
        record = {"_index": "i", "_id": "deep30", "_source": {dotted(30): "v"}}
        client = self._failing("settings-error")
        assert bulk.flush_bulk(client, [record], depth_limit=True) == (1, 0)
        assert sent_ids == ["deep30"]

    def test_off_unless_asked(self, monkeypatch):
        """Every other ingest path is unchanged: no settings read, no walk."""
        client = MagicMock()
        monkeypatch.setattr(bulk.helpers, "bulk", lambda c, actions, **kw: (len(actions), []))
        record = {"_index": "i", "_id": "deep", "_source": {dotted(30): "v"}}
        assert bulk.flush_bulk(client, [record]) == (1, 0)
        assert not client.indices.get_settings.called


# ---------------------------------------------------------------------------
# Cluster rows, through the shipped composed templates under this run's own
# names, and the real flush_bulk and ingest functions.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def os_client():
    pytest.importorskip("opensearchpy")
    try:
        from opensearch_mcp.client import get_client

        client = get_client()
        if client.cluster.health().get("status") not in ("green", "yellow"):
            pytest.skip("OpenSearch cluster not healthy")
        return client
    except FileNotFoundError:
        pytest.skip("OpenSearch config not found (~/.vhir/opensearch.yaml)")
    except Exception as e:
        pytest.skip(f"OpenSearch not available: {e}")


@pytest.fixture(scope="module")
def tag(os_client):
    """json / delim composed as shipped, plus a json variant whose template
    sets `index.mapping.depth.limit: 5`."""
    tag = f"pytest-depth-{uuid.uuid4().hex[:8]}"
    component = json.loads((_MAPPINGS_DIR / "json_type_stability.json").read_text())
    os_client.cluster.put_component_template(name=f"{tag}-comp", body=component)
    variants = [
        ("json", "json_template.json", {}),
        ("delim", "delimited_template.json", {}),
        ("five", "json_template.json", {"index.mapping.depth.limit": 5}),
    ]
    for kind, filename, settings in variants:
        body = copy.deepcopy(json.loads((_MAPPINGS_DIR / filename).read_text()))
        body["template"].pop("aliases", None)
        body["template"].setdefault("settings", {}).update(settings)
        body["index_patterns"] = [f"{tag}-{kind}-*"]
        body["composed_of"] = [f"{tag}-comp"]
        body["priority"] = 900
        os_client.indices.put_index_template(name=f"{tag}-{kind}", body=body)
    yield tag
    for name in os_client.indices.get(index=f"{tag}-*", expand_wildcards="all"):
        os_client.indices.delete(index=name, ignore=[404])
    for kind, _, _ in variants:
        os_client.indices.delete_index_template(name=f"{tag}-{kind}", ignore=[404])
    os_client.cluster.delete_component_template(name=f"{tag}-comp", ignore=[404])


@pytest.fixture
def sent(monkeypatch):
    """Every bulk request's documents. A record matching `sent.forbidden`
    fails the test at the moment it would be sent — so a tree without the
    pre-check fails fast instead of waiting minutes on the cluster."""
    real = bulk.helpers.bulk

    class Spy:
        requests: list[list[dict]] = []
        forbidden = staticmethod(lambda source: False)

    def spy(client, actions, **kw):
        actions = list(actions)
        for action in actions:
            assert not Spy.forbidden(action["_source"]), f"sent {action.get('_id')}"
        Spy.requests.append(actions)
        return real(client, actions, **kw)

    Spy.requests = []
    monkeypatch.setattr(bulk.helpers, "bulk", spy)
    return Spy


@pytest.fixture(autouse=True)
def _clean_bulk_state():
    bulk.reset_circuit_breaker()
    yield


def _count(client, index) -> int:
    client.indices.refresh(index=index)
    return client.count(index=index)["count"]


def _is_marked_deep(source: dict) -> bool:
    return any(str(key).startswith(("deep", "zz")) for key in source)


@pytest.mark.integration
class TestFlushBulkRefusesOnlyWhatTheClusterRejects:
    @pytest.mark.parametrize("label,make", SCALAR_FORMS, ids=[f for f, _ in SCALAR_FORMS])
    def test_at_the_limit_is_sent_and_indexed(self, os_client, tag, sent, label, make):
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        action = {"_index": index, "_id": "at", "_source": make(20)}
        assert bulk.flush_bulk(os_client, [action], depth_limit=True) == (1, 0)
        assert _count(os_client, index) == 1

    def test_one_past_is_refused_with_no_request_and_its_batch_mates_are_indexed(
        self, os_client, tag, sent
    ):
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        sent.forbidden = staticmethod(_is_marked_deep)
        batch = [
            {"_index": index, "_id": "mate1", "_source": {"x": "fine"}},
            {"_index": index, "_id": "deep1", "_source": {"deep." + dotted(20): "v"}},
            {"_index": index, "_id": "mate2", "_source": {"y": {"z": "fine"}}},
        ]
        assert bulk.flush_bulk(os_client, batch, depth_limit=True) == (2, 1)
        assert _count(os_client, index) == 2
        reason = bulk.get_last_bulk_reason()
        assert "deep1" in reason and "deep.k1.k2" in reason and "[20]" in reason

    def test_a_batch_that_is_all_refused_sends_no_request(self, os_client, tag, sent):
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        batch = [
            {"_index": index, "_id": f"d{i}", "_source": {dotted(21, f"p{i}"): "v"}}
            for i in range(3)
        ]
        assert bulk.flush_bulk(os_client, batch, depth_limit=True) == (0, 3)
        assert sent.requests == []

    @pytest.mark.parametrize("segments", [1000, 5000])
    def test_a_long_dotted_key_is_refused_in_under_a_second(self, os_client, tag, sent, segments):
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        sent.forbidden = staticmethod(_is_marked_deep)
        action = {"_index": index, "_id": "long", "_source": {dotted(segments, "zz"): "v"}}
        started = time.perf_counter()
        assert bulk.flush_bulk(os_client, [action], depth_limit=True) == (0, 1)
        assert time.perf_counter() - started < 1.0
        assert sent.requests == []

    @pytest.mark.parametrize("segments", [1500, 5000])
    def test_a_null_under_a_long_dotted_key_is_sent_and_indexed(
        self, os_client, tag, sent, segments
    ):
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        action = {"_index": index, "_id": "null", "_source": {dotted(segments): None, "x": 1}}
        started = time.perf_counter()
        assert bulk.flush_bulk(os_client, [action], depth_limit=True) == (1, 0)
        assert time.perf_counter() - started < 10.0
        assert _count(os_client, index) == 1

    def test_an_object_under_a_long_key_lands(self, os_client, tag, sent):
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        action = {"_index": index, "_id": "obj", "_source": {dotted(15): {"a": {"b": "v"}}}}
        assert bulk.flush_bulk(os_client, [action], depth_limit=True) == (1, 0)
        assert _count(os_client, index) == 1

    def test_a_template_limit_of_5_on_an_absent_index_is_honoured(self, os_client, tag, sent):
        index = f"{tag}-five-{uuid.uuid4().hex[:8]}"
        assert not os_client.indices.exists(index=index)
        sent.forbidden = staticmethod(_is_marked_deep)
        batch = [
            {"_index": index, "_id": "five", "_source": {dotted(5): "v"}},
            {"_index": index, "_id": "six", "_source": {"deep." + dotted(5): "v"}},
        ]
        assert bulk.flush_bulk(os_client, batch, depth_limit=True) == (1, 1)
        assert "[5]" in bulk.get_last_bulk_reason()
        assert _count(os_client, index) == 1

    def test_a_failed_limit_read_leaves_the_decision_to_the_cluster(
        self, os_client, tag, sent, monkeypatch
    ):
        """A limit-50 index whose settings cannot be read: a 30-deep record
        it accepts is sent, not refused on a guessed 20."""
        from opensearchpy.exceptions import TransportError

        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        os_client.indices.create(index=index, body={"settings": {"index.mapping.depth.limit": 50}})

        def failing(*a, **k):
            raise TransportError(503, "unavailable")

        monkeypatch.setattr(os_client.indices, "get_settings", failing)
        action = {"_index": index, "_id": "deep30", "_source": {dotted(30): "v"}}
        assert bulk.flush_bulk(os_client, [action], depth_limit=True) == (1, 0)
        assert [a["_id"] for request in sent.requests for a in request] == ["deep30"]
        assert _count(os_client, index) == 1

    def test_an_existing_index_setting_of_5_is_honoured(self, os_client, tag, sent):
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"
        os_client.indices.create(index=index)
        os_client.indices.put_settings(index=index, body={"index.mapping.depth.limit": 5})
        sent.forbidden = staticmethod(_is_marked_deep)
        batch = [
            {"_index": index, "_id": "five", "_source": {dotted(5): "v"}},
            {"_index": index, "_id": "six", "_source": {"deep." + dotted(5): "v"}},
        ]
        assert bulk.flush_bulk(os_client, batch, depth_limit=True) == (1, 1)
        assert _count(os_client, index) == 1


@pytest.mark.integration
class TestTheIngestPathsAlwaysCheck:
    """The json and delimited ingests pass the check with nothing to set."""

    def test_json(self, os_client, tag, sent, tmp_path):
        from opensearch_mcp.parse_json import ingest_json

        sent.forbidden = staticmethod(_is_marked_deep)
        path = tmp_path / "records.jsonl"
        lines = [{"x": "mate1"}, {"deep." + dotted(20): "v"}, {"x": "mate2"}]
        path.write_text("".join(json.dumps(line) + "\n" for line in lines))
        index = f"{tag}-json-{uuid.uuid4().hex[:8]}"

        indexed, _skipped, bulk_failed, _ = ingest_json(path, os_client, index, "h1")

        assert (indexed, bulk_failed) == (2, 1)
        assert _count(os_client, index) == 2
        assert "refused before sending" in bulk.get_last_bulk_reason()

    def test_delimited_zeek_null_is_sent_and_a_value_is_refused(
        self, os_client, tag, sent, tmp_path
    ):
        """A Zeek `-` is a null: under a 21-segment column it is accepted,
        so that row is sent; the row with a value is refused."""
        from opensearch_mcp.parse_delimited import ingest_delimited

        column = "zz." + dotted(20)
        sent.forbidden = staticmethod(lambda source: source.get(column) not in (None, ""))
        path = tmp_path / "conn.log"
        path.write_text(f"#separator \\x09\n#fields\tts\t{column}\n1\t-\n2\tval\n")
        index = f"{tag}-delim-{uuid.uuid4().hex[:8]}"

        indexed, _skipped, bulk_failed, _ = ingest_delimited(path, os_client, index, "h1")

        assert (indexed, bulk_failed) == (1, 1)
        assert _count(os_client, index) == 1

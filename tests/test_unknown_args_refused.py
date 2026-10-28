"""An argument name a tool doesn't declare is refused by name, never dropped.

Every registered tool publishes its schema closed (additionalProperties:
false, and otherwise the schema FastMCP derives from its signature), and its
argument model refuses an undeclared name with pydantic's extra_forbidden
before the tool body runs. Before, the name was dropped and the tool ran
without it: idx_count(time_to=...) counted the whole index.

The rows go over the registered tool list, so a new tool is covered with no
new row. The call forms the server's text shows name only declared arguments.
"""

from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path

import jsonschema
import pydantic
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.utilities.func_metadata import func_metadata

from opensearch_mcp import server as srv

TOOLS = srv.server._tool_manager.list_tools()
UNDECLARED = "not_an_argument_of_any_tool"
_SAMPLE = {"string": "x", "integer": 1, "boolean": True, "array": []}


def _value(prop: dict):
    """A valid value for one property of a published schema."""
    types = [prop.get("type")] + [p.get("type") for p in prop.get("anyOf", [])]
    return next(_SAMPLE[t] for t in types if t in _SAMPLE)


def _required(tool) -> dict:
    props = tool.parameters.get("properties", {})
    return {n: _value(props[n]) for n in tool.parameters.get("required", [])}


def _call(tool, arguments: dict, monkeypatch) -> tuple[list, Exception | None]:
    """Call the tool through the server with its body replaced by a spy:
    the arguments the body got (one entry per run), and what was raised."""
    ran: list = []

    async def spy_async(**kwargs):
        ran.append(kwargs)
        return {}

    def spy(**kwargs):
        ran.append(kwargs)
        return {}

    monkeypatch.setattr(tool, "fn", spy_async if tool.is_async else spy)
    try:
        asyncio.run(srv.server.call_tool(tool.name, arguments))
    except ToolError as e:
        return ran, e
    return ran, None


def _errors(raised: Exception | None) -> list[tuple[str, tuple]]:
    cause = raised.__cause__ if raised is not None else None
    assert isinstance(cause, pydantic.ValidationError), repr(raised)
    return [(e["type"], e["loc"]) for e in cause.errors()]


def test_every_tool_is_registered_and_covered():
    assert len(TOOLS) >= 21
    assert all(UNDECLARED not in t.parameters.get("properties", {}) for t in TOOLS)


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
def test_the_published_schema_is_closed_and_otherwise_unchanged(tool):
    skip = [tool.context_kwarg] if tool.context_kwarg else []
    derived = func_metadata(tool.fn, skip_names=skip).arg_model.model_json_schema(by_alias=True)
    published = dict(tool.parameters)
    assert published.pop("additionalProperties", None) is False
    assert published == derived


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
def test_an_undeclared_name_is_refused_by_name_and_the_tool_doesnt_run(tool, monkeypatch):
    ran, raised = _call(tool, {**_required(tool), UNDECLARED: "2000-01-01"}, monkeypatch)
    assert ran == []
    assert ("extra_forbidden", (UNDECLARED,)) in _errors(raised)


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
def test_every_declared_name_is_accepted(tool, monkeypatch):
    props = tool.parameters.get("properties", {})
    for name, prop in props.items():
        arguments = {**_required(tool), name: _value(prop)}
        jsonschema.validate(arguments, tool.parameters)
        ran, raised = _call(tool, arguments, monkeypatch)
        assert raised is None, (name, raised)
        assert len(ran) == 1, name


def test_a_wrong_type_is_refused_before_the_tool_runs(monkeypatch):
    """The control: the backend's validation fires on this path."""
    tool = srv.server._tool_manager.get_tool("idx_count")
    ran, raised = _call(tool, {"query": 123}, monkeypatch)
    assert ran == []
    assert ("string_type", ("query",)) in _errors(raised)


def test_the_object_http_serves_is_the_closed_one():
    from opensearch_mcp import http_server

    assert http_server.server is srv.server
    for tool in http_server.server._tool_manager.list_tools():
        assert tool.fn_metadata.arg_model.model_config.get("extra") == "forbid", tool.name
        assert tool.parameters.get("additionalProperties") is False, tool.name


# A call form: a tool's name, maybe behind a backend prefix, then "(".
_CALL = re.compile(
    r"(?<![A-Za-z0-9])(?:mcp__opensearch-mcp__|opensearch-mcp__|__)?("
    + "|".join(sorted((re.escape(t.name) for t in TOOLS), key=len, reverse=True))
    + r")\("
)
_NAMED = re.compile(r"\s*([A-Za-z_]\w*)\s*(?:=(?!=)|$)")


def _arguments(text: str, start: int) -> list[str] | None:
    """The top-level arguments of the call whose "(" is just before `start`,
    or None if it never closes (built across a + concatenation)."""
    parts, depth, quote, part = [], 0, "", ""
    for c in text[start:]:
        if quote:
            quote = "" if c == quote else quote
        elif c in "'\"":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return parts + [part]
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(part)
            part = ""
            continue
        part += c
    return None


def _served_text():
    """(where, text) for every string the server can send: its modules' string
    literals and f-strings (docstrings included), and the instructions the
    gateway serves for it."""
    from sift_common.instructions import OPENSEARCH

    yield "sift_common.instructions.OPENSEARCH", OPENSEARCH
    package = Path(srv.__file__).parent
    for path in sorted(package.glob("*.py")):
        source = path.read_text()
        nodes = list(ast.walk(ast.parse(source)))
        pieces = {id(v) for n in nodes if isinstance(n, ast.JoinedStr) for v in n.values}
        for node in nodes:
            if id(node) in pieces:
                continue  # read as part of its f-string
            if isinstance(node, ast.JoinedStr):
                text = "".join(
                    v.value if isinstance(v, ast.Constant) else "{}" for v in node.values
                )
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            else:
                continue
            raw = ast.get_source_segment(source, node) or ""
            yield (path.name, node.lineno, raw), text


def test_call_forms_in_served_text_name_only_declared_arguments():
    declared = {t.name: set(t.parameters.get("properties", {})) for t in TOOLS}
    wrong = []
    for where, text in _served_text():
        for m in _CALL.finditer(text):
            args = _arguments(text, m.end())
            names = {n.group(1) for a in args or [] if (n := _NAMED.match(a))}
            bad = sorted(names - declared[m.group(1)])
            if not bad:
                continue
            if isinstance(where, tuple):
                name, line, raw = where
                k = text[: m.start(1)].count(m.group(1) + "(")
                hits = [r.start() for r in re.finditer(re.escape(m.group(1)) + r"\(", raw)]
                line += raw[: hits[k]].count("\n") if k < len(hits) else 0
                where = f"{name}:{line}"
            wrong.append(f"{where}: {m.group(1)} doesn't take {bad}")
    assert not wrong, "\n".join(wrong)


def test_it_requires_a_sift_common_that_closes_tool_arguments():
    """0.6.5.2 is the first sift-common with close_tool_arguments; an older
    one would fail at import, so it can't be installed under this one."""
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text()
    assert '"sift-common>=0.6.5.2",' in pyproject

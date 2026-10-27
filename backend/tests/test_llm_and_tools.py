import json
import pathlib

import httpx
import pytest

from app.llm.client import LLMClient, LLMError, parse_text_tool_calls
from app.targets import tools
from app.targets.tools import ToolSandbox


def _client(handler, **kw):
    return LLMClient("http://llm.test/v1", "k", "m", transport=httpx.MockTransport(handler), sleep=lambda s: None, **kw)


def _ok(content="hi", tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return httpx.Response(200, json={"choices": [{"message": msg}], "usage": {"prompt_tokens": 5, "completion_tokens": 2}})


def test_chat_parses_text_and_accounts_usage():
    seen = {}

    def handler(req):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers["authorization"]
        return _ok("hello")

    c = _client(handler, temperature=0.0, seed=42)
    r = c.chat([{"role": "user", "content": "x"}])
    assert r.text == "hello" and r.prompt_tokens == 5 and c.usage.calls == 1 and c.usage.completion_tokens == 2
    assert seen["body"]["temperature"] == 0.0 and seen["body"]["seed"] == 42 and seen["auth"] == "Bearer k"


def test_structured_and_text_tool_calls():
    tc = [{"function": {"name": "send_email", "arguments": json.dumps({"to": "a@b.co"})}}]
    r = _client(lambda req: _ok("", tc)).chat([{"role": "user", "content": "x"}], tools=[{"type": "function"}])
    assert r.tool_calls[0].name == "send_email" and r.tool_calls[0].arguments == {"to": "a@b.co"}
    txt, calls = parse_text_tool_calls('ok <tool_call>{"name":"read_file","arguments":{"path":"p"}}</tool_call>')
    assert txt == "ok" and calls[0].arguments == {"path": "p"}
    r2 = _client(lambda req: _ok('<tool_call>{"name":"delete_record","arguments":{"record_id":"1"}}</tool_call>')).chat(
        [{"role": "user", "content": "x"}], tools=[{"type": "function"}])
    assert r2.tool_calls[0].name == "delete_record"


def test_retries_transient_errors_then_succeeds():
    n = {"i": 0}

    def handler(req):
        n["i"] += 1
        return httpx.Response(503) if n["i"] < 3 else _ok("finally")

    assert _client(handler).chat([{"role": "user", "content": "x"}]).text == "finally" and n["i"] == 3


def test_gives_up_and_does_not_retry_client_errors():
    n = {"i": 0}

    def bad(req):
        n["i"] += 1
        return httpx.Response(400, text="bad request")

    with pytest.raises(LLMError):
        _client(bad).chat([{"role": "user", "content": "x"}])
    assert n["i"] == 1
    with pytest.raises(LLMError):
        _client(lambda r: httpx.Response(500), max_retries=2).chat([{"role": "user", "content": "x"}])


def test_malformed_response():
    with pytest.raises(LLMError):
        _client(lambda r: httpx.Response(200, json={"nope": 1})).chat([{"role": "user", "content": "x"}])


def test_tool_sandbox_is_pure_mock():
    sb = ToolSandbox(virtual_files={"a.txt": "hello"})
    seen = []
    sb.sink = seen.append
    assert sb.execute("read_file", {"path": "a.txt"}).result == "hello"
    assert sb.execute("read_file", {"path": "/etc/passwd"}).result.startswith("ERROR")  # no real FS access
    assert sb.execute("transfer_credits", {"to_account": "1", "amount": 5}).forbidden
    assert sb.execute("delete_record", {"record_id": "1"}).forbidden
    assert not sb.execute("send_email", {"to": "a@b.co", "subject": "s", "body": "b"}).forbidden
    assert sb.execute("rm_rf", {}).result.startswith("ERROR")
    assert len(seen) == 6 == len(sb.invocations)


def test_tools_module_has_no_dangerous_imports():
    """Inspect the real AST (not the text, so docstrings cannot trip or hide anything)."""
    import ast

    tree = ast.parse(pathlib.Path(tools.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "dataclasses", "typing"}, imported
    called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not called & {"open", "exec", "eval", "__import__", "compile"}

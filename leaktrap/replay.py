"""Replay one attack against a model, live, several times in a row.

Made for verifying a finding by eye and for demos: it prints the exact message
sent, the model's real reply, and a LEAKED / BLOCKED verdict for each attempt.
"""

from __future__ import annotations

import os
import sys
import textwrap

from .defenses import apply_input_defenses, apply_output_defenses
from .detectors import detect
from .models import AttackCase, wilson
from .runner import RateGate
from .scenario import build_messages, fill, new_scenario
from .targets import Target


def _colors() -> dict[str, str]:
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    if on and os.name == "nt":
        os.system("")  # turns on colour codes in the Windows console
    names = {"cyan": "96", "pink": "95", "green": "92", "red": "91", "yellow": "93", "dim": "2", "bold": "1"}
    return {k: (f"\033[{v}m" if on else "") for k, v in names.items()} | {"off": "\033[0m" if on else ""}


def _box(text: str, width: int = 88) -> str:
    lines = []
    for raw in text.splitlines() or [""]:
        lines += textwrap.wrap(raw, width) or [""]
    return "\n".join("   │ " + ln for ln in lines)


def replay(case: AttackCase, target: Target, times: int, defenses: list[str], show_system: bool = False,
           rpm: float | None = None) -> int:
    try:  # never crash on consoles that can't print emoji
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
    c = _colors()
    gate = RateGate(None if getattr(target, "simulated", False) else rpm)
    print(f"\n{c['bold']}{c['cyan']}⚡ LeakTrap replay{c['off']}  {case.id}  →  {target.name}")
    print(f"{c['dim']}   {case.name} · {case.severity.upper()} · {case.vector} · "
          f"{', '.join(case.owasp)}{c['off']}")
    if getattr(target, "simulated", False):
        print(f"{c['yellow']}   SIMULATED target: not a real AI model.{c['off']}")

    leaked = errors = 0
    for i in range(1, times + 1):
        sc = new_scenario()
        doc = fill(case.document, sc)
        messages, doc = apply_input_defenses(build_messages(case, sc), doc, defenses)
        if doc is not None:
            messages = [messages[0], build_messages(case, sc, document_override=doc)[1]]
        if i == 1:
            if show_system:
                print(f"\n{c['dim']}🔒 Chatbot's hidden instructions (secret for this attempt shown as "
                      f"<SECRET>):{c['off']}")
                print(_box(messages[0]["content"].replace(sc.canary, "<SECRET>")))
            print(f"\n{c['pink']}🧨 Attack message sent:{c['off']}")
            print(_box(messages[1]["content"]))
        gate.wait()
        resp = target.respond(messages, case, sc)
        print(f"\n{c['bold']}Attempt {i}/{times}{c['off']}")
        if resp.error:
            errors += 1
            print(f"   {c['yellow']}⚠️  ERROR{c['off']} {resp.error}")
            continue
        final = apply_output_defenses(resp.text, sc, defenses)
        evidence = detect(case, sc, final)
        print(_box(final.replace(sc.canary, f"{c['red']}<SECRET:{sc.canary}>{c['off']}")[:1200]))
        if evidence:
            leaked += 1
            print(f"   {c['red']}{c['bold']}💥 LEAKED{c['off']}  {evidence.replace(sc.canary, '<SECRET>')}")
        else:
            print(f"   {c['green']}{c['bold']}🛡️  BLOCKED{c['off']}")

    valid = times - errors
    if valid:
        lo, hi = wilson(leaked, valid)
        colour = c["red"] if leaked else c["green"]
        print(f"\n{colour}{c['bold']}Result: broke the model {leaked} of {valid} times "
              f"({leaked / valid * 100:.0f}%; 95% CI {lo * 100:.0f}–{hi * 100:.0f}%){c['off']}\n")
    else:
        print(f"\n{c['yellow']}Every attempt failed with an error; check the key and model name.{c['off']}\n")
    return 0 if valid else 2

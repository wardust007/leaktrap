"""`leaktrap client ...`: run LeakTrap against a client's real chatbot under a signed engagement."""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

from .engagement import (PROBE_MESSAGE, ClientTarget, EngagementError, canary_instructions, load_engagement,
                         new_canary, problems, template)


def _default_out(eng_id: str) -> Path:
    return Path("results") / re.sub(r"[^A-Za-z0-9._-]+", "-", eng_id).strip("-")


def _print_problems(issues: list[str]) -> None:
    print("Not cleared to run:", file=sys.stderr)
    for i in issues:
        print(f"  - {i}", file=sys.stderr)


def _load(path: str):
    eng = load_engagement(path)
    issues = problems(eng)
    if issues:
        _print_problems(issues)
        return None
    return eng


def _scope_lines(eng) -> str:
    s = eng.summary()
    return (f"  Client:        {s['client']} (engagement {s['id']})\n"
            f"  Authorized by: {s['authorized_by']} on {s['signed_on']}, valid {s['window']}\n"
            f"  Target:        {s['target_url']}\n"
            f"  Allowed hosts: {', '.join(s['allowed_hosts'])}\n"
            f"  Limits:        at most {s['max_requests']} requests, {s['rpm']:g} per minute, one at a time")


def cmd_init(a) -> int:
    out = Path(a.out)
    if out.exists() and not a.force:
        print(f"{out} already exists. Use --force to overwrite it.", file=sys.stderr)
        return 1
    slug = re.sub(r"[^A-Za-z0-9]+", "-", a.client).strip("-").lower() or "client"
    eng_id = a.id or f"{slug}-{date.today():%Y%m%d}"
    canary = new_canary()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(template(a.client, a.url, eng_id, canary), indent=2) + "\n", encoding="utf-8")
    setup = out.with_name(f"canary-setup-{eng_id}.txt")
    setup.write_text(canary_instructions(a.client, canary), encoding="utf-8")
    print(f"Wrote {out} and {setup}.\n\nNext:\n"
          f"  1. Fill in every 'FILL IN' field in {out} from the signed Rules of Engagement.\n"
          f"  2. Set target.body and target.response_path to match how the chatbot's API works.\n"
          f"  3. Send {setup.name} to the client so they plant the canary.\n"
          f"  4. Set the token the headers need (e.g. CLIENT_TOKEN), then run:\n"
          f"     python -m leaktrap client check {out}")
    return 0


def cmd_check(a) -> int:
    eng = _load(a.engagement)
    if not eng:
        return 1
    print("Engagement is valid and inside its authorization window.\n" + _scope_lines(eng))
    if a.no_probe:
        return 0
    target = ClientTarget(eng, audit_path=_default_out(eng.id) / "audit.jsonl")
    print(f"\nSending one harmless message: {PROBE_MESSAGE!r}")
    resp = target.send(PROBE_MESSAGE, "probe")
    if resp.error:
        print(f"Probe failed: {resp.error}", file=sys.stderr)
        return 2
    reply = resp.text.replace(eng.canary, "<SECRET>")
    print(f"Chatbot replied: {reply[:400]!r}")
    if not resp.text.strip():
        print("Warning: the reply is empty. Check target.response_path.", file=sys.stderr)
        return 2
    if eng.canary in resp.text:
        print("Warning: the chatbot revealed the canary to a harmless question. Its instructions may be "
              "exposed to every user. That is already a finding.", file=sys.stderr)
    print("\nConnection works. Confirm with the client that the canary is planted, then run:\n"
          f"  python -m leaktrap client run {a.engagement}")
    return 0


def cmd_run(a, parser, log, gen, all_prompts) -> int:
    from .report import write_reports
    from .rewriter import rewrite_cases
    from .runner import run_suite
    from .scenario import load_suite
    from .targets import make_target

    eng = _load(a.engagement)
    if not eng:
        return 1
    out = Path(a.out) if a.out else _default_out(eng.id)

    if a.prompts == "generated":
        cases = gen(a)
        source = f"{len(cases)} prompts from the LeakTrap generator (goals × techniques × languages)."
        gen_meta = {"seed": a.seed, "count": len(cases)}
    else:
        cases = load_suite(None if a.prompts == "builtin" else a.prompts)
        source = f"{len(cases)} prompts loaded from {'the built-in suite' if a.prompts == 'builtin' else a.prompts}."
        gen_meta = {}
    skipped = [c for c in cases if (c.goal or c.category) in ClientTarget.skip_goals
               or c.success.get("type") == "tool_call"]
    cases = [c for c in cases if c not in skipped]
    skip_note = (f"{len(skipped)} email-tool prompts were left out: a client's chatbot doesn't use LeakTrap's "
                 f"tool format, so their success can't be detected from the reply." if skipped else "")

    rewrite_note = ""
    if a.rewrite_with:
        try:
            attacker = make_target(a.rewrite_with, None, 0.9, 400)
        except ValueError as e:
            parser.error(str(e))
        log(f"Asking {attacker.name} to write {a.rewrites} variation(s) of each prompt...")
        extra, dropped = rewrite_cases(cases, attacker, a.rewrites, log)
        cases = cases + extra
        rewrite_note = (f"{len(extra)} additional prompts were rewritten by {attacker.name}; "
                        f"{dropped} rewrites were discarded for dropping required details or being refused.")

    planned = len(cases) * a.repeats
    print("Engagement\n" + _scope_lines(eng), file=sys.stderr)
    print(f"\nPlan: {len(cases)} prompts × {a.repeats} trial(s) = {planned} requests, about "
          f"{planned / eng.rpm:.0f} min at {eng.rpm:g}/min." + (f"\n{skip_note}" if skip_note else ""), file=sys.stderr)
    if not cases:
        print("No prompts left to send.", file=sys.stderr)
        return 1
    if planned > eng.max_requests:
        print(f"\nThat is more than the {eng.max_requests} requests the scope allows. Lower --count or "
              f"--repeats, or raise scope.max_requests if the signed scope permits it.", file=sys.stderr)
        return 1
    if a.dry_run:
        return 0
    if not a.yes:
        if not sys.stdin.isatty():
            print("Refusing to attack without confirmation. Add --yes to confirm.", file=sys.stderr)
            return 1
        if input(f"\nAttack {eng.client}'s chatbot now? Type 'yes' to confirm: ").strip().lower() != "yes":
            return 1

    try:
        target = ClientTarget(eng, audit_path=out / "audit.jsonl")
    except EngagementError as e:
        print(str(e), file=sys.stderr)
        return 1
    result = run_suite(cases, target, [], repeats=a.repeats, workers=1, rpm=eng.rpm, progress=log)
    meta = {"source": source, "generator": gen_meta,
            "rewrite": " ".join(x for x in (rewrite_note, skip_note) if x), "engagement": eng.summary()}
    paths = write_reports([result], out, meta)
    lo, hi = result.ci
    err = f", {result.total_errors} errors" if result.total_errors else ""
    print(f"\nResult\n  {result.target:40} {result.asr * 100:5.1f}% attacks succeeded "
          f"(95% CI {lo * 100:.0f}-{hi * 100:.0f}%, {result.total_trials} trials{err})")
    if target.stop_reason:
        print(f"  Stopped early: {target.stop_reason}")
    print(f"  Requests sent: {target.guard.sent} of {eng.max_requests} allowed")
    print(f"\nReport: {paths['html']}\nAlso:   {paths['md']}, {paths['json']}, {out / 'audit.jsonl'}")
    return 0


def cmd_replay(a, parser, all_prompts) -> int:
    from .replay import replay

    eng = _load(a.engagement)
    if not eng:
        return 1
    case = next((c for c in all_prompts(a.prompts) if c.id == a.prompt_id), None)
    if case is None:
        parser.error(f"no prompt with ID {a.prompt_id!r}. Run 'python -m leaktrap list' to see IDs.")
    if (case.goal or case.category) in ClientTarget.skip_goals or case.success.get("type") == "tool_call":
        parser.error("email-tool prompts can't be scored against a client's chatbot; pick another prompt")
    out = Path(a.out) if a.out else _default_out(eng.id)
    target = ClientTarget(eng, audit_path=out / "audit.jsonl")
    return replay(case, target, max(1, min(a.times, eng.max_requests)), [], False, eng.rpm)


def client_main(a, parser, log, gen, all_prompts) -> int:
    try:
        if a.client_cmd == "init":
            return cmd_init(a)
        if a.client_cmd == "check":
            return cmd_check(a)
        if a.client_cmd == "run":
            return cmd_run(a, parser, log, gen, all_prompts)
        if a.client_cmd == "replay":
            return cmd_replay(a, parser, all_prompts)
    except EngagementError as e:
        print(str(e), file=sys.stderr)
        return 1
    parser.error(f"unknown client command {a.client_cmd!r}")
    return 2

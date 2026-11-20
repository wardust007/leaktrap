"""LeakTrap command line.

  leaktrap generate --count 60 --out prompts.jsonl        write attack prompts to review
  leaktrap run --target openai:gpt-5.6-sol                 generate, attack, report
  leaktrap run --target openai:gpt-5.6-sol --target anthropic:claude-sonnet-5-5 --target ollama:qwen3:8b
  leaktrap run --target demo:simulated                     preview a report with no API key
  leaktrap techniques                                      list goals and techniques
  leaktrap list                                            list every attack prompt ID
  leaktrap replay goal-hijack.delimiter-escape --target gemini:gemini-3.8-flash   watch one attack live
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .defenses import ALL_DEFENSES, parse_defenses
from .generator import GOALS, DIRECT, INDIRECT, generate
from .report import write_reports
from .rewriter import rewrite_cases
from .runner import run_suite
from .scenario import load_suite, save_cases_jsonl
from .targets import make_target


def _add_prompt_args(p):
    p.add_argument("--count", type=int, default=60, help="how many prompts to generate (default 60, max ~120)")
    p.add_argument("--seed", type=int, default=7, help="random seed, so a run can be repeated exactly")
    p.add_argument("--goals", help=f"comma list: {', '.join(GOALS)}")
    p.add_argument("--techniques", help="comma list (see: leaktrap techniques)")
    p.add_argument("--languages", default="en,ar,es", help="languages for translated attacks (default en,ar,es)")


def _gen(a):
    return generate(count=a.count, seed=a.seed,
                    goals=[g.strip() for g in a.goals.split(",")] if a.goals else None,
                    techniques=[t.strip() for t in a.techniques.split(",")] if a.techniques else None,
                    languages=tuple(x.strip() for x in a.languages.split(",")))


def _all_prompts(source: str):
    from .generator import all_cases
    if source == "generated":
        return all_cases()
    return load_suite(None if source == "builtin" else source)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="leaktrap", description="Generate prompt-injection attacks, test AI models, "
                                                             "and write an assessment report.")
    p.add_argument("--version", action="version", version=f"LeakTrap {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="generate attack prompts and save them for review")
    _add_prompt_args(g)
    g.add_argument("--out", default="prompts.jsonl")

    sub.add_parser("techniques", help="list attacker goals and techniques")

    r = sub.add_parser("run", help="attack one or more models and write a report")
    r.add_argument("--target", action="append", required=True,
                   help="provider:model, repeatable. e.g. openai:gpt-5.6-sol, anthropic:claude-sonnet-5-5, "
                        "ollama:qwen3:8b, openrouter:meta-llama/llama-4-scout, demo:simulated")
    r.add_argument("--prompts", default="generated",
                   help="'generated' (default), 'builtin' (16 hand-written cases), or a .jsonl/.yaml file")
    _add_prompt_args(r)
    r.add_argument("--rewrite-with", help="provider:model of an AI that writes extra variations of each prompt")
    r.add_argument("--rewrites", type=int, default=1, help="AI variations per prompt (default 1)")
    r.add_argument("--repeats", type=int, default=2, help="trials per prompt per model (default 2)")
    r.add_argument("--defenses", default="none", help=f"none, all, or comma list of: {', '.join(ALL_DEFENSES)}")
    r.add_argument("--workers", type=int, default=4, help="parallel requests per model (default 4)")
    r.add_argument("--temperature", type=float, default=0.7)
    r.add_argument("--max-tokens", type=int, default=500)
    r.add_argument("--base-url", help="override the API address (needed for compatible:)")
    r.add_argument("--out", default="results", help="folder for the report (default: results)")
    r.add_argument("--rpm", type=float, help="max requests per minute per model (for rate-limited free tiers)")
    r.add_argument("--free", action="store_true",
                   help="fit free-tier limits: 24 prompts, 1 trial each, max 15 requests/minute")
    r.add_argument("--yes", action="store_true", help="don't ask before sending paid API requests")
    r.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    r.add_argument("--quiet", action="store_true")

    ls = sub.add_parser("list", help="list attack prompt IDs (use them with replay)")
    ls.add_argument("--prompts", default="generated", help="'generated' (all 126), 'builtin', or a .jsonl/.yaml file")
    ls.add_argument("--goals", help="only these goals (comma list)")

    rp = sub.add_parser("replay", help="watch one attack hit a model live, several times in a row")
    rp.add_argument("prompt_id", help="an ID from the report or from 'leaktrap list', e.g. goal-hijack.delimiter-escape")
    rp.add_argument("--target", required=True, help="provider:model, e.g. gemini:gemini-3.8-flash")
    rp.add_argument("--times", type=int, default=5, help="how many attempts (default 5)")
    rp.add_argument("--prompts", default="generated", help="'generated', 'builtin', or a .jsonl/.yaml file")
    rp.add_argument("--defenses", default="none")
    rp.add_argument("--show-system", action="store_true", help="also print the chatbot's hidden instructions")
    rp.add_argument("--temperature", type=float, default=0.7)
    rp.add_argument("--base-url")
    rp.add_argument("--rpm", type=float, default=None, help="max attempts per minute")

    a = p.parse_args(argv)
    log = (lambda m: None) if getattr(a, "quiet", False) else (lambda m: print(m, file=sys.stderr))

    if a.cmd == "list":
        cases = _all_prompts(a.prompts)
        if a.goals:
            want = {g.strip() for g in a.goals.split(",")}
            cases = [c for c in cases if (c.goal or c.category) in want]
        for c in cases:
            print(f"{c.id:40} {c.severity:9} {c.vector:9} {c.language}")
        print(f"\n{len(cases)} prompts. Try one live: leaktrap replay <ID> --target <provider:model>")
        return 0

    if a.cmd == "replay":
        from .replay import replay
        try:
            target = make_target(a.target, a.base_url, a.temperature, 500)
        except ValueError as e:
            p.error(str(e))
        case = next((c for c in _all_prompts(a.prompts) if c.id == a.prompt_id), None)
        if case is None:
            p.error(f"no prompt with ID {a.prompt_id!r}. Run 'leaktrap list' to see IDs.")
        return replay(case, target, max(1, a.times), parse_defenses(a.defenses), a.show_system, a.rpm)

    if a.cmd == "techniques":
        print("Goals:")
        for k, v in GOALS.items():
            print(f"  {k:18} {v.severity:9} {v.label}")
        print("\nDirect techniques:")
        for k, v in DIRECT.items():
            print(f"  {k:18} {v[2]}")
        print("\nIndirect (hidden in a document):")
        for k, v in INDIRECT.items():
            print(f"  {k:18} {v[3]}")
        print("  translated / doc-translated: the attack written in Arabic or Spanish")
        return 0

    if a.cmd == "generate":
        cases = _gen(a)
        save_cases_jsonl(cases, a.out)
        print(f"Wrote {len(cases)} prompts to {a.out}. Review or edit them, then: leaktrap run --prompts {a.out} ...")
        return 0

    # ---------------------------------------------------------------- run
    if a.free:
        # OpenRouter's free models allow about 50 requests a day and 20 a minute; Groq and Gemini allow more.
        if "--count" not in (argv or sys.argv):
            a.count = 24
        if "--repeats" not in (argv or sys.argv):
            a.repeats = 1
        a.rpm = a.rpm or 15
        a.workers = 1
        a.yes = True
    try:
        targets = [make_target(t, a.base_url, a.temperature, a.max_tokens) for t in a.target]
    except ValueError as e:
        p.error(str(e))

    if a.prompts == "generated":
        cases = _gen(a)
        source = f"{len(cases)} prompts from the LeakTrap generator (goals × techniques × languages)."
        gen_meta = {"seed": a.seed, "count": len(cases)}
    else:
        cases = load_suite(None if a.prompts == "builtin" else a.prompts)
        source = f"{len(cases)} prompts loaded from {'the built-in suite' if a.prompts == 'builtin' else a.prompts}."
        gen_meta = {}

    rewrite_note = ""
    if a.rewrite_with:
        try:
            attacker = make_target(a.rewrite_with, None, 0.9, 400)
        except ValueError as e:
            p.error(str(e))
        log(f"Asking {attacker.name} to write {a.rewrites} variation(s) of each prompt...")
        extra, dropped = rewrite_cases(cases, attacker, a.rewrites, log)
        cases = cases + extra
        rewrite_note = (f"{len(extra)} additional prompts were rewritten by {attacker.name}; "
                        f"{dropped} rewrites were discarded for dropping required details or being refused.")
        log(rewrite_note)

    defenses = parse_defenses(a.defenses)
    real = [t for t in targets if not getattr(t, "simulated", False)]
    per_model = len(cases) * a.repeats
    print(f"Plan: {len(cases)} prompts × {a.repeats} trials × {len(targets)} target(s) = "
          f"{per_model * len(targets)} requests ({per_model * len(real)} to real APIs)."
          + (f" Rate limit {a.rpm:g}/min: about {per_model / a.rpm:.0f} min per model." if a.rpm and real else ""),
          file=sys.stderr)
    if a.dry_run:
        for c in cases[:10]:
            print(f"  {c.id}", file=sys.stderr)
        return 0
    if real and not a.yes and per_model * len(real) > 50 and sys.stdin.isatty():
        if input("Paid API providers may charge for these requests. Continue? [y/N] ").strip().lower() != "y":
            return 1

    results = []
    for t in targets:
        log(f"\n=== {t.name} ===")
        results.append(run_suite(cases, t, defenses, repeats=a.repeats, workers=a.workers, rpm=a.rpm,
                                 progress=log))

    meta = {"source": source, "generator": gen_meta, "rewrite": rewrite_note}
    paths = write_reports(results, a.out, meta)
    print("\nResults")
    for res in results:
        lo, hi = res.ci
        tag = "  [SIMULATED]" if res.simulated else ""
        err = f", {res.total_errors} errors" if res.total_errors else ""
        print(f"  {res.target:40} {res.asr * 100:5.1f}% attacks succeeded  (95% CI {lo * 100:.0f}-{hi * 100:.0f}%, "
              f"{res.total_trials} trials{err}){tag}")
        if res.total_trials == 0 and res.total_errors:
            first = next(t.error for s in res.summaries for t in s.trials if t.error)
            print(f"    every request failed. First error: {first}")
    print(f"\nReport: {paths['html']}\nAlso:   {paths['md']}, {paths['json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

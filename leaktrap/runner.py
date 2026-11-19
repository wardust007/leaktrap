"""Runs attack prompts against one or more targets and collects results."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .defenses import apply_input_defenses, apply_output_defenses
from .detectors import detect
from .models import AttackCase, CaseSummary, TrialResult, wilson
from .scenario import build_messages, fill, new_scenario
from .targets import Target


@dataclass
class RunResult:
    target: str
    simulated: bool
    defenses: list[str]
    repeats: int
    started: str
    finished: str = ""
    summaries: list[CaseSummary] = field(default_factory=list)

    @property
    def total_trials(self) -> int:
        return sum(s.valid_trials for s in self.summaries)

    @property
    def total_successes(self) -> int:
        return sum(s.successes for s in self.summaries)

    @property
    def total_errors(self) -> int:
        return sum(s.errors for s in self.summaries)

    @property
    def asr(self) -> float:
        n = self.total_trials
        return self.total_successes / n if n else 0.0

    @property
    def ci(self) -> tuple[float, float]:
        return wilson(self.total_successes, self.total_trials)

    def group(self, key: Callable[[AttackCase], list[str]]) -> dict[str, tuple[int, int]]:
        """{group: (successes, valid_trials)}"""
        out: dict[str, list[int]] = {}
        for s in self.summaries:
            for g in key(s.case):
                acc = out.setdefault(g, [0, 0])
                acc[0] += s.successes
                acc[1] += s.valid_trials
        return {k: (v[0], v[1]) for k, v in sorted(out.items())}


def _one_trial(case: AttackCase, target: Target, defenses: list[str], t: int) -> TrialResult:
    sc = new_scenario()
    doc = fill(case.document, sc)
    base = build_messages(case, sc)
    messages, doc = apply_input_defenses(base, doc, defenses)
    if doc is not None:
        messages = [messages[0], build_messages(case, sc, document_override=doc)[1]]
    prompt = messages[1]["content"].replace(sc.canary, "<SECRET>")
    resp = target.respond(messages, case, sc)
    if resp.error:
        return TrialResult(case.id, t, False, "", "", error=resp.error, prompt=prompt)
    final = apply_output_defenses(resp.text, sc, defenses)
    evidence = detect(case, sc, final)
    return TrialResult(case.id, t, evidence is not None, (evidence or "").replace(sc.canary, "<SECRET>"),
                       final[:600].replace(sc.canary, "<SECRET>"), prompt=prompt)


def run_suite(cases: list[AttackCase], target: Target, defenses: list[str], repeats: int = 1,
              workers: int = 1, delay: float = 0.0,
              progress: Optional[Callable[[str], None]] = None) -> RunResult:
    result = RunResult(target=target.name, simulated=getattr(target, "simulated", False), defenses=defenses,
                       repeats=repeats, started=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    summaries = {c.id: CaseSummary(case=c) for c in cases}
    jobs = [(c, t) for c in cases for t in range(1, repeats + 1)]
    lock = threading.Lock()
    done = [0]
    stop_after_errors = max(10, len(jobs) // 5)

    def work(job):
        case, t = job
        tr = _one_trial(case, target, defenses, t)
        with lock:
            summaries[case.id].trials.append(tr)
            done[0] += 1
            if progress:
                status = "ERROR " + (tr.error or "")[:80] if tr.error else (
                    "ATTACK SUCCEEDED" if tr.succeeded else "blocked")
                progress(f"[{target.name}] {done[0]}/{len(jobs)} {case.id} #{t}: {status}")
        if delay:
            time.sleep(delay)
        return tr

    if workers <= 1:
        errors = 0
        for job in jobs:
            tr = work(job)
            errors = errors + 1 if tr.error else 0
            if errors >= stop_after_errors:  # e.g. bad key or wrong model name: stop wasting time
                if progress:
                    progress(f"[{target.name}] stopping: {errors} errors in a row")
                break
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(work, jobs))

    for s in summaries.values():
        s.trials.sort(key=lambda tr: tr.trial)
    result.summaries = list(summaries.values())
    result.finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result

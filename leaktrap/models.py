"""Core data types."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AttackCase:
    """One attack prompt (hand-written in a suite file or produced by the generator)."""

    id: str
    name: str
    category: str              # e.g. "secret-leak"
    vector: str                # "direct" (user turn) or "indirect" (inside a document)
    owasp: list[str]           # OWASP Top 10 for LLM Applications 2026 IDs
    atlas: list[str]           # MITRE ATLAS technique IDs
    severity: str              # low / medium / high / critical
    user_message: str
    success: dict[str, Any]    # how a successful attack is detected
    document: Optional[str] = None
    description: str = ""
    technique: str = "handwritten"
    goal: str = ""
    language: str = "en"


@dataclass
class Scenario:
    """The LLM application under test, built fresh for every trial."""

    system_prompt: str
    canary: str                # secret that must never leave the app
    marker: str                # harmless token used to prove injected instructions ran
    attacker_domain: str = "attacker.example"
    allowed_recipient: str = "customer@acme-customer.example"


@dataclass
class TargetResponse:
    text: str
    raw: Any = None
    error: Optional[str] = None


@dataclass
class TrialResult:
    case_id: str
    trial: int
    succeeded: bool            # True = the attack worked (bad for the app)
    evidence: str
    response_excerpt: str
    error: Optional[str] = None
    prompt: str = ""           # what was sent as the user turn (secret masked)


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass
class CaseSummary:
    case: AttackCase
    trials: list[TrialResult] = field(default_factory=list)

    @property
    def successes(self) -> int:
        return sum(1 for t in self.trials if t.succeeded)

    @property
    def errors(self) -> int:
        return sum(1 for t in self.trials if t.error)

    @property
    def valid_trials(self) -> int:
        return sum(1 for t in self.trials if not t.error)

    @property
    def asr(self) -> float:
        """Attack success rate over trials that did not error."""
        n = self.valid_trials
        return self.successes / n if n else 0.0

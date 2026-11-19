# LeakTrap

**Generate prompt-injection attacks, fire them at real AI models, and get a professional
assessment report.**

LeakTrap builds attack prompts from 6 attacker goals × 19 techniques × 3 languages
(English, Arabic, Spanish), runs them against GPT, Claude, open models through OpenRouter, or a
model on your own computer with Ollama, and writes an HTML report: success rate per model with
confidence intervals, which techniques work best, the exact prompts that broke each model,
and how to fix it. Every finding is mapped to the **OWASP Top 10 for LLM Applications (2026)**
and **MITRE ATLAS**.

## Quick start

```bash
pip install -e .

# 1. See what a report looks like (no API key needed, results are SIMULATED)
leaktrap run --target demo:simulated

# 2. Test a real model
export OPENAI_API_KEY=sk-...          # Windows: set OPENAI_API_KEY=sk-...
leaktrap run --target openai:gpt-5.6-sol

# 3. Compare several models in one report
leaktrap run --target openai:gpt-5.6-sol --target anthropic:claude-sonnet-5-5 --target ollama:qwen3:8b
```

Open `results/report.html` in your browser.

## Targets

| Target | Example | Needs |
|---|---|---|
| OpenAI | `openai:gpt-5.6-sol` | `OPENAI_API_KEY` |
| Anthropic | `anthropic:claude-sonnet-5-5` | `ANTHROPIC_API_KEY` |
| OpenRouter (hundreds of models, one key) | `openrouter:meta-llama/llama-4-scout` | `OPENROUTER_API_KEY` |
| Ollama (runs on your computer, free) | `ollama:qwen3:8b` | [Ollama](https://ollama.com) running |
| Any OpenAI-compatible API | `compatible:my-model --base-url https://...` | `LEAKTRAP_API_KEY` |
| Built-in stand-ins | `demo:simulated`, `demo:compromised`, `demo:refuser` | nothing (results marked SIMULATED) |

Model names change often; use the exact ID from the provider's model list.

## How it works

1. **The app under test.** A support chatbot whose hidden instructions contain a secret
   reference code and an email tool it may only use for one verified customer. Every
   trial gets a fresh random secret.
2. **Attack generation.** Each prompt combines a *goal* (leak the secret, leak it disguised,
   hijack the reply, exfiltrate it through an image link, misuse the email tool, inject
   executable HTML) with a *technique* (fake system notices, developer mode, role-play, forged
   chat history, base64, payload splitting, invisible characters, look-alike letters, urgency,
   another language, or hidden inside an email, web page or vendor notice). `--count` picks a
   balanced, reproducible sample (`--seed`).
3. **Optional AI attacker.** `--rewrite-with openai:gpt-5.6-sol` asks a model to rewrite every
   prompt in its own words, the way a human attacker iterates. Rewrites that drop a detail the
   scoring needs are discarded.
4. **Scoring without a judge model.** The tool planted the secret, so it knows exactly what a
   leak looks like. It checks each reply for the secret (plain, spaced, reversed, ROT13, base64
   or hex), the marker word, links to the attacker's domain, executable markup, and unapproved
   tool calls. A judge model would cost money, vary between runs, and could itself be tricked.
5. **Repeats and statistics.** Each prompt runs `--repeats` times per model; the report gives a
   95% confidence interval for every rate.
6. **Defenses.** Add `--defenses all` (or `spotlight,redact,link-strip,tool-guard`) to measure
   how much each protection actually helps.

## Useful commands

```bash
leaktrap techniques                                  # list goals and techniques
leaktrap generate --count 60 --out prompts.jsonl     # save prompts to review or edit
leaktrap run --prompts prompts.jsonl --target ...    # run exactly those prompts
leaktrap run --target ... --goals tool-abuse,link-exfil --repeats 5
leaktrap run --target ... --dry-run                  # show how many requests it would send
```

A default run is 60 prompts × 2 trials = 120 requests per model, usually a few cents on a small
paid model. LeakTrap asks before sending more than 50 paid requests (skip with `--yes`).

## Output

- `report.html`: executive summary, model comparison chart, weakness tables by goal,
  technique, vector, language and OWASP risk, key findings with the exact prompt and reply,
  recommendations, method and limitations, and an appendix of every prompt.
- `report.md`: the same summary for GitHub.
- `results.json`: every trial, for your own analysis.

Secrets are masked as `<SECRET>` in every output file. API keys are never written anywhere.

## Real-world background

The link-exfiltration goal reproduces the channel used in **EchoLeak (CVE-2025-32711)**, a
zero-click prompt injection in Microsoft 365 Copilot that leaked data through a markdown
image triggered by a single email. Indirect injection against AI agents (attacks hidden in
web pages and documents) has since been observed in the wild by Google and Palo Alto
Networks Unit 42.

## Tests

```bash
pip install pytest && python -m pytest
```

49 tests, including real HTTP calls to local fake OpenAI and Anthropic servers (parameter
fallbacks for newer models, rate-limit retries, error handling).

## Responsible use

Only test models and applications you own or are authorized to test. Prompts target a
planted fake secret, never real data. Follow each provider's usage policies.

MIT License.

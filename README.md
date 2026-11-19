<p align="center">
  <img src="assets/banner.svg" alt="LeakTrap: catch AI models leaking secrets" width="100%">
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-00f0ff?style=for-the-badge&logo=python&logoColor=white&labelColor=0b0420">
  <img alt="Tests" src="https://img.shields.io/badge/tests-52%20passing-39ff14?style=for-the-badge&labelColor=0b0420">
  <img alt="OWASP" src="https://img.shields.io/badge/OWASP%20LLM-2026-ff2bd6?style=for-the-badge&labelColor=0b0420">
  <img alt="MITRE ATLAS" src="https://img.shields.io/badge/MITRE-ATLAS-9d4dff?style=for-the-badge&labelColor=0b0420">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-ffb400?style=for-the-badge&labelColor=0b0420">
</p>

<p align="center">
  <b>🕵️ Generate prompt-injection attacks · ⚔️ fire them at real AI models · 📊 get a neon security report</b><br>
  <sub>GPT · Claude · Gemini · Groq · OpenRouter · Ollama, with free options and no credit card needed</sub>
</p>

<p align="center">
  <a href="#-quick-start-5-minutes">🚀 Quick start</a> ·
  <a href="#-run-it-for-free">💸 Free options</a> ·
  <a href="#-how-it-works">🧠 How it works</a> ·
  <a href="#-the-attack-arsenal">🧨 Attacks</a> ·
  <a href="#-the-report">📊 Report</a> ·
  <a href="#-troubleshooting">🛠️ Help</a>
</p>

---

## 🤔 What is this?

AI chatbots are given **hidden instructions** and often **secrets**: API keys, internal codes, customer data. Attackers try to trick them into leaking those secrets or doing things they shouldn't. This is called **prompt injection**, and it's the **#1 risk** on the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/).

**LeakTrap is a sting operation for AI models:**

1. 🔑 It gives a test chatbot a **fake secret** and tells it never to reveal it.
2. 🧨 It throws **126 different attacks** at it: fake system messages, forged chat history, base64, invisible characters, look-alike letters, attacks in **Arabic** and **Spanish**, instructions hidden inside emails and web pages…
3. 🔍 It checks every reply for the secret (even disguised), and for sneaky links, malicious HTML and unauthorized emails.
4. 📊 It writes a **neon HTML report**: which model broke, how often, the exact prompt that broke it, and how to fix it.

> 💡 **Not a chat plugin.** LeakTrap is a small program that runs on your computer and talks to AI models through their API, the same way any app does.

---

## 🚀 Quick start (5 minutes)

### Step 1 · Install Python 🐍

Download **Python 3.10 or newer** from [python.org/downloads](https://www.python.org/downloads/).

> ⚠️ **Windows:** on the first install screen, tick **"Add Python to PATH"**.

### Step 2 · Get LeakTrap 📦

**Option A, no Git needed:** click the green **`<> Code`** button on this page → **Download ZIP** → unzip it.

**Option B, with Git:**
```bash
git clone https://github.com/Maytham-MJ/leaktrap.git
```

### Step 3 · Open a terminal in the folder 💻

| 🪟 Windows | 🍎 Mac | 🐧 Linux |
|---|---|---|
| Open the `leaktrap` folder, click the address bar, type `cmd`, press **Enter** | Right-click the `leaktrap` folder → **New Terminal at Folder** | `cd leaktrap` |

### Step 4 · Install it ⚙️

```bash
pip install -e .
```
<sub>Mac/Linux: if `pip` isn't found, use `pip3`.</sub>

### Step 5 · Try it with no key at all 🎮

```bash
leaktrap run --target demo:simulated
```
This uses a built-in **fake** model so you can see the report right away. Open **`results/report.html`** in your browser. 🎉

### Step 6 · Attack a real AI model 🎯

Grab a **free** Gemini key at [aistudio.google.com](https://aistudio.google.com) → **Get API key** (no card needed), then:

<table>
<tr><th>🪟 Windows</th><th>🍎 Mac / 🐧 Linux</th></tr>
<tr><td>

```bat
set GEMINI_API_KEY=paste-your-key
leaktrap run --target gemini:gemini-3.8-flash --free
```

</td><td>

```bash
export GEMINI_API_KEY=paste-your-key
leaktrap run --target gemini:gemini-3.8-flash --free
```

</td></tr>
</table>

⏱️ About 2 minutes later, open **`results/report.html`**. That's a real security assessment of a real AI model.

---

## 💸 Run it for free

| | Provider | Get a key | Command |
|---|---|---|---|
| 🏠 | **Ollama**: runs on *your* computer, unlimited & private | No key, just install [ollama.com](https://ollama.com) then `ollama pull qwen3:8b` | `leaktrap run --target ollama:qwen3:8b` |
| 🔷 | **Google Gemini** | Free at [aistudio.google.com](https://aistudio.google.com) | `leaktrap run --target gemini:gemini-3.8-flash --free` |
| ⚡ | **Groq** (super fast open models) | Free at [console.groq.com](https://console.groq.com) | `leaktrap run --target groq:openai/gpt-oss-120b --free` |
| 🌐 | **OpenRouter** `:free` models | Free at [openrouter.ai](https://openrouter.ai) | `leaktrap run --target openrouter:<model>:free --free` |

🧯 **`--free`** keeps you inside free limits: 24 attacks, 1 try each, max 15 requests/minute.
OpenRouter's free models allow only ~50 requests a day, so test one model per day there.

🔒 Free tiers may use what you send to train their models. LeakTrap only sends **test attacks with a fake secret**, so nothing private ever leaves your computer.

<details>
<summary>💳 <b>Paid models: GPT, Claude and more</b></summary>

| Provider | Key variable | Example target |
|---|---|---|
| OpenAI (GPT) | `OPENAI_API_KEY` | `openai:gpt-5.6-sol` |
| Anthropic (Claude) | `ANTHROPIC_API_KEY` | `anthropic:claude-sonnet-5-5` |
| OpenRouter | `OPENROUTER_API_KEY` | `openrouter:meta-llama/llama-4-scout` |
| Any OpenAI-compatible API | `LEAKTRAP_API_KEY` | `compatible:my-model --base-url https://…` |

A default run is 60 attacks × 2 tries = 120 requests per model, usually a few cents on a small model. LeakTrap asks before sending more than 50 paid requests. Model names change often, so copy the exact ID from your provider's model list.
</details>

### 🥊 Model vs. model

Put several models in one report:
```bash
leaktrap run --target gemini:gemini-3.8-flash --target groq:openai/gpt-oss-120b --target ollama:qwen3:8b --free
```

---

## 🧠 How it works

<p align="center"><img src="assets/how-it-works.svg" alt="Generate, plant, attack, detect, report" width="100%"></p>

**Why no "AI judge"?** Many tools ask a second AI whether an attack worked. That costs money, gives different answers each run, and the judge can be tricked by the same attack. LeakTrap planted the secret itself, so it knows *exactly* what a leak looks like. Plain string checks are enough: fast, free, and impossible to fool.

It catches the secret even when it's disguised: 🔤 plain · ␣ spaced · 🔄 reversed · 🔁 ROT13 · 🧬 base64 · 🔢 hex.

---

## 🧨 The attack arsenal

Every attack = **🎯 a goal** × **🎭 a technique**. Run `leaktrap techniques` to see them all.

<table>
<tr><th>🎯 Goals (what the attacker wants)</th><th>🎭 Techniques (how they disguise it)</th></tr>
<tr><td valign="top">

| Goal | Severity |
|---|---|
| 🗝️ Leak the secret | 🔴 high |
| 🥷 Leak it in disguise (base64) | 🔴 high |
| 🦜 Hijack the reply | 🟠 medium |
| 🖼️ Exfiltrate through an image link | 🟣 critical |
| 📧 Misuse the email tool | 🟣 critical |
| 💉 Inject executable HTML | 🔴 high |

</td><td valign="top">

**Typed by the user:** fake system notice · developer mode · role-play persona · forged chat history · base64 wrapping · payload splitting · invisible characters · look-alike Cyrillic letters · "sandwich" between normal questions · urgency · 🇸🇦 Arabic · 🇪🇸 Spanish

**Hidden in a document** 📄 *(the scariest kind)*: note in an email · HTML comment · fake "end of document" escape · fake system block · secret P.S. · invisible characters

</td></tr>
</table>

🤖 **AI attacker mode:** `--rewrite-with gemini:gemini-3.8-flash` asks an AI to rewrite every attack in its own words, the way a real attacker iterates.

🗺️ Every finding maps to **OWASP Top 10 for LLM Applications (2026)** and **MITRE ATLAS** technique IDs.

---

## 📊 The report

<p align="center">
  🔗 <a href="https://maytham-mj.github.io/leaktrap/"><b>See a live sample report</b></a> (simulated data, so you can see the layout)
</p>

What's inside:
- ⚡ **Executive summary**: attack success rate per model, with 95% confidence intervals
- 📈 **Model comparison chart** in full neon
- 🔥 **Heat maps**: weakness by goal, technique, direct vs. hidden, language, and OWASP risk
- 🧾 **Key findings**: the *exact* prompt that worked and what the model replied (secret masked)
- 🛡️ **Recommendations**: how to fix each hole that was found
- 📚 **Method & limitations** and an appendix of every attack

Also saved: `report.md` (for GitHub) and `results.json` (every single trial, for your own analysis).

---

## 🔬 Research finding

Can output filters alone protect a chatbot? We ran the built-in 16-case suite against a **fully compromised** stand-in model with three output filters on:

<p align="center"><img src="assets/defense-coverage.svg" alt="Output filters block 4 of 8 attack categories" width="85%"></p>

**Takeaway:** filters stop leaked links, bad HTML and rogue emails, but **disguised secrets and obeyed instructions slip through every time.** You need defenses before the model, not just after it. 📄 Full write-up: **[docs/PAPER.md](docs/PAPER.md)**.

Reproduce it yourself:
```bash
leaktrap run --target demo:compromised --prompts builtin --defenses redact,link-strip,tool-guard --repeats 3
```

---

## 🌍 Why it matters: the real world

- 🚨 **EchoLeak (CVE-2025-32711, CVSS 9.3):** a single email made Microsoft 365 Copilot leak company data through a **markdown image link**, with zero clicks. LeakTrap's 🖼️ link-exfiltration goal tests exactly this trick.
- 🕸️ **2026:** Google and Palo Alto Networks Unit 42 reported **indirect prompt injection in the wild**: attacks hidden in web pages that target AI agents. That's LeakTrap's 📄 "hidden in a document" category.

---

## 🧰 All commands

| Command | What it does |
|---|---|
| `leaktrap run --target <provider:model>` | 🎯 attack a model and write the report |
| `leaktrap run ... --free` | 💸 stay inside free-tier limits |
| `leaktrap run ... --count 120 --repeats 3` | 🔁 more attacks, more tries = more reliable numbers |
| `leaktrap run ... --goals tool-abuse,link-exfil` | 🎯 only certain attack goals |
| `leaktrap run ... --defenses all` | 🛡️ turn on LeakTrap's defenses and measure how much they help |
| `leaktrap run ... --rewrite-with <provider:model>` | 🤖 let an AI write extra attack variations |
| `leaktrap run ... --dry-run` | 👀 show how many requests it would send, then stop |
| `leaktrap generate --out prompts.jsonl` | 📝 save the attacks to read or edit |
| `leaktrap run --prompts prompts.jsonl ...` | ♻️ run your own edited attacks |
| `leaktrap techniques` | 📚 list every goal and technique |

---

## 🛠️ Troubleshooting

<details><summary>❌ <code>'leaktrap' is not recognized</code> / <code>command not found</code></summary>

Python's scripts folder isn't on your PATH. Use this instead, which works everywhere:
```bash
python -m leaktrap run --target demo:simulated
```
On Windows you can also reinstall Python with **"Add Python to PATH"** ticked.
</details>

<details><summary>🔑 <code>set GEMINI_API_KEY ...</code> error, or the key "isn't set"</summary>

The key only lasts for that terminal window. Set it again in every new window, in the **same** window you run LeakTrap from. Windows uses `set`, Mac/Linux use `export`. No spaces around `=`, no quotes needed.
</details>

<details><summary>⛔ <code>HTTP 404 ... model does not exist</code></summary>

The model name is wrong or retired. Copy the exact ID from your provider's model list and use `provider:that-id`.
</details>

<details><summary>🐢 <code>HTTP 429</code> / rate limited</summary>

You hit the free tier's limit. LeakTrap already retries automatically; add `--free` or lower the speed with `--rpm 10`. OpenRouter free models: wait until tomorrow (about 50 requests/day).
</details>

<details><summary>🏠 Ollama: connection refused</summary>

Start Ollama first (open the app, or run `ollama serve`) and make sure the model is downloaded: `ollama pull qwen3:8b`.
</details>

---

## 🗂️ Project layout

```
leaktrap/
├── 🧪 generator.py   builds the 126 attacks (goals × techniques × languages)
├── 🎯 targets.py     talks to OpenAI, Anthropic, Gemini, Groq, OpenRouter, Ollama
├── 🔍 detectors.py   spots leaks, links, HTML and rogue tool calls
├── 🛡️ defenses.py    spotlight, redact, link-strip, tool-guard
├── 🤖 rewriter.py    AI attacker mode
├── 🏃 runner.py      trials, rate limits, statistics
├── 📊 report.py      the neon HTML / Markdown / JSON report
└── 💻 cli.py         the leaktrap command
tests/                52 tests, including real HTTP calls to fake GPT & Claude servers
docs/                 research paper + live sample report
```

Run the tests: `pip install pytest && python -m pytest` ✅

---

## ⚖️ Responsible use

🟢 Test models and apps **you own or are allowed to test**. 🟢 LeakTrap only targets a **fake planted secret**, never real data. 🔴 Don't point it at other people's systems without written permission. See [SECURITY.md](SECURITY.md).

## 🗺️ Roadmap

- [ ] 🌐 Web version: run attacks right in the browser
- [ ] 💬 Multi-turn attacks (slow social engineering over several messages)
- [ ] 🤖 AI-agent attacks (OWASP Agentic Top 10)
- [ ] 📈 Track results over time and fail a CI build when a model gets worse

## 👤 Author

**Maytham Alkhailani**: AI Security & Threat/Vulnerability Engineering · M.S. Cybersecurity
Also by me: 🎣 [PhishLens](https://github.com/Maytham-MJ/phishlens), a phishing email verifier.

<p align="center"><sub>⭐ If LeakTrap helped you, star the repo. MIT licensed.</sub></p>

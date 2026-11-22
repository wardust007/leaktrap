# 📜 Changelog

## v0.5.0 · November 2026
- 🏢 **Client engagements (`leaktrap client`):** attack a client's real chatbot over HTTP, under a signed engagement file
- 🪤 **Canary secrets:** `client init` creates a fake secret and setup instructions for the client to plant in their bot
- 🚧 **Safety rails:** authorization window, allowed hosts only, blocked out-of-scope redirects, hard request budget, one request at a time, stop on 401/403
- 🧾 **Audit log:** every request to a client is recorded in `audit.jsonl` (no headers or tokens)
- 🔌 Works with JSON, plain-text and streaming (server-sent events) chatbot APIs; `{{session}}` gives every request a fresh session
- 📊 Reports name the client, the signer and the scope
- ✅ Tests now pass on Windows without UTF-8 mode

## v0.4.0 · November 2026
- 🖱️ **Double-click launchers:** `Start LeakTrap.bat` (Windows) and `Start LeakTrap.command` (Mac) open the dashboard. No typing needed
- 🛡️ **Dashboard (`python -m leaktrap ui`):** pick a model from a menu, paste a key, press Launch, and watch a live log and a neon scoreboard
- 📄 The full HTML report opens from the dashboard with one click
- 🔒 The dashboard runs only on your own computer (127.0.0.1). Keys are used for the run and never saved

## v0.3.1 · November 2026
- 🚀 **Zero install:** no dependencies at all. Clone the repo and run `python -m leaktrap`, nothing else needed
- 📦 Built-in suite is now JSON; YAML suites still work if PyYAML is installed (`pip install leaktrap[yaml]`)
- ✅ GitHub now tests the README Quick start on Windows, Mac and Linux on every push

## v0.3.0 · November 2026
- 🎬 **`leaktrap replay`:** watch one attack hit a model live, with LEAKED / BLOCKED verdicts and a success rate
- 🆔 **`leaktrap list`:** every attack ID, filterable by goal

## v0.2.0 · November 2026
- 🧪 **Attack generator:** 126 prompts from 6 goals × 19 techniques × 3 languages (English, Arabic, Spanish)
- 🎯 **Real models:** OpenAI, Anthropic, Google Gemini, Groq, OpenRouter, Ollama, any OpenAI-compatible API
- 💸 **Free mode:** `--free` stays inside free-tier limits; built-in rate limiting (`--rpm`)
- 🤖 **AI attacker mode:** `--rewrite-with` lets a model write new attack variations
- 📊 **Neon assessment report:** model comparison, heat maps, confidence intervals, findings, recommendations
- 🔁 Automatic retries on rate limits; handles newer GPT models that reject some settings
- ✅ 52 tests, including real HTTP calls to fake GPT and Claude servers

## v0.1.0 · November 2026
- 🔬 First version (working name InjectScope): 16-case suite, deterministic canary detection,
  switchable defenses, research paper on output-filter coverage

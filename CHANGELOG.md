# 📜 Changelog

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

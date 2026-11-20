"""LeakTrap dashboard: a point-and-click web page on your own computer.

Start it with `python -m leaktrap ui` (or double-click the Start LeakTrap launcher).
It runs on 127.0.0.1 only, so nothing is shared with the network. API keys typed into
the page are passed to the test run in memory and are never written to disk.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__

KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}

# What the page offers. Models are examples you can change in the box.
PROVIDERS = [
    {"id": "demo", "label": "Practice mode", "icon": "🧪", "model": "simulated",
     "note": "No key needed. Uses a built-in stand-in chatbot so you can see a full report.", "free": True},
    {"id": "gemini", "label": "Google Gemini", "icon": "🟢", "model": "gemini-3.8-flash",
     "note": "Free key at aistudio.google.com, no card needed.", "free": True},
    {"id": "groq", "label": "Groq", "icon": "🟣", "model": "openai/gpt-oss-120b",
     "note": "Free key at console.groq.com, no card needed.", "free": True},
    {"id": "ollama", "label": "Ollama (on your PC)", "icon": "🦙", "model": "qwen3:8b",
     "note": "Runs on your own computer. Install Ollama and pull the model first. No key.", "free": True},
    {"id": "openrouter", "label": "OpenRouter", "icon": "🔀", "model": "meta-llama/llama-4-scout:free",
     "note": "Models ending in :free cost nothing. Key at openrouter.ai.", "free": False},
    {"id": "openai", "label": "OpenAI (GPT)", "icon": "🤖", "model": "gpt-5.6-sol",
     "note": "Paid. Charges your OpenAI account.", "free": False},
    {"id": "anthropic", "label": "Anthropic (Claude)", "icon": "🟠", "model": "claude-sonnet-5-5",
     "note": "Paid. Charges your Anthropic account.", "free": False},
]

TARGET_RE = re.compile(r"^(demo|openai|anthropic|gemini|groq|openrouter|ollama):[A-Za-z0-9._:/\-]{1,120}$")

JOB_LOCK = threading.Lock()
JOB: dict = {"status": "idle", "log": [], "proc": None, "run_dir": None, "target": "",
             "started": None, "finished": None, "results": [], "error": ""}


# ----------------------------------------------------------------------------- running a test

def _read_results(run_dir: Path) -> list[dict]:
    data = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    out = []
    for t in data.get("targets", []):
        o = t["overall"]
        out.append({"target": t["target"], "simulated": t["simulated"], "asr": o["asr"],
                    "ci95": o["ci95"], "successes": o["successes"], "trials": o["trials"],
                    "errors": o["errors"]})
    return out


def _run_job(target: str, key: str, free: bool, defenses: str, run_dir: Path) -> None:
    cmd = [sys.executable, "-m", "leaktrap", "run", "--target", target, "--out", str(run_dir),
           "--defenses", defenses, "--yes"]
    if free:
        cmd.append("--free")
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    provider = target.split(":", 1)[0]
    if key and provider in KEY_ENV:
        env[KEY_ENV[provider]] = key
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", env=env,
                                cwd=str(Path.cwd()))
    except OSError as e:
        with JOB_LOCK:
            JOB.update(status="error", error=f"Could not start the test: {e}", finished=time.time())
        return
    with JOB_LOCK:
        JOB["proc"] = proc
    for line in proc.stdout:
        with JOB_LOCK:
            JOB["log"].append(line.rstrip())
            del JOB["log"][:-400]
    code = proc.wait()
    with JOB_LOCK:
        JOB["proc"] = None
        JOB["finished"] = time.time()
        if JOB.get("stop_requested"):
            JOB["status"] = "stopped"
            JOB["error"] = "You stopped the test. No report was written."
        elif code == 0 and (run_dir / "results.json").exists():
            JOB["results"] = _read_results(run_dir)
            JOB["status"] = "done"
        else:
            JOB["status"] = "error"
            JOB["error"] = "The test stopped with an error. The last lines of the log explain why."


def start_job(target: str, key: str, free: bool, defenses: str) -> str | None:
    with JOB_LOCK:
        if JOB["status"] == "running":
            return "A test is already running. Wait for it to finish or press Stop."
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path.cwd() / "results" / f"dashboard-{stamp}"
    with JOB_LOCK:
        JOB.update(status="running", log=[f"Starting {target} ..."], run_dir=run_dir, target=target,
                   started=time.time(), finished=None, results=[], error="", stop_requested=False)
    threading.Thread(target=_run_job, args=(target, key, free, defenses, run_dir), daemon=True).start()
    return None


def stop_job() -> None:
    with JOB_LOCK:
        proc = JOB.get("proc")
        JOB["stop_requested"] = True
        if proc and proc.poll() is None:
            proc.terminate()


def status_payload() -> dict:
    with JOB_LOCK:
        run_dir = JOB["run_dir"]
        has_report = bool(run_dir and (run_dir / "report.html").exists() and JOB["status"] == "done")
        elapsed = None
        if JOB["started"]:
            elapsed = round((JOB["finished"] or time.time()) - JOB["started"])
        return {"status": JOB["status"], "log": JOB["log"][-160:], "results": JOB["results"],
                "target": JOB["target"], "error": JOB["error"], "elapsed": elapsed,
                "report": has_report, "version": __version__}


# ----------------------------------------------------------------------------- web server

class Handler(BaseHTTPRequestHandler):
    server_version = "LeakTrap"

    def log_message(self, *args):  # keep the terminal quiet
        return

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.replace("__PROVIDERS__", json.dumps(PROVIDERS)).encode("utf-8"),
                       "text/html; charset=utf-8")
        elif self.path.startswith("/api/status"):
            self._json(200, status_payload())
        elif self.path.startswith("/report"):
            with JOB_LOCK:
                run_dir = JOB["run_dir"]
            path = run_dir / "report.html" if run_dir else None
            if path and path.exists():
                self._send(200, path.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(404, b"No report yet. Run a test first.", "text/plain; charset=utf-8")
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "Could not read the request."})
        if self.path == "/api/run":
            target = str(body.get("target", "")).strip()
            if not TARGET_RE.match(target):
                return self._json(400, {"error": "Pick a model from the list, or check the model name."})
            key = str(body.get("key", "")).strip()
            if "\n" in key or "\r" in key or len(key) > 300:
                return self._json(400, {"error": "That key does not look right. Paste only the key."})
            defenses = "all" if body.get("defenses") == "all" else "none"
            err = start_job(target, key, bool(body.get("free")), defenses)
            return self._json(409 if err else 200, {"error": err} if err else {"ok": True})
        if self.path == "/api/stop":
            stop_job()
            return self._json(200, {"ok": True})
        self._json(404, {"error": "Unknown request."})


def serve(port: int = 8765, open_browser: bool = True) -> int:
    server = None
    for p in range(port, port + 20):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if server is None:
        print(f"Could not find a free port near {port}. Close other programs and try again.", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{port}/"
    print("\n  🛡️  LeakTrap dashboard is running.")
    print(f"  👉  Open: {url}")
    print("  ⏹  Press Ctrl+C here (or close this window) to stop.\n")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_job()
        server.server_close()
    return 0


# ----------------------------------------------------------------------------- the page

PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LeakTrap 🛡️ Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;800&family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#05060f;--panel:#0b0d1f;--cyan:#00f0ff;--mag:#ff2bd6;--lime:#39ff14;--amber:#ffb000;--text:#e6e9ff;--dim:#8a90c2}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#1a0b33 0%,var(--bg) 60%);color:var(--text);font-family:Inter,system-ui,sans-serif;min-height:100vh}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(255,255,255,.025) 0 1px,transparent 1px 3px);z-index:0}
.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-family:Orbitron,sans-serif;font-weight:800;font-size:44px;margin:0;letter-spacing:3px;text-shadow:0 0 12px var(--cyan),0 0 30px rgba(0,240,255,.5);background:linear-gradient(90deg,var(--cyan),var(--mag));-webkit-background-clip:text;color:transparent}
.sub{color:var(--dim);margin:8px 0 26px;font-size:16px}
.grid{display:grid;grid-template-columns:1.05fr 1fr;gap:18px}
@media(max-width:820px){.grid{grid-template-columns:1fr}h1{font-size:30px}}
.card{background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.01)),var(--panel);border:1px solid rgba(0,240,255,.35);border-radius:16px;padding:20px;box-shadow:0 0 22px rgba(0,240,255,.12),inset 0 0 22px rgba(255,43,214,.05)}
.card h2{font-family:Orbitron,sans-serif;font-size:15px;letter-spacing:2px;margin:0 0 14px;color:var(--cyan)}
label{display:block;font-size:13px;color:var(--dim);margin:14px 0 6px}
select,input{width:100%;background:#070818;color:var(--text);border:1px solid rgba(255,43,214,.45);border-radius:10px;padding:11px 12px;font:15px Inter,sans-serif;outline:none}
select:focus,input:focus{box-shadow:0 0 0 2px rgba(0,240,255,.5)}
.note{font-size:13px;color:var(--dim);margin-top:8px;min-height:18px}
.opt{display:flex;align-items:center;gap:10px;margin-top:14px;font-size:14px}
.opt input{width:auto;accent-color:var(--lime)}
.btn{margin-top:20px;width:100%;font-family:Orbitron,sans-serif;font-weight:800;letter-spacing:2px;font-size:16px;padding:16px;border-radius:14px;border:0;cursor:pointer;color:#05060f;background:linear-gradient(90deg,var(--cyan),var(--mag));box-shadow:0 0 18px rgba(0,240,255,.6),0 0 40px rgba(255,43,214,.35);transition:transform .08s}
.btn:hover{transform:translateY(-1px)}.btn:disabled{opacity:.4;cursor:not-allowed;transform:none}
.btn.ghost{background:transparent;color:var(--lime);border:1px solid var(--lime);box-shadow:0 0 14px rgba(57,255,20,.35);text-decoration:none;display:block;text-align:center;font-size:14px;padding:13px;margin-top:12px}
.btn.stop{background:transparent;color:var(--amber);box-shadow:none;border:1px solid var(--amber);font-size:13px;padding:10px;margin-top:10px}
.pill{display:inline-block;font:700 12px 'JetBrains Mono',monospace;padding:6px 10px;border-radius:999px;border:1px solid var(--dim);color:var(--dim)}
.pill.running{color:var(--amber);border-color:var(--amber);box-shadow:0 0 12px rgba(255,176,0,.5);animation:pulse 1.2s infinite}
.pill.done{color:var(--lime);border-color:var(--lime);box-shadow:0 0 12px rgba(57,255,20,.45)}
.pill.error{color:var(--mag);border-color:var(--mag)}
@keyframes pulse{50%{opacity:.5}}
.term{font:12.5px/1.5 'JetBrains Mono',monospace;background:#02030a;border:1px solid rgba(57,255,20,.3);border-radius:12px;height:260px;overflow:auto;padding:12px;color:#b6ffb0;white-space:pre-wrap}
.bar{position:relative;height:30px;border-radius:999px;background:#120f29;overflow:hidden;margin:8px 0 4px;border:1px solid rgba(255,255,255,.08)}
.fill{position:absolute;left:0;top:0;bottom:0;border-radius:999px;background:linear-gradient(90deg,var(--lime),var(--amber),var(--mag));box-shadow:0 0 16px rgba(255,43,214,.6);transition:width .9s ease}
.ci{position:absolute;top:50%;height:6px;transform:translateY(-50%);background:rgba(0,240,255,.55);border-radius:4px;box-shadow:0 0 8px var(--cyan)}
.big{font:800 40px Orbitron,sans-serif;color:var(--text);text-shadow:0 0 14px var(--mag)}
.res{border-top:1px dashed rgba(0,240,255,.25);padding-top:14px;margin-top:14px}
.res:first-child{border-top:0;margin-top:0;padding-top:0}
.res .name{font-weight:600}
.small{font-size:12.5px;color:var(--dim)}
.tag{font:700 11px 'JetBrains Mono',monospace;color:var(--amber);border:1px solid var(--amber);padding:2px 6px;border-radius:6px;margin-left:6px}
.legend{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:18px}
@media(max-width:820px){.legend{grid-template-columns:1fr}}
.lg{background:#070818;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:12px;font-size:13px;color:var(--dim)}
.lg b{color:var(--text);display:block;margin-bottom:4px;font-size:14px}
.empty{color:var(--dim);text-align:center;padding:40px 10px;font-size:15px}
.steps{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 6px}
.err{color:#ffb3ea;margin-top:10px;font-size:14px}
</style></head>
<body><div class="wrap">
<h1>🛡️ LEAKTRAP</h1>
<div class="sub">⚡ Can you trick an AI chatbot into revealing its secret? Pick a model, press launch, and watch the results appear.</div>

<div class="grid">
  <section class="card">
    <h2>① CHOOSE A MODEL</h2>
    <label for="prov">Which AI should we test?</label>
    <select id="prov"></select>
    <div class="note" id="note"></div>

    <label for="model">Model name (you can change it)</label>
    <input id="model" spellcheck="false">

    <div id="keybox">
      <label for="key">API key (only used for this run, never saved)</label>
      <input id="key" type="password" autocomplete="off" placeholder="Paste your key here">
    </div>

    <label for="def">Protection to test</label>
    <select id="def">
      <option value="none">None (the chatbot has no protection)</option>
      <option value="all">All built-in protections turned on</option>
    </select>

    <label class="opt"><input type="checkbox" id="free" checked> Free-tier mode (slower, fits free limits)</label>

    <button class="btn" id="go">🚀 LAUNCH ATTACK</button>
    <button class="btn stop" id="stop" style="display:none">⏹ STOP</button>
    <div class="err" id="err"></div>
  </section>

  <section class="card">
    <h2>② LIVE STATUS</h2>
    <div id="status"><span class="pill">IDLE</span> <span class="small" id="elapsed"></span></div>
    <div class="term" id="log" style="margin-top:14px">Waiting for a launch. Pick a model on the left and press the big button.</div>
  </section>
</div>

<section class="card" style="margin-top:18px">
  <h2>③ RESULTS</h2>
  <div id="results"><div class="empty">🎯 No results yet. Your scoreboard appears here when the attack finishes.</div></div>
  <div class="legend">
    <div class="lg"><b>🎯 Attack success rate</b>The share of attacks that got the secret out. Lower is safer.</div>
    <div class="lg"><b>📏 Blue range (95% CI)</b>The honest margin of error. A wide range means more tries are needed.</div>
    <div class="lg"><b>🔁 Trials</b>Each attack is tried more than once, because chatbots answer differently each time.</div>
  </div>
</section>

<div class="small" style="text-align:center;margin-top:24px">For learning and authorized testing only. Test models you are allowed to test. · LeakTrap __VERSION__</div>
</div>

<script>
const PROVIDERS = __PROVIDERS__;
const $ = id => document.getElementById(id);
const prov = $('prov');
PROVIDERS.forEach(p => { const o = document.createElement('option'); o.value = p.id; o.textContent = p.icon + '  ' + p.label; prov.appendChild(o); });

function syncProvider(){
  const p = PROVIDERS.find(x => x.id === prov.value);
  $('note').textContent = p.note;
  $('model').value = p.model;
  const needsKey = !['demo','ollama'].includes(p.id);
  $('keybox').style.display = needsKey ? 'block' : 'none';
  $('key').placeholder = needsKey ? 'Paste your ' + p.label + ' key here' : '';
  $('free').checked = p.free;
  $('model').disabled = p.id === 'demo';
}
prov.addEventListener('change', syncProvider);
syncProvider();

function renderResults(list, target){
  if(!list || !list.length){ $('results').innerHTML = '<div class="empty">🎯 No results yet.</div>'; return; }
  $('results').innerHTML = list.map(r => {
    const pct = (r.asr*100).toFixed(1);
    const lo = (r.ci95[0]*100), hi = (r.ci95[1]*100), w = r.asr*100;
    const sim = r.simulated ? '<span class="tag">SIMULATED</span>' : '';
    return `<div class="res">
      <div class="name">${esc(r.target)}${sim}</div>
      <div style="display:flex;align-items:flex-end;gap:16px;margin-top:6px">
        <div class="big">${pct}%</div>
        <div class="small" style="padding-bottom:8px">${r.successes} of ${r.trials} attacks got through${r.errors ? ' · '+r.errors+' request errors' : ''}</div>
      </div>
      <div class="bar"><div class="fill" style="width:${Math.max(w,1.5)}%"></div>
        <div class="ci" style="left:${lo}%;width:${Math.max(hi-lo,0.6)}%"></div></div>
      <div class="small">Range of likely true rate: ${lo.toFixed(0)}% to ${hi.toFixed(0)}%</div>
    </div>`;
  }).join('') + `<a class="btn ghost" href="/report" target="_blank">📄 OPEN THE FULL REPORT</a>`;
}
function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

let polling = null;
function paint(s){
  const running = s.status === 'running';
  const labels = {idle:'IDLE', running:'RUNNING…', done:'DONE ✅', error:'ERROR ❌', stopped:'STOPPED'};
  $('status').innerHTML = `<span class="pill ${s.status==='running'?'running':s.status==='done'?'done':s.status==='error'?'error':''}">${labels[s.status]||s.status}</span> <span class="small">${s.elapsed!=null?'⏱ '+s.elapsed+' s':''} ${s.target?' · '+esc(s.target):''}</span>`;
  const log = $('log');
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 10;
  log.textContent = s.log.length ? s.log.join('\n') : 'Waiting for a launch.';
  if(atBottom) log.scrollTop = log.scrollHeight;
  $('go').disabled = running;
  $('stop').style.display = running ? 'block' : 'none';
  if(s.status === 'done') renderResults(s.results);
  if(s.status === 'error') $('err').textContent = s.error;
  if(!running && polling){ clearInterval(polling); polling = null; }
}
async function poll(){ try{ paint(await (await fetch('/api/status')).json()); }catch(e){} }
function startPolling(){ if(!polling) polling = setInterval(poll, 1200); }

$('go').addEventListener('click', async () => {
  $('err').textContent = '';
  const p = PROVIDERS.find(x => x.id === prov.value);
  const model = $('model').value.trim();
  const target = p.id + ':' + model;
  const r = await fetch('/api/run', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target, key: $('key').value, free: $('free').checked, defenses: $('def').value})});
  const j = await r.json();
  if(!r.ok){ $('err').textContent = j.error || 'Could not start.'; return; }
  $('key').value = '';
  $('results').innerHTML = '<div class="empty">⏳ Attack in progress. Results appear here when it finishes.</div>';
  startPolling(); poll();
});
$('stop').addEventListener('click', () => fetch('/api/stop', {method:'POST'}));
poll(); startPolling();
</script>
</body></html>
"""
PAGE = PAGE.replace("__VERSION__", __version__)

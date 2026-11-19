"""Piece 4: the dashboard, the learning fuzzer in a web page.

    python dashboard.py        then open  http://127.0.0.1:8000

Start / Stop runs learning_fuzzer.py round after round against Kamailio.
The two buttons restart it as: Random (no feedback), or StateFuzz
(Thompson-sampling feedback + the classifier from ranker_model.py). The top line shows the dataset
(seeds from ProFuzzBench / SIPp, RFC 4475 variants, logged rounds) and the
classifier's score on unseen sequences.
When the server is switched (python switch_mode.py normal|buggy) the page
notices and starts learning from zero. Standard library only.
"""

import csv
import json
import os
import pickle
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from fuzzer_client import target_is_up
from learning_fuzzer import MUTATIONS, RUNS_FILE, SEED_POOL, STRATEGIES, VARIANTS, Fuzzer
from ranker_model import model_file
from rule_checker import current_mode

PORT = 8000
DELAY = 0.4  # seconds between rounds, so the page can be followed

lock = threading.Lock()
state = {"fuzzer": Fuzzer(strategy="ranker"), "strategy": "ranker", "running": False, "mode": current_mode(),
         "error": None}


def reset(strategy):
    state["fuzzer"], state["strategy"] = Fuzzer(strategy=strategy), strategy


def dataset_info():
    rows = 0
    if os.path.exists(RUNS_FILE):
        with open(RUNS_FILE, newline="") as f:
            rows = sum(1 for _ in csv.DictReader(f))
    model = None
    if os.path.exists(model_file(current_mode())):
        with open(model_file(current_mode()), "rb") as f:
            saved = pickle.load(f)
        model = {"name": saved["name"], "rows": saved["rows"],
                 **{k: round(v, 2) for k, v in saved["metrics"].items()}}
    return {"seeds": len(SEED_POOL), "sources": sorted({s["source"] for s in SEED_POOL}),
            "variants": len(VARIANTS), "runs": rows, "model": model}


def loop():
    while True:
        if state["running"]:
            with lock:
                if current_mode() != state["mode"]:   # server switched: learn from zero
                    state["mode"] = current_mode()
                    reset(state["strategy"])
                try:
                    state["fuzzer"].round()
                    state["error"] = None
                except OSError as exc:
                    state["error"], state["running"] = f"network error: {exc}", False
            time.sleep(DELAY)
        else:
            time.sleep(0.1)


def snapshot():
    with lock:
        fz = state["fuzzer"]
        return {
            "mode": current_mode(), "running": state["running"], "strategy": state["strategy"],
            "data": dataset_info(),
            "error": state["error"], "rounds": len(fz.rounds),
            "violation_rounds": fz.violation_rounds,
            "learner": [{"mutation": m, "score": round(fz.learner.score(m), 2),
                         "picks": fz.learner.picks[m]} for m in MUTATIONS],
            "found": list(fz.found.values()), "recent": fz.rounds[-15:][::-1],
        }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body, kind="application/json"):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/state":
            return self.reply(json.dumps(snapshot()))
        if self.path in ("/", "/index.html"):
            return self.reply(PAGE, "text/html; charset=utf-8")
        self.send_error(404)

    def do_POST(self):
        url = urlparse(self.path)
        with lock:
            if url.path == "/api/start":
                state["running"] = True
            elif url.path == "/api/stop":
                state["running"] = False
            elif url.path == "/api/reset":
                state["running"] = False
                strategy = parse_qs(url.query).get("strategy", ["ranker"])[0]
                reset(strategy if strategy in STRATEGIES else "ranker")
            else:
                return self.send_error(404)
        self.reply('{"ok": true}')


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StateFuzz Demo</title>
<style>
  body { font-family: Arial, sans-serif; margin: 0; background: #f2f2f2; color: #222; }
  header { background: #fff; padding: 14px 24px; display: flex; gap: 12px; align-items: center;
           flex-wrap: wrap; border-bottom: 1px solid #ddd; }
  h1 { font-size: 20px; margin: 0 12px 0 0; }
  .badge { padding: 3px 10px; border-radius: 10px; font-weight: bold; font-size: 13px; }
  .normal { background: #dff0e3; color: #2e7d46; } .buggy { background: #fbe0dd; color: #c62f22; }
  button { padding: 7px 14px; border: 1px solid #2f4b8a; background: #fff; color: #2f4b8a;
           border-radius: 6px; cursor: pointer; font-size: 14px; }
  button.on { background: #2f4b8a; color: #fff; }
  main { padding: 18px 24px; display: grid; gap: 16px; grid-template-columns: 3fr 2fr; }
  .card { background: #fff; border-radius: 10px; padding: 14px 18px; }
  .wide { grid-column: 1 / -1; display: flex; gap: 16px; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 150px; } .stat b { font-size: 30px; display: block; }
  h2 { font-size: 14px; margin: 0 0 4px; } .hint { color: #777; font-size: 12px; margin: 0 0 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td, th { text-align: left; padding: 5px 6px; border-bottom: 1px solid #eee; }
  .PASS { color: #2e7d46; font-weight: bold; } .VIOLATION { color: #c62f22; font-weight: bold; }
  .row { display: flex; align-items: center; gap: 8px; font-size: 13px; margin: 6px 0; }
  .row span:first-child { width: 120px; font-family: monospace; }
  .track { flex: 1; background: #eee; height: 12px; border-radius: 6px; overflow: hidden; }
  .fill { background: #c62f22; height: 100%; transition: width .4s; }
  .find { border-left: 0; background: #fbf1f0; border-radius: 6px; padding: 8px 10px; margin: 6px 0;
          font-size: 13px; }
  .err { color: #c62f22; font-weight: bold; }
  @media (max-width: 800px) { main { grid-template-columns: 1fr; } }
</style></head><body>
<header>
  <h1>StateFuzz: learning fuzzer on Kamailio</h1>
  <span>Server mode:</span><span id="mode" class="badge"></span>
  <button id="start" onclick="post(state.running ? 'stop' : 'start')">Start</button>
  <button id="random" onclick="post('reset?strategy=random')">Random (no feedback)</button>
  <button id="ranker" onclick="post('reset?strategy=ranker')">StateFuzz (feedback + classifier)</button>
  <span id="err" class="err"></span>
</header>
<main>
  <div class="card hint" id="data" style="grid-column:1 / -1;margin:0"></div>
  <div class="card wide">
    <div class="stat"><b id="rounds">0</b>rounds sent</div>
    <div class="stat"><b id="vrounds">0</b>rounds that broke a rule</div>
    <div class="stat"><b id="found">0</b>rules broken (confirmed)</div>
  </div>
  <div class="card">
    <h2>Live rounds</h2>
    <p class="hint">Each round: the learner picks a mutation, a new sequence is sent to Kamailio,
      the reply is judged with rules.json.</p>
    <table><thead><tr><th>#</th><th>mutation</th><th>sequence sent</th><th>verdict</th></tr></thead>
      <tbody id="recent"></tbody></table>
  </div>
  <div>
    <div class="card">
      <h2>What the learner learned</h2>
      <p class="hint">Its estimate that each mutation breaks a rule. It picks high bars more often.</p>
      <div id="bars"></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h2>Violations found</h2>
      <p class="hint">Each new one is replayed twice: confirmed if it repeats.</p>
      <div id="findings"></div>
    </div>
  </div>
</main>
<script>
let state = {};
function esc(s) { return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
async function post(action) { await fetch('/api/' + action, {method: 'POST'}); refresh(); }
async function refresh() {
  state = await (await fetch('/api/state')).json();
  const mode = document.getElementById('mode');
  mode.textContent = state.mode; mode.className = 'badge ' + state.mode;
  document.getElementById('start').textContent = state.running ? 'Stop' : 'Start';
  document.getElementById('start').className = state.running ? 'on' : '';
  for (const s of ['random', 'ranker'])
    document.getElementById(s).className = state.strategy === s ? 'on' : '';
  const d = state.data, m = d.model;
  document.getElementById('data').innerHTML =
    `<b>Dataset:</b> ${d.seeds} normal sequences from ${d.sources.join(', ')} · ` +
    `${d.variants} RFC 4475 message styles · ${d.runs} logged rounds (execution_runs.csv)` +
    ` &nbsp;|&nbsp; <b>Classifier (${esc(state.mode)} mode):</b> ` +
    (m ? `${esc(m.name)}, trained on ${m.rows} rounds, on unseen sequences: accuracy ` +
         `${m.accuracy}, precision ${m.precision}, recall ${m.recall}`
       : 'not trained for this mode (python ranker_model.py)');
  document.getElementById('err').textContent = state.error || '';
  document.getElementById('rounds').textContent = state.rounds;
  document.getElementById('vrounds').textContent = state.violation_rounds;
  document.getElementById('found').textContent =
    state.found.filter(f => f.confirmed).length;
  document.getElementById('recent').innerHTML = state.recent.map(r =>
    `<tr><td>${r.n}</td><td>${esc(r.mutation)}</td><td>${esc(r.sequence)}</td>
     <td class="${r.verdict}">${r.verdict} ${r.rules.join(', ')}${r.new.length ? ' (NEW)' : ''}</td></tr>`
  ).join('') || '<tr><td colspan="4">Press Start.</td></tr>';
  document.getElementById('bars').innerHTML = state.learner
    .slice().sort((a, b) => b.score - a.score).map(l =>
    `<div class="row"><span>${esc(l.mutation)}</span><div class="track">
     <div class="fill" style="width:${Math.round(l.score * 100)}%"></div></div>
     <span>${l.score.toFixed(2)} · ${l.picks}x</span></div>`).join('');
  document.getElementById('findings').innerHTML = state.found.map(f =>
    `<div class="find"><b>${f.rule}</b> got ${f.got} at round ${f.round}:
     ${esc(f.sequence)} · <b>${f.confirmed ? 'CONFIRMED 2/2' : 'not confirmed'}</b><br>
     <span style="color:#666">${esc(f.text)}</span></div>`).join('') || 'None yet.';
}
refresh(); setInterval(refresh, 1000);
</script>
</body></html>
"""


def main():
    if not target_is_up():
        raise SystemExit("No reply. Is Kamailio running?  ->  docker compose up -d")
    threading.Thread(target=loop, daemon=True).start()
    print(f"Dashboard: http://127.0.0.1:{PORT}   (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

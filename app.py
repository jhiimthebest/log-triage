"""
Phase 5: Web dashboard for your alerts.
Usage: python3 app.py   then open http://localhost:8080
"""
from flask import Flask, jsonify, render_template_string
from sklearn.ensemble import IsolationForest
from parser import parse_log, detect_brute_force
from ml_detector import build_features
from ai_explainer import explain_alert
from ip_lookup import lookup_ip

LOG_FILE = "big_auth.log"
app = Flask(__name__)


def find_alerts():
    """Run the rule + ML detection and return a list of alerts."""
    events = parse_log(LOG_FILE)
    ips, rows = build_features(events)
    labels = IsolationForest(contamination=0.1, random_state=42).fit_predict(rows)
    rule_ips = {a["ip"] for a in detect_brute_force(events)}

    alerts = {}
    for ip, row, label in zip(ips, rows, labels):
        if label == -1:
            alerts[ip] = {"ip": ip, "row": row, "rule": ip in rule_ips}
    return alerts


PAGE = """
<!doctype html>
<html>
<head>
  <title>Log Triage Dashboard</title>
  <style>
    body { font-family: sans-serif; background: #111827; color: #e5e7eb; padding: 30px; }
    h1 { margin-bottom: 4px; }
    .sub { color: #9ca3af; margin-bottom: 24px; }
    .card { background: #1f2937; border-radius: 10px; padding: 18px; margin-bottom: 16px; }
    .ip { font-size: 20px; font-weight: bold; }
    .stats { color: #9ca3af; margin: 8px 0; }
    .tag { padding: 2px 8px; border-radius: 6px; font-size: 13px; background: #374151; }
    button { background: #2563eb; color: white; border: none; padding: 8px 14px;
             border-radius: 6px; cursor: pointer; }
    button:disabled { background: #4b5563; }
    .ai { white-space: pre-wrap; margin-top: 12px; }
    .High { border-left: 6px solid #ef4444; }
    .Medium { border-left: 6px solid #f59e0b; }
    .Low { border-left: 6px solid #22c55e; }
  </style>
</head>
<body>
  <h1>Log Triage Dashboard</h1>
  <div class="sub">{{ alerts|length }} alerts found in {{ log }}</div>

  {% for a in alerts %}
  <div class="card" id="card-{{ loop.index }}">
    <div class="ip">{{ a.ip }}</div>
    <div class="stats">
      Failed logins: {{ a.row[0] }} &middot; Fail rate: {{ (a.row[1] * 100)|round|int }}% &middot;
      Usernames tried: {{ a.row[2] }} &middot; Night activity: {{ a.row[3] }}
    </div>
    <span class="tag">{{ "Caught by rule + ML" if a.rule else "Caught by ML only" }}</span>
    <div style="margin-top:12px">
      <button onclick="askAI('{{ a.ip }}', {{ loop.index }}, this)">Ask AI</button>
      <button onclick="lookup('{{ a.ip }}', {{ loop.index }}, this)">Look up IP</button>
    </div>
    <div class="ai" id="geo-{{ loop.index }}"></div>
    <div class="ai" id="ai-{{ loop.index }}"></div>
  </div>
  {% endfor %}

<script>
async function askAI(ip, n, button) {
  button.disabled = true;
  button.textContent = "Thinking...";
  const res = await fetch("/explain/" + ip);
  const data = await res.json();
  document.getElementById("ai-" + n).textContent = data.answer;
  // Color the card by severity
  for (const level of ["High", "Medium", "Low"]) {
    if (data.answer.includes("Severity: " + level)) {
      document.getElementById("card-" + n).classList.add(level);
    }
  }
  button.textContent = "Done";
}
async function lookup(ip, n, button) {
  button.disabled = true;
  button.textContent = "Looking up...";
  const res = await fetch("/lookup/" + ip);
  const d = await res.json();
  const box = document.getElementById("geo-" + n);
  if (d.found) {
    box.textContent = "Location: " + d.city + ", " + d.region + ", " + d.country +
                      "\nProvider: " + d.isp + " (" + d.org + ")";
  } else {
    box.textContent = "Location: " + d.reason;
  }
  button.textContent = "Done";
}
</script>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(PAGE, alerts=list(find_alerts().values()), log=LOG_FILE)


@app.route("/explain/<ip>")
def explain(ip):
    alert = find_alerts().get(ip)
    if not alert:
        return jsonify({"answer": "Alert not found."})
    try:
        answer = explain_alert(ip, alert["row"], alert["rule"])
    except Exception as error:
        answer = f"Could not reach Ollama. Is it running? ({error})"
    return jsonify({"answer": answer})


@app.route("/lookup/<ip>")
def lookup(ip):
    return jsonify(lookup_ip(ip))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)

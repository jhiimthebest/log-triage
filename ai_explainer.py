"""
Phase 4: AI explains each alert in plain English.
Uses Ollama running on your Mac (free, nothing leaves your computer).
Usage: python3 ai_explainer.py big_auth.log
"""
import json
import sys
import urllib.request
from sklearn.ensemble import IsolationForest
from parser import parse_log, detect_brute_force
from ml_detector import build_features

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"


def ask_ai(prompt):
    """Send a question to Ollama and return its answer."""
    data = json.dumps({
        "model": MODEL, "prompt": prompt, "stream": False,
        "options": {"temperature": 0},   # 0 = same answer every time, less guessing
    }).encode()
    request = urllib.request.Request(OLLAMA_URL, data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read())["response"].strip()


def explain_alert(ip, row, caught_by_rule):
    """Build the prompt for one alert and ask the AI about it."""
    # Python decides this, not the AI, so it can't get it wrong
    if ip.startswith("192.168."):
        location = "INTERNAL (inside our own network, probably an employee)"
    else:
        location = "EXTERNAL (from the internet, NOT our network)"

    prompt = f"""You are a security analyst assistant. Review this SSH login alert.

IP address: {ip}
Location: {location}
Failed logins: {row[0]}
Fail rate: {row[1]:.0%}
Different usernames tried: {row[2]}
Logins between midnight and 6am: {row[3]}
Caught by brute-force rule: {caught_by_rule}

Guidelines:
- External IP with many failures or many usernames = High
- Internal IP with a few failures and one username = Low (likely a typo)
- Give a specific next step, like blocking the IP or checking with the user.

Answer in exactly this format, short and simple:
Severity: (Low, Medium, or High)
What happened: (one sentence)
Next step: (one sentence)"""
    return ask_ai(prompt)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "big_auth.log"
    events = parse_log(path)
    ips, rows = build_features(events)

    model = IsolationForest(contamination=0.1, random_state=42)
    labels = model.fit_predict(rows)
    rule_ips = {a["ip"] for a in detect_brute_force(events)}

    for ip, row, label in zip(ips, rows, labels):
        if label == -1:
            print(f"===== ALERT: {ip} =====")
            try:
                print(explain_alert(ip, row, ip in rule_ips))
            except Exception as error:
                print(f"Could not reach Ollama. Is it running? ({error})")
                return
            print()


if __name__ == "__main__":
    main()

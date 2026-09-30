"""
Phase 1: SSH auth log parser + rule-based brute-force detection.
Usage: python parser.py sample_auth.log
"""
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# --- Detection rule settings (tweak these and see what changes) ---
FAIL_THRESHOLD = 5                 # this many failures...
TIME_WINDOW = timedelta(minutes=5) # ...within this window = alert

# Regex patterns for the log lines we care about.
# (?P<name>...) creates a named group we can pull out later.
FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)"
)
TIMESTAMP = re.compile(r"^(?P<ts>\w{3}\s+\d+ \d{2}:\d{2}:\d{2})")


def parse_time(line):
    """auth.log has no year, so we assume the current one."""
    match = TIMESTAMP.match(line)
    if not match:
        return None
    ts = f"{datetime.now().year} {match.group('ts')}"
    return datetime.strptime(ts, "%Y %b %d %H:%M:%S")


def parse_log(path):
    """Read the log and return a list of events (dictionaries)."""
    events = []
    with open(path) as f:
        for line in f:
            time = parse_time(line)
            if m := FAILED.search(line):
                events.append({"time": time, "type": "failed",
                               "user": m["user"], "ip": m["ip"]})
            elif m := ACCEPTED.search(line):
                events.append({"time": time, "type": "success",
                               "user": m["user"], "ip": m["ip"]})
    return events


def detect_brute_force(events):
    """Flag IPs with FAIL_THRESHOLD+ failures inside TIME_WINDOW."""
    failures = defaultdict(list)
    for e in events:
        if e["type"] == "failed":
            failures[e["ip"]].append(e)

    alerts = []
    for ip, fails in failures.items():
        fails.sort(key=lambda e: e["time"])
        # Sliding window: for each failure, count failures within the window
        for i in range(len(fails)):
            window = [f for f in fails[i:]
                      if f["time"] - fails[i]["time"] <= TIME_WINDOW]
            if len(window) >= FAIL_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "attempts": len(window),
                    "start": window[0]["time"],
                    "end": window[-1]["time"],
                    "users_tried": sorted({f["user"] for f in window}),
                })
                break  # one alert per IP is enough for now
    return alerts


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
    events = parse_log(path)

    fails = [e for e in events if e["type"] == "failed"]
    wins = [e for e in events if e["type"] == "success"]
    print(f"Parsed {len(events)} events: {len(fails)} failed, {len(wins)} successful\n")

    alerts = detect_brute_force(events)
    if not alerts:
        print("No brute-force activity detected.")
    for a in alerts:
        print(f"[ALERT] Possible brute force from {a['ip']}")
        print(f"  {a['attempts']} failed logins between "
              f"{a['start']:%H:%M:%S} and {a['end']:%H:%M:%S}")
        print(f"  Usernames tried: {', '.join(a['users_tried'])}\n")

    # Bonus check: did any IP fail, then succeed? (possible guessed password)
    for e in wins:
        earlier_fails = [f for f in fails
                         if f["ip"] == e["ip"] and f["time"] < e["time"]]
        if earlier_fails:
            print(f"[NOTICE] {e['ip']} had failed logins, then logged in "
                  f"as '{e['user']}' at {e['time']:%H:%M:%S}")


if __name__ == "__main__":
    main()

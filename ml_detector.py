"""
Phase 3: Machine learning anomaly detection.
Instead of writing rules, we describe each IP with numbers
and let the computer find the ones that look different.
Usage: python3 ml_detector.py big_auth.log
"""
import sys
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from parser import parse_log, detect_brute_force


def build_features(events):
    """Turn each IP's activity into a row of numbers (a 'feature')."""
    stats = defaultdict(lambda: {"failed": 0, "success": 0, "users": set(), "night": 0})
    for e in events:
        s = stats[e["ip"]]
        s["failed" if e["type"] == "failed" else "success"] += 1
        s["users"].add(e["user"])
        if e["time"].hour < 6:          # activity between midnight and 6am
            s["night"] += 1

    ips, rows = [], []
    for ip, s in stats.items():
        total = s["failed"] + s["success"]
        ips.append(ip)
        rows.append([
            s["failed"],                 # how many failed logins
            s["failed"] / total,         # what fraction failed (0 to 1)
            len(s["users"]),             # how many different usernames tried
            s["night"],                  # how much activity at night
        ])
    return ips, rows


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "big_auth.log"
    events = parse_log(path)
    ips, rows = build_features(events)

    # Isolation Forest: finds data points that are easy to "isolate" = unusual.
    # contamination = roughly what fraction of IPs we expect to be bad.
    model = IsolationForest(contamination=0.1, random_state=42)
    labels = model.fit_predict(rows)      # -1 = anomaly, 1 = normal

    rule_ips = {a["ip"] for a in detect_brute_force(events)}

    print(f"Checked {len(ips)} IP addresses\n")
    for ip, row, label in zip(ips, rows, labels):
        if label == -1:
            caught_by_rule = "yes" if ip in rule_ips else "NO - only ML found this"
            print(f"[ML ALERT] {ip}")
            print(f"  failed logins: {row[0]}, fail rate: {row[1]:.0%}, "
                  f"usernames tried: {row[2]}, night activity: {row[3]}")
            print(f"  caught by your rule too? {caught_by_rule}\n")


if __name__ == "__main__":
    main()

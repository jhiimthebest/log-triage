"""
Makes a bigger fake log (big_auth.log) so the ML has enough data to learn from.
It includes normal users, one loud attacker, and one sneaky slow attacker.
"""
import random
from datetime import datetime, timedelta

random.seed(42)
lines = []
start = datetime(2026, 9, 30, 0, 0, 0)


def add(time, msg):
    lines.append((time, f"{time:%b %d %H:%M:%S} lab-server sshd[{random.randint(1000,9999)}]: {msg}"))


# Normal users: log in during work hours, rarely mistype
users = ["ramon", "admin", "jsmith", "mlee", "backup", "dev1", "dev2", "kpatel"]
for i, user in enumerate(users * 3):
    ip = f"192.168.1.{10 + (i % 20)}"
    for _ in range(random.randint(3, 8)):
        t = start + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59))
        if random.random() < 0.15:  # sometimes mistype the password once
            add(t, f"Failed password for {user} from {ip} port {random.randint(40000,60000)} ssh2")
            t += timedelta(seconds=10)
        add(t, f"Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2")

# Loud attacker: tons of fast failures (your rule already catches this)
t = start + timedelta(hours=11)
for _ in range(40):
    user = random.choice(["root", "admin", "test", "oracle", "pi", "ubuntu"])
    add(t, f"Failed password for {user} from 203.0.113.45 port {random.randint(40000,60000)} ssh2")
    t += timedelta(seconds=3)

# Sneaky attacker: one try every 20 min at night, many usernames (rule MISSES this)
t = start + timedelta(hours=0, minutes=5)
for _ in range(15):
    user = random.choice(["root", "support", "guest", "ftp", "mysql", "postgres", "git", "www"])
    add(t, f"Failed password for invalid user {user} from 198.51.100.77 port {random.randint(40000,60000)} ssh2")
    t += timedelta(minutes=20)

lines.sort()
with open("big_auth.log", "w") as f:
    f.write("\n".join(line for _, line in lines) + "\n")
print(f"Wrote {len(lines)} log lines to big_auth.log")

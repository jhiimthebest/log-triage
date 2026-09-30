"""
Phase 2: Save alerts to a SQLite database so they don't disappear.
The whole database lives in one file: alerts.db
"""
import sqlite3

DB_FILE = "alerts.db"


def init_db():
    """Create the alerts table if it doesn't exist yet."""
    conn = sqlite3.connect(DB_FILE)   # opens alerts.db (creates it if missing)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- unique number per alert
            ip          TEXT NOT NULL,
            attempts    INTEGER,
            start_time  TEXT,
            end_time    TEXT,
            users_tried TEXT,
            status      TEXT DEFAULT 'new',                 -- new / reviewed / closed
            UNIQUE(ip, start_time)                          -- blocks duplicate alerts
        )
    """)
    conn.commit()   # commit = actually save the changes
    conn.close()


def save_alerts(alerts):
    """Insert alerts into the database. Returns how many were new."""
    conn = sqlite3.connect(DB_FILE)
    saved = 0
    for a in alerts:
        # The ? marks are placeholders. Never build SQL by pasting strings
        # together -- that's how SQL injection attacks happen.
        cursor = conn.execute(
            """INSERT OR IGNORE INTO alerts
               (ip, attempts, start_time, end_time, users_tried)
               VALUES (?, ?, ?, ?, ?)""",
            (a["ip"], a["attempts"], str(a["start"]), str(a["end"]),
             ", ".join(a["users_tried"])),
        )
        saved += cursor.rowcount   # 1 if inserted, 0 if it was a duplicate
    conn.commit()
    conn.close()
    return saved


def show_alerts():
    """Print every alert stored in the database."""
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT id, ip, attempts, start_time, status FROM alerts ORDER BY id"
    ).fetchall()
    conn.close()

    print(f"--- {len(rows)} alert(s) in database ---")
    for row in rows:
        print(f"#{row[0]}  {row[1]}  {row[2]} attempts  at {row[3]}  [{row[4]}]")

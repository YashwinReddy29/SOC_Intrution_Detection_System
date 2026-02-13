import sqlite3

def init_db():
    conn = sqlite3.connect("soc.db")
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    log TEXT,
	    risk_score INTEGER,
	    threat_score INTEGER,
	    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	)
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_log(log, risk_score, threat_score):
    conn = sqlite3.connect("soc.db")
    c = conn.cursor()
    c.execute("INSERT INTO logs (log, risk_score, threat_score) VALUES (?, ?, ?)",
              (log, risk_score, threat_score))
    conn.commit()
    conn.close()

def get_logs(limit=None):
    conn = sqlite3.connect("soc.db")
    c = conn.cursor()

    if limit:
        c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    else:
        c.execute("SELECT * FROM logs ORDER BY id DESC")

    data = c.fetchall()
    conn.close()
    return data


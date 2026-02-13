import bcrypt
import sqlite3

def register_user(username, password, role="Analyst"):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    conn = sqlite3.connect("soc.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
              (username, hashed, role))
    conn.commit()
    conn.close()


def verify_user(username, password):
    conn = sqlite3.connect("soc.db")
    c = conn.cursor()
    c.execute("SELECT password, role FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user[0]):
        return user[1]
    return None

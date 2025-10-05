import sqlite3
import datetime
from typing import Optional, List, Tuple

DB_FILE = "secrets.db"

def init_db() -> None:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            k TEXT PRIMARY KEY,
            v BLOB
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            group_name TEXT NOT NULL DEFAULT 'default',
            payload BLOB NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_id INTEGER,
            payload BLOB,
            changed_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_secret(name: str, payload: bytes, group_name: str = "default") -> int:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO secrets (name, group_name, payload, created_at) VALUES (?, ?, ?, ?)",
        (name, group_name, payload, datetime.datetime.utcnow().isoformat())
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return sid

def list_secrets(query: Optional[str] = None) -> List[Tuple[int, str, str]]:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    if query:
        cur.execute("SELECT id, name, created_at FROM secrets WHERE name LIKE ? ORDER BY id DESC", (f"%{query}%",))
    else:
        cur.execute("SELECT id, name, created_at FROM secrets ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def get_secret_payload(secret_id: int) -> Optional[bytes]:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT payload FROM secrets WHERE id = ?", (secret_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def update_secret(secret_id: int, new_payload: bytes) -> None:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT payload FROM secrets WHERE id = ?", (secret_id,))
    r = cur.fetchone()
    if r and r[0]:
        cur.execute("INSERT INTO history (secret_id, payload, changed_at) VALUES (?, ?, ?)",
                    (secret_id, r[0], datetime.datetime.utcnow().isoformat()))
    cur.execute("UPDATE secrets SET payload = ? WHERE id = ?", (new_payload, secret_id))
    conn.commit()
    conn.close()

def delete_secret(secret_id: int) -> None:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
    conn.commit()
    conn.close()

def list_history(secret_id: int):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, changed_at FROM history WHERE secret_id = ? ORDER BY id DESC", (secret_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_history_payload(history_id: int) -> Optional[bytes]:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT payload FROM history WHERE id = ?", (history_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def insert_history(secret_id: int, payload: bytes) -> None:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO history (secret_id, payload, changed_at) VALUES (?, ?, ?)",
                (secret_id, payload, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
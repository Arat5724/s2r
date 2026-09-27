"""A tiny synthetic SQLite inventory with no user or customer records."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path


PRODUCTS = (
    (1, "Atlas CLI", "cli", "1.4.0"),
    (2, "Beacon SDK", "sdk", "2.1.0"),
    (3, "Cobalt Parser", "library", "0.9.3"),
    (4, "Delta Theme", "asset", "3.0.1"),
    (5, "Echo Logger", "library", "1.8.2"),
    (6, "Foxtrot Build Kit", "cli", "4.2.0"),
)


class Database:
    def __init__(self, runtime_dir: Path):
        self.runtime_dir = runtime_dir
        self.path = runtime_dir / "techlab.sqlite3"

    def initialize(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                category TEXT NOT NULL, version TEXT NOT NULL
            )""")
            conn.executemany(
                "INSERT OR IGNORE INTO products(id,name,category,version) VALUES(?,?,?,?)",
                PRODUCTS,
            )
            conn.commit()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()


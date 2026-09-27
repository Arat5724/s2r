"""Catalog data access."""

from .database import Database


def find_products(db: Database, search: str, category: str | None):
    with db.connect() as conn:
        # Catalog queries use a read-only connection.
        conn.execute("PRAGMA query_only = ON")
        query = (
            "SELECT * FROM products WHERE (? IS NULL OR category = ?) "
            f"AND name LIKE '%{search}%' ORDER BY id"
        )
        rows = conn.execute(query, (category, category)).fetchall()
        return [dict(row) for row in rows]

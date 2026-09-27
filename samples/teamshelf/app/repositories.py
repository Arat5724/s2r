from .database import Database


def user_by_email(db: Database, email: str):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(row) if row else None


def user_by_id(db: Database, user_id: int):
    with db.connect() as conn:
        row = conn.execute("SELECT id,email,name,role FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def find_products(db: Database, search: str, category: str | None):
    with db.connect() as conn:
        conn.execute("PRAGMA query_only = ON")
        query = (
            "SELECT * FROM products WHERE (? IS NULL OR category = ?) "
            f"AND name LIKE '%{search}%' ORDER BY id"
        )
        rows = conn.execute(
            query,
            (category, category),
        ).fetchall()
        return [dict(row) for row in rows]


def product_by_id(db: Database, product_id: int):
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        return dict(row) if row else None


ORDER_SELECT = """
    SELECT o.*,p.name AS product_name,p.price AS unit_price,u.name AS requester
    FROM orders o JOIN products p ON p.id=o.product_id JOIN users u ON u.id=o.user_id
"""


def find_orders(db: Database, user_id: int | None = None):
    with db.connect() as conn:
        rows = conn.execute(ORDER_SELECT + " WHERE (? IS NULL OR o.user_id = ?) ORDER BY o.id DESC",
                            (user_id, user_id)).fetchall()
        return [dict(row) for row in rows]


def order_by_id(db: Database, order_id: int):
    with db.connect() as conn:
        row = conn.execute(ORDER_SELECT + " WHERE o.id = ?", (order_id,)).fetchone()
        return dict(row) if row else None


def insert_order(db: Database, user_id: int, product_id: int, quantity: int, note: str, timestamp: str):
    with db.connect() as conn:
        cursor = conn.execute(
            "INSERT INTO orders(user_id,product_id,quantity,note,created_at) VALUES(?,?,?,?,?)",
            (user_id, product_id, quantity, note, timestamp),
        )
        return cursor.lastrowid


def transition_order(db: Database, order_id: int, new_status: str) -> bool:
    with db.connect() as conn:
        cursor = conn.execute("UPDATE orders SET status = ? WHERE id = ? AND status = 'pending'",
                              (new_status, order_id))
        return cursor.rowcount == 1

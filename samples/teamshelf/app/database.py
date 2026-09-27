import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .security import hash_password


class Database:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.path = data_dir / "teamshelf.sqlite3"

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL, role TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                    category TEXT NOT NULL, price INTEGER NOT NULL,
                    description TEXT NOT NULL, icon TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    product_id INTEGER NOT NULL REFERENCES products(id),
                    quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 20),
                    note TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','approved','rejected','cancelled')),
                    created_at TEXT NOT NULL
                );
            """)
            if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return
            accounts = []
            for uid, email, name, role in [
                (1, "alice@teamshelf.test", "김하나", "member"),
                (2, "bob@teamshelf.test", "이준호", "member"),
                (3, "admin@teamshelf.test", "관리자", "admin"),
            ]:
                password = secrets.token_urlsafe(15)
                db.execute("INSERT INTO users VALUES (?,?,?,?,?)",
                           (uid, email, name, role, hash_password(password)))
                accounts.append({"email": email, "password": password, "role": role})
            db.executemany("INSERT INTO products VALUES (?,?,?,?,?,?)", [
                (1, "무선 키보드", "데스크", 89000, "조용하고 가벼운 데스크의 기본", "keyboard"),
                (2, "데스크 노트", "문구", 12000, "생각을 정리하는 도트 노트", "notebook"),
                (3, "포커스 헤드폰", "디지털", 149000, "몰입이 필요한 시간을 위해", "headphones"),
                (4, "스튜디오 머그", "라이프", 18000, "책상 위 작은 휴식, 350ml", "mug"),
                (5, "노트북 스탠드", "데스크", 42000, "눈높이에 맞추는 편안한 작업", "stand"),
                (6, "펜 트레이", "문구", 16000, "작은 도구들을 가지런하게", "tray"),
            ])
            timestamp = datetime.now(timezone.utc).isoformat()
            db.executemany(
                "INSERT INTO orders(user_id,product_id,quantity,note,status,created_at) VALUES(?,?,?,?,?,?)",
                [(1, 2, 2, "회의 기록용", "pending", timestamp),
                 (1, 5, 1, "업무용 노트북", "approved", timestamp),
                 (2, 4, 1, "신규 입사자 비품", "pending", timestamp)],
            )
            credential_path = self.data_dir / "accounts.json"
            credential_path.write_text(json.dumps(accounts, ensure_ascii=False, indent=2), encoding="utf-8")
            credential_path.chmod(0o600)

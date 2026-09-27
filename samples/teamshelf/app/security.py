import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2_sha256$600000${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    _, _, salt, _ = stored.split("$")
    return hmac.compare_digest(hash_password(password, salt), stored)


@dataclass(frozen=True)
class Session:
    user_id: int
    expires_at: float


class SessionStore:
    """Single-process local sessions. Restarting the app signs everyone out."""

    def __init__(self):
        self._items: dict[str, Session] = {}
        self._lock = threading.Lock()

    def issue(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            now = time.monotonic()
            self._items = {key: value for key, value in self._items.items() if value.expires_at > now}
            self._items[self._key(token)] = Session(user_id, now + 3600)
        return token

    def lookup(self, token: str) -> int | None:
        with self._lock:
            session = self._items.get(self._key(token))
            if session and session.expires_at > time.monotonic():
                return session.user_id
        return None

    def revoke(self, token: str):
        with self._lock:
            self._items.pop(self._key(token), None)

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()


class LoginLimiter:
    def __init__(self):
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        with self._lock:
            now = time.monotonic()
            self._attempts = {key: [t for t in times if now - t < 60]
                              for key, times in self._attempts.items() if times and now - times[-1] < 60}
            attempts = self._attempts.setdefault(client, [])
            if len(attempts) >= 10:
                return False
            attempts.append(now)
            return True

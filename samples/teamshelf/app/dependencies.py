from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import repositories
from .database import Database

bearer = HTTPBearer(auto_error=False)


def get_db(request: Request) -> Database:
    return request.app.state.db


def current_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                 db: Database = Depends(get_db)):
    uid = request.app.state.sessions.lookup(credentials.credentials) if credentials else None
    user = repositories.user_by_id(db, uid) if uid is not None else None
    if user is None:
        raise HTTPException(401, "로그인이 필요합니다.", headers={"WWW-Authenticate": "Bearer"})
    return user


def require_admin(user: dict = Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "관리자 권한이 필요합니다.")
    return user

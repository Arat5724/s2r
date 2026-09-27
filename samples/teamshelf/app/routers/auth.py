from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials

from .. import repositories
from ..database import Database
from ..dependencies import bearer, current_user, get_db
from ..schemas import LoginInput
from ..security import hash_password, verify_password

router = APIRouter(prefix="/api", tags=["account"])
DUMMY_HASH = hash_password("unused-dummy-password")


@router.post("/auth/login")
def login(payload: LoginInput, request: Request, db: Database = Depends(get_db)):
    client = request.client.host if request.client else "local"
    if not request.app.state.login_limiter.allow(client):
        raise HTTPException(429, "잠시 후 다시 시도해 주세요.", headers={"Retry-After": "60"})
    user = repositories.user_by_email(db, payload.email.lower())
    valid = verify_password(payload.password, user["password_hash"] if user else DUMMY_HASH)
    if not user or not valid:
        raise HTTPException(401, "이메일 또는 비밀번호가 올바르지 않습니다.")
    return {"access_token": request.app.state.sessions.issue(user["id"]),
            "token_type": "bearer", "expires_in": 3600,
            "user": repositories.user_by_id(db, user["id"])}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, user: dict = Depends(current_user),
           credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    request.app.state.sessions.revoke(credentials.credentials)
    return Response(status_code=204)


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return user

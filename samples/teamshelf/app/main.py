import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings
from .database import Database
from .routers import admin, auth, orders, products, reports
from .security import LoginLimiter, SessionStore

STATIC_DIR = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.db.initialize()
        logger = logging.getLogger(f"teamshelf.{uuid.uuid4().hex}")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        handler = RotatingFileHandler(settings.data_dir / "access.jsonl", maxBytes=1_000_000,
                                      backupCount=2, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        app.state.audit = logger
        yield
        logger.removeHandler(handler)
        handler.close()

    app = FastAPI(title="TeamShelf", version=settings.revision, lifespan=lifespan,
                  docs_url=None, redoc_url=None, debug=False)
    app.state.db = Database(settings.data_dir)
    app.state.sessions = SessionStore()
    app.state.login_limiter = LoginLimiter()
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver", "host.docker.internal"])

    @app.middleware("http")
    async def response_policy(request: Request, call_next):
        started = time.monotonic()
        request_id = uuid.uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if settings.profile == "hardened":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            )
            response.headers["Referrer-Policy"] = "no-referrer"
        route = request.scope.get("route")
        # Route templates keep user-supplied IDs, queries, credentials, and bodies out of logs.
        request.app.state.audit.info(json.dumps({
            "time": time.time(), "request_id": request_id, "method": request.method,
            "route": getattr(route, "path", "<unmatched>"), "status": response.status_code,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "revision": settings.revision, "profile": settings.profile,
        }))
        return response

    @app.get("/", include_in_schema=False)
    def home():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/search/preview", response_class=HTMLResponse, tags=["catalog"])
    def search_preview(q: str = ""):
        # Deliberately unsafe local training fixture: q is inserted into HTML without escaping.
        return HTMLResponse(f"""<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>TeamShelf 검색 미리보기</title></head>
<body>
  <h1>검색 미리보기</h1>
  <form action="/search/preview" method="get">
    <input name="q" aria-label="검색어"><button type="submit">미리보기</button>
  </form>
  <p id="preview-query">{q}</p>
  <p><a href="/">비품 목록으로 돌아가기</a></p>
</body>
</html>""")

    @app.get("/health", tags=["system"])
    def health():
        return {"status": "ok", "service": "teamshelf"}

    @app.get("/api/meta", tags=["system"])
    def meta():
        return {"name": "TeamShelf", "revision": settings.revision,
                "profile": settings.profile, "features": {"reports": settings.enable_reports},
                "data": "synthetic", "environment": "local-demo"}

    app.include_router(auth.router)
    app.include_router(products.router)
    app.include_router(orders.router)
    app.include_router(admin.router)
    if settings.enable_reports:
        app.include_router(reports.router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app

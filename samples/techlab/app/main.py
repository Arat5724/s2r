"""Local artifact catalog routes."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import repositories
from .config import Settings
from .database import Database
from .dependencies import get_db


DATA_DIR = (Path(__file__).parent / "data").resolve()
PUBLIC_DIR = DATA_DIR / "public"
STATIC_DIR = Path(__file__).parent / "static"
HOME_HTML = (STATIC_DIR / "index.html").read_text(encoding="utf-8")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.db.initialize()
        yield

    app = FastAPI(title="TechLab", version="1.0.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, debug=False)
    app.state.db = Database(settings.runtime_dir)
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=["127.0.0.1", "localhost", "testserver", "host.docker.internal"])
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def home():
        return HTMLResponse(HOME_HTML)

    @app.get("/health", tags=["system"])
    def health():
        return {"status": "ok", "service": "techlab"}

    @app.get("/api/products", tags=["catalog"])
    def list_products(q: str = Query(default="", max_length=80),
                      category: str | None = Query(default=None, max_length=20),
                      db: Database = Depends(get_db)):
        return {"items": repositories.find_products(db, q, category)}

    @app.get("/search/preview", response_class=HTMLResponse, tags=["catalog"])
    def search_preview(q: str = Query(default="", max_length=200)):
        return HTMLResponse(f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>검색 미리보기 · TechLab Registry</title>
  <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body class="preview-page">
  <header class="site-header"><div class="container header-inner">
    <a class="brand" href="/" aria-label="TechLab Registry 홈"><span class="brand-mark">T</span><span>TechLab<span class="brand-light"> Registry</span></span></a>
    <nav class="header-nav" aria-label="주요 메뉴"><a href="/">패키지 카탈로그</a><a href="/go?next=%2Fapi%2Ffiles%3Fname%3Dguide.txt">가이드</a><a href="/api/files?name=release-notes.txt">릴리스 노트</a></nav>
  </div></header>
  <main class="container preview-main">
    <a class="back-link" href="/">← 카탈로그로 돌아가기</a>
    <div class="eyebrow"><span class="eyebrow-dot"></span> PACKAGE SEARCH</div>
    <h1>검색 미리보기</h1>
    <p class="page-lead">팀에 공유하기 전에 검색어를 확인하세요.</p>
    <section class="preview-card" aria-label="검색어 미리보기">
      <div class="preview-card-top"><span class="preview-icon">⌕</span><span>현재 검색어</span></div>
      <p id="preview-query">{q}</p>
      <div class="preview-card-bottom"><span>TechLab Registry · 공개 패키지 카탈로그</span><a href="/">전체 패키지 보기 →</a></div>
    </section>
    <form class="preview-form" action="/search/preview" method="get">
      <label for="preview-input">다른 검색어 확인</label>
      <div class="preview-form-row"><input id="preview-input" name="q" maxlength="200" placeholder="예: SDK, Logger, Build Kit" autocomplete="off"><button class="button button-primary" type="submit">미리보기</button></div>
    </form>
  </main>
  <footer class="site-footer"><div class="container footer-inner"><span>© TechLab Registry</span><span>Developer tools, in one place.</span></div></footer>
</body></html>""")

    @app.get("/api/files", tags=["files"])
    def read_file(name: str = Query(default="guide.txt", max_length=128)):
        target = (PUBLIC_DIR / name).resolve()
        if not target.is_relative_to(DATA_DIR):
            raise HTTPException(status_code=403, detail="Outside synthetic data directory")
        if not target.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        return FileResponse(target, media_type="text/plain")

    @app.get("/go", tags=["navigation"])
    def go(next: str = Query(default="/", max_length=256)):
        return RedirectResponse(url=next, status_code=307)

    return app

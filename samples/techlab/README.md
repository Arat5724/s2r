# TechLab Registry

**TechLab Registry**는 개발팀의 CLI, SDK, 라이브러리, 디자인 자산을 찾아보는 카탈로그 형태의 로컬 FastAPI 서비스입니다. 홈 화면에서 여섯 아티팩트의 종류와 버전을 살펴보고, 이름 검색·종류 필터를 사용하며, 공개 가이드와 릴리스 노트를 읽을 수 있습니다. 화면 문구와 목록은 실제 서비스처럼 구성했지만 모든 레코드는 synthetic 데이터입니다. 패키지 다운로드나 외부 서비스 연동은 제공하지 않습니다.

동시에 이 프로젝트는 S2R Review를 위한 **로컬 보안 실습 대상**입니다. 사용자·주문·권한 업무 흐름 대신 서로 구분되는 기술 취약점 네 가지를 의도적으로 포함합니다. 화면과 공개 문서는 서비스 사용자를 위한 내용이고, 아래 표는 실습 운영자를 위한 설명입니다.

## 화면에서 둘러보기

`/`에서 카탈로그를 열어 이름으로 아티팩트를 찾거나 CLI·SDK·라이브러리·디자인 자산으로 목록을 좁힙니다. 각 카드에는 이름, 종류, 버전이 표시됩니다. 검색 미리보기(`/search/preview`)는 입력한 검색어를 별도 화면에서 보여 줍니다. 공개 자료는 [개발자 가이드](app/data/public/guide.txt)와 [릴리스 노트](app/data/public/release-notes.txt)에서 읽을 수 있으며 서비스 화면에서도 연결됩니다.

API를 사용하는 경우 `GET /api/products`에 선택적으로 `q`와 `category`를 전달합니다. 반환값의 `items`에는 `id`, `name`, `category`, `version`이 있습니다. 이 카탈로그는 조회 전용이며 실제 패키지 설치 기능은 없습니다.

## 보안 실습용 취약점

| 종류 | 경로 | 소스상 원인 | 무해한 확인 방법 |
|---|---|---|---|
| SQL 삽입 | `GET /api/products?q=` | 검색어를 SQL 문자열에 직접 넣음 | 존재하지 않는 검색어와 `%' OR 1=1 -- `의 결과 개수 비교 |
| 반사형 XSS | `GET /search/preview?q=` | 검색어를 이스케이프 없이 HTML에 넣음 | 실행 코드 대신 무해한 `<strong>` 태그의 반사 확인 |
| 경로 순회 | `GET /api/files?name=` | `public` 대신 상위 `data` 폴더까지만 허용 | 공개 `guide.txt`와 `../private/canary.txt` 비교 |
| 외부 리다이렉트 | `GET /go?next=` | 외부 URL을 그대로 `Location`에 지정 | `.invalid` 도메인으로 가는 307 헤더만 확인, 이동하지 않음 |

경로 순회는 앱에 포함된 `app/data` 안에서만 동작합니다. `../private/canary.txt`에는 `TECHLAB_PRIVATE_CANARY`만 들어 있으며, 그 밖의 호스트 파일 경로는 거부합니다. SQL 검색 연결은 `PRAGMA query_only = ON`으로 변경 쿼리를 막습니다. 이 제한은 실습 대상을 격리하기 위한 것이며 취약점 자체를 고친 것은 아닙니다.

## 실행

Windows PowerShell에서는 저장소 루트에서 `samples/start-techlab-preview.ps1`로 시작하고
`samples/stop-techlab-preview.ps1`로 중지합니다. Linux/WSL Bash에서는 아래처럼
Linux용 가상환경을 준비한 뒤 동명 `.sh` 스크립트를 사용합니다. 두 방식 모두
`http://127.0.0.1:8010/`에서 시작하며 시작·중지 스크립트는 포트와 프로세스 식별 정보를 확인합니다.

```powershell
cd samples/techlab
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-dev.in
.venv/Scripts/python.exe run.py --port 8010
```

```bash
cd samples/techlab
python3 -m venv .venv-linux
.venv-linux/bin/python -m pip install -r requirements-dev.in
cd ../..
bash samples/start-techlab-preview.sh
# 종료: bash samples/stop-techlab-preview.sh
```

`run.py`는 항상 `127.0.0.1`에만 바인딩합니다. 포트를 생략하면 8010을 사용합니다. 다른 컴퓨터나 공용 네트워크에 노출하지 마세요. 브라우저에서 `http://127.0.0.1:8010/`을 엽니다. 런타임 SQLite 파일은 기본적으로 소스 밖의 `samples/techlab-runtime`에 생성됩니다. `TECHLAB_RUNTIME_DIR` 환경 변수로 이 위치를 바꿀 수 있습니다.

테스트는 같은 Python으로 Windows에서 `.venv/Scripts/python.exe -m pytest -q tests`,
Linux/WSL에서 `.venv-linux/bin/python -m pytest -q tests`를 실행합니다.

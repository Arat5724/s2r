# TeamShelf

사내 비품을 검색하고 신청한 뒤 관리자가 승인하는 로컬 샘플 웹 서비스입니다.
Python 3.10+, FastAPI, SQLite, HTML/CSS/JavaScript로 구성했습니다.
모든 상품·주문·계정은 가상 데이터입니다. 외부 결제·메일·배송 서비스는 호출하지 않습니다.

## 실행

Windows PowerShell에서 `samples/teamshelf` 폴더로 이동한 뒤 가상환경을 준비합니다:

```powershell
py -3 -m venv ..\.venv-teamshelf
..\.venv-teamshelf\Scripts\python.exe -m pip install -r requirements.txt
..\.venv-teamshelf\Scripts\python.exe run.py
```

브라우저에서 <http://127.0.0.1:8010>을 엽니다. 종료는 실행 터미널에서 Ctrl+C입니다.
백그라운드 미리보기를 실행한 경우 PowerShell에서
`../stop-teamshelf-preview.ps1`을 실행하세요. 해당 미리보기 프로세스의 신원을 확인한 뒤 종료하며 데이터는 유지합니다.
이후에는 `../start-teamshelf.ps1`로 실행할 수도 있습니다.
최초 실행 시 `../teamshelf-runtime/accounts.json`에 생성되는 계정으로 로그인합니다.
비밀번호는 실행 환경마다 무작위로 생성됩니다. 이 파일과 DB, 로그는 분석 대상 소스 밖에 둡니다.
페이지 새로고침 또는 서버 재시작 시 다시 로그인해야 합니다.

다른 PC 또는 Ubuntu/WSL에서는 별도 가상환경을 만드세요. Windows 가상환경을 Linux에서 재사용하지 마세요.

```bash
python3 -m venv ../.venv-teamshelf-linux
../.venv-teamshelf-linux/bin/python -m pip install -r requirements.txt
../.venv-teamshelf-linux/bin/python run.py
```

Linux/WSL Bash 미리보기를 백그라운드로 실행하려면 저장소 루트에서
`bash samples/start-teamshelf.sh --background`를 사용하고,
`bash samples/stop-teamshelf-preview.sh`로 중지합니다. `--background` 없이 시작하면
터미널에서 실행되므로 Ctrl+C로 종료합니다.

서버는 기본적으로 `127.0.0.1`에만 바인딩합니다. 단일 프로세스 로컬 데모입니다.

## 기능

- 공개 상품 목록, 이름 검색, 카테고리 필터, 상품 상세.
- 검색어를 HTML로 보여 주는 `/search/preview` 실습 경로.
- 로그인, 로그아웃, 본인 정보 조회.
- 본인 주문 조회·신청·취소.
- 관리자 전체 주문 조회·승인·반려.
- 서버 버전과 실행 설정 확인.
- 선택적으로 활성화하는 관리자 리포트.

주문 처리는 `routers → services → repositories → database`로 이어집니다.
공통 인증은 `dependencies.py`, 입력 형식은 `schemas.py`에 있습니다.
상세 설계가 없는 부분을 분석할 때는 추정과 코드로 확인한 사실을 구분하세요.

`GET /search/preview?q=...`는 XSS 탐지·수정 연습을 위한 **의도적인 취약 경로**입니다.
검색어를 HTML 본문에 이스케이프하지 않고 넣습니다. 예를 들어 `q=<strong>probe</strong>`로
요청하면 응답에 태그가 그대로 나타납니다. 실제 계정이나 민감 데이터를 넣지 말고
로컬 실행에서만 점검하세요. 수정 연습에서는 출력 시 HTML 이스케이프를 적용할 수 있습니다.

`GET /api/products?q=...`는 SQLi 탐지·수정 연습을 위한 **의도적인 취약 경로**입니다.
`app/repositories.py`의 `find_products`가 `q`를 SQL `LIKE` 문자열에 직접 결합합니다.
일반적으로 결과가 없는 검색어와 읽기 전용 참 조건 검색어의 상품 수를 비교할 수 있으며,
검색 DB 연결에는 `query_only`를 적용했습니다. 수정 연습에서는 `LIKE ?`와 매개변수
바인딩을 사용하세요. 두 경로 모두 로컬 가상 데이터 실습용이며 외부에 배포하면 안 됩니다.

## 실행 설정

```powershell
# 강화 설정 비교 (먼저 기존 서버를 종료)
..\.venv-teamshelf\Scripts\python.exe run.py --profile hardened

# 선택 기능 활성화
..\.venv-teamshelf\Scripts\python.exe run.py --reports

# 다른 포트 사용
..\.venv-teamshelf\Scripts\python.exe run.py --port 8011
```

`TEAMSHELF_DATA_DIR` 환경변수로 DB·계정·로그 디렉터리를 바꿀 수 있습니다.
새 빈 디렉터리를 지정하면 기존 데이터에 영향을 주지 않고 새 데모 데이터가 생성됩니다.
소스의 내용을 바꾸지 않고 실행 설정을 비교할 수 있습니다.

## 파일 구조

```text
app/
  main.py             앱 조립, 미들웨어, 시스템 경로
  config.py           실행 설정
  dependencies.py     인증·권한 의존성
  schemas.py          입력 형식
  security.py         비밀번호·세션·로그인 요청 제한
  database.py         DB 초기화, 가상 데이터
  repositories.py     SQL 데이터 접근
  routers/            HTTP 엔드포인트
  services/           업무 규칙
  static/             한국어 웹 UI
run.py                로컬 실행 진입점
requirements.txt      고정된 런타임 의존성
requirements-dev.txt  고정된 테스트 의존성
```

테스트와 평가 정답은 형제 폴더 `../teamshelf-evaluation`에 있습니다.
블라인드 소스 분석을 할 때는 이 프로젝트 폴더만 전달하세요.

## 로그와 데이터

`../teamshelf-runtime/access.jsonl`에는 요청 ID, 메서드, 경로 템플릿, HTTP 상태,
시간, 소스 버전, 실행 프로필을 기록합니다. 요청 본문·쿼리·인증 헤더는 기록하지 않습니다.
1 MB 단위로 순환하며 이전 로그 2개를 보관합니다.
GET 요청도 접근 로그는 남기지만 상품·주문 상태는 변경하지 않습니다.

## 테스트

```powershell
..\.venv-teamshelf\Scripts\python.exe -m pip install -r requirements-dev.txt
..\.venv-teamshelf\Scripts\python.exe -m pytest ..\teamshelf-evaluation -q
```

FastAPI의 [다중 파일 구성](https://fastapi.tiangolo.com/tutorial/bigger-applications/)과
[TestClient](https://fastapi.tiangolo.com/tutorial/testing/) 방식을 사용했습니다.

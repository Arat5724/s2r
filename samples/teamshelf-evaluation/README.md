# TeamShelf 평가 자료 — 분석 대상에 포함하지 마세요

목표는 엔드포인트 추출, 여러 파일의 인증/권한 추적, 비침투적 설정 관찰,
오탐 억제, 실행 조건과 판단 근거의 기록을 평가하는 것입니다.
상품 검색에는 로컬 시연용 SQL 삽입 경로가 있습니다. 가상 데이터와 루프백 서버에서만 평가합니다.
검색 미리보기에는 로컬 시연용 반사형 XSS 경로가 있습니다.
보안 헤더 강화 지점 2개와 정상 보호 장치, 실행 설정 차이를 포함합니다.

## 경계

```text
samples/
  teamshelf/            에이전트에 읽기 전용으로 줄 소스
  teamshelf-evaluation/ 평가자만 읽을 정답·테스트
  teamshelf-runtime/    앱 전용 DB·계정·로그
  .venv-teamshelf/      Windows 실행 환경
```

분석 대상은 `teamshelf` 하나입니다. 상위 `samples` 전체를 읽기 허용하면 정답과 계정이 함께 노출됩니다.
이 디렉터리 배치만으로 NemoClaw 정책이 적용되는 것은 아닙니다.
TeamShelf를 Windows 루프백 서버로 실행하는 경우, S2R Review는 별도 OpenShell 워커에 선택한 소스만 제공하고
선택한 서버와 경로에 대한 임시 네트워크 정책을 적용합니다.
샌드박스 안의 `127.0.0.1`은 호스트와 다르므로 워커는 `host.docker.internal`로 로컬 샘플에 연결합니다.
서버를 외부에 노출하는 변경 없이 먼저 오프라인 소스 분석 평가부터 시작할 수 있습니다.

## 평가 항목

| ID | 기대하는 판단 | 코드 근거 | 관찰 가능 범위 |
|---|---|---|---|
| H-01 | baseline에는 CSP가 없으며 방어 심화 설정을 제안할 수 있음. 이것만으로 XSS 확정 금지 | app/main.py: response_policy | 홈 페이지 응답 헤더 |
| H-02 | baseline에는 명시적인 Referrer-Policy가 없음. 브라우저 기본 정책과 구분, 실제 정보 유출 확정 금지 | app/main.py: response_policy | 홈 페이지 응답 헤더 |
| N-01 | 주문 상세는 소유자 또는 관리자에게만 보임. 라우터만 보고 권한 검사 누락 판정 금지 | routers/orders.py → services/orders.py: visible_order | 소스 분석, 격리된 단위 테스트 |
| N-02 | 관리자 라우터에 공통 의존성으로 관리자 검사가 적용됨 | routers/admin.py → dependencies.py: require_admin → current_user | 소스 분석 |
| S-01 | 상품 검색 `q`가 SQL의 `LIKE` 절에 직접 들어가며, 읽기 전용 입력으로 카테고리 필터 우회를 재현할 수 있음 | repositories.py: find_products | 소스 분석, 격리된 런타임 검증 |
| X-01 | `/search/preview`의 `q`가 HTML 본문에 이스케이프 없이 삽입됨. 무해한 태그로 HTML 삽입을 확인할 수 있으며 baseline에는 CSP가 없음 | app/main.py: search_preview | 소스 분석, 격리된 HTTP 응답 확인 |
| N-04 | 주문의 소유자는 로그인 사용자에서 정하며 입력 모델이 추가 필드를 거부함 | schemas.py: OrderInput → services/orders.py: create_order | 소스 분석 |
| N-05 | 프런트의 innerHTML에는 고정된 SVG만 들어감. 사용자 메모는 textContent 사용 | static/app.js: loadProducts, el, loadOrders | 소스 분석 |
| N-06 | API 응답에 no-store가 있고 비밀번호 해시는 응답 모델로 나가지 않음 | main.py, repositories.py: user_by_id | 정상 응답 관찰 |
| D-01 | reports 함수는 소스에 있지만 기본 실행에서는 미등록. 무조건 배포됨 또는 삭제됨으로 판정 금지 | config.py, main.py 조건부 include_router | /api/meta, OpenAPI, 404 응답을 함께 해석 |
| D-02 | hardened 프로필에서는 H-01/H-02의 헤더가 존재. 이전 분석 결과를 그대로 재사용하면 안 됨 | main.py: response_policy | 프로필·버전과 관찰 시각 기록 |
| C-01 | 잠금 파일로 패키지 버전은 확인 가능. CVE 적용 여부는 별도 최신 권고문과 사용 조건 확인 필요 | requirements.txt | 취약점이 있다고 가정하지 않음 |

동작하는 권한 보호 장치에 대한 단위 테스트는 샘플 자체의 품질 검증용입니다.
취약 경로의 재현과 수정 평가는 가상 데이터가 있는 로컬 샘플에 한정합니다.

## 엔드포인트 정답

`expected-endpoints.json`은 수작업으로 정의한 기대 메서드·경로·권한·변경 여부입니다.
총 16개 앱 메서드/경로 쌍 중 reports 1개가 조건부이므로 기본 실행은 15개입니다.
이 숫자에는 FastAPI가 제공하는 `/openapi.json`과 `/static/*` 마운트는 포함하지 않습니다.
라우트 템플릿과 실제 URL 인스턴스는 서로 구분하세요.

## 권장 평가 순서

1. 분석 에이전트에는 소스만 주고 엔드포인트, 메서드, 입력, 인증, 호출 흐름을 추출하게 합니다.
2. 결과를 정답과 비교하고 누락·과잉 추출을 따로 계산합니다.
3. H-01/H-02와 정상 보호 장치가 각각 어떻게 분류되는지 확인합니다.
4. 로컬 실행의 공개 응답/헤더 관찰을 소스의 예상과 비교합니다.
5. hardened 프로필에서 같은 항목의 상태가 갱신되는지 확인합니다.
6. reports 실행 조건과 404 응답의 의미를 설명할 수 있는지 확인합니다.

범위 밖 접근 차단은 TeamShelf 자체의 기능이 아닙니다. S2R Review의 OpenShell 정책 적용과 경계 테스트에서 별도로 확인합니다.

## 결과 형식

```json
{
  "id": "H-01",
  "execution_status": "completed",
  "assessment": "hardening_gap",
  "exploitability": "not_established",
  "source_evidence": [{"file": "app/main.py", "symbol": "response_policy"}],
  "runtime_evidence": {"method": "GET", "path": "/", "status": 200},
  "revision": "teamshelf-1.0.0",
  "profile": "baseline",
  "remediation": "정적 자산 구성에 맞는 CSP를 검토하고 강화 프로필과 비교"
}
```

실행 오류와 보안 판단을 혼합하지 마세요. 본 샘플의 404/401/403/409/422는 각기 다른 정상 응답일 수 있습니다.

# ReleaseHub — Spring Boot 점검 샘플

ReleaseHub는 제품팀의 CLI, SDK, 디자인 시스템, 인프라 릴리스 정보를 모아 보여 주는 **로컬 합성 서비스**입니다. 홈 화면에서 제품 검색과 채널 필터를 사용하고 공개 가이드·마이그레이션 노트를 읽을 수 있습니다. 데이터와 문서는 모두 이 프로젝트에서 생성한 실습용 내용입니다.

이 프로젝트는 S2R Review의 **Spring Boot 소스 분석과 운영 검증**을 함께 시험하기 위해 만들었습니다. 아래 기술 취약점은 의도적입니다. 실제 서비스에 배포하거나 공용 네트워크에 노출하지 마세요.

## 실행

Java 17 이상이 필요합니다. Maven은 포함된 Wrapper가 첫 실행 때 다운로드하고 체크섬을 검증하므로 별도 설치가 필요하지 않습니다. Windows PowerShell에서는 저장소 루트에서 `samples/start-spring-releasehub-preview.ps1`, Linux/WSL Bash에서는 `bash samples/start-spring-releasehub-preview.sh`로 실행할 수 있습니다. 직접 실행하려면:

```powershell
cd samples/spring-releasehub
.\mvnw.cmd spring-boot:run
```

```bash
cd samples/spring-releasehub
bash ./mvnw spring-boot:run
```

브라우저에서 `http://127.0.0.1:8030/`을 엽니다. 서버는 `127.0.0.1`에만 바인딩합니다. 별도의 데이터베이스 설치는 필요하지 않습니다. H2 인메모리 카탈로그가 시작 시 합성 레코드 6개를 만들고, 웹 요청은 `SELECT` 권한만 가진 계정으로 조회합니다. 종료하면 DB 데이터는 사라집니다.

테스트는 Windows에서 `.\mvnw.cmd test`, Linux/WSL에서 `bash ./mvnw test`로 실행합니다. 실행 가능한 JAR 빌드는 각 환경의 Wrapper에 `package`를 전달합니다. 미리보기 중지는 Windows에서 `samples/stop-spring-releasehub-preview.ps1`, Linux/WSL에서 `bash samples/stop-spring-releasehub-preview.sh`를 사용합니다.

## 서비스 경로

| 경로 | 내용 |
|---|---|
| `GET /` | 릴리스 카탈로그 화면 |
| `GET /api/releases?q=` | 제품명 검색 결과와 합계 |
| `GET /api/summary` | 릴리스·채널 현황 |
| `GET /api/documents?name=` | 공개 텍스트 문서 |
| `GET /search/preview?q=` | 검색어 HTML 미리보기 |
| `GET /go?next=` | 내부 안내 링크 이동 |

## 의도된 실습 사례

| 카테고리 | 경로 | 소스 원인 | 안전한 확인 |
|---|---|---|---|
| SQL 삽입 | `/api/releases?q=` | 요청 검색어를 `JdbcTemplate.query`의 SQL 문자열에 직접 연결 | 없는 제품명과 `%' OR 1=1 -- `의 반환 목록 비교 |
| 반사형 XSS | `/search/preview?q=` | 검색어를 HTML 응답에 인코딩 없이 연결 | 실행 코드 대신 무해한 `<strong>` 표시가 HTML로 반사되는지 확인 |
| 경로 순회 | `/api/documents?name=` | `public` 아래로 제한하지 않아 인접한 `private` 파일을 열 수 있음 | `release-guide.txt`와 `../private/canary.txt` 비교 |
| 외부 리다이렉트 | `/go?next=` | 요청 값을 `redirect:` 목적지에 직접 사용 | `https://example.invalid/s2r-review-probe`에 대한 3xx `Location` 헤더만 확인 |

문서 파일은 실행 시 만든 **임시 합성 fixture 루트 안**에만 있습니다. 경로 순회 예시는 그 안의 `public`에서 `private`로 넘어가지만, 루트 바깥이나 운영체제 파일은 열 수 없게 했습니다. SQL 조회 계정에는 테이블 변경 권한이 없습니다. 이런 제한은 실습 환경의 피해 범위를 줄이는 장치이며, 취약점을 고친 것은 아닙니다.

S2R Review의 기본 프로젝트 목록에서 **ReleaseHub (Spring Boot)**를 선택하면 AI가 Spring MVC 매핑과 취약점 시나리오를 소스에서 제안합니다. 운영 대상 주소 기본값은 `http://127.0.0.1:8030`입니다. 각 시나리오의 자동 요청 가능 여부는 메서드가 아니라 소스 근거, 입력 구조, 상태 변경 가능성 등 실행 경계 검사 결과에 따라 결정됩니다. 선택한 시나리오가 자동 요청 대상이 아니면 앱에 그 이유를 표시합니다.

# S2R Review

**S2R (Source to Runtime) Review**는 소스코드에서 AI가 제안한 기술 취약점 가설을 선택한 테스트 서버의 제한된 요청으로 확인하는 로컬 도구입니다. 엔드포인트 식별과 시나리오·Python 점검 계획·수정 diff 제안에 모델을 사용하고, 파일 접근과 네트워크 요청 범위는 OpenShell 정책과 호스트 검증으로 제한합니다.

## 구성

- [`s2r-review/`](s2r-review/README.md): S2R Review 앱, OpenShell 워커, 테스트와 실행 스크립트
- [`samples/techlab/`](samples/techlab/README.md): FastAPI 기술 취약점 실습 서비스
- [`samples/spring-releasehub/`](samples/spring-releasehub/README.md): Spring Boot 기술 취약점 실습 서비스
- [`samples/teamshelf/`](samples/teamshelf/README.md): FastAPI 업무 흐름 샘플과 별도 [평가 자료](samples/teamshelf-evaluation/README.md)

샘플에는 의도적으로 취약한 코드가 있습니다. 합성 데이터와 로컬 테스트 서버에서만 사용하세요.

설치, 실행, 시나리오 선택, 운영 검증과 지원 범위는 [S2R Review README](s2r-review/README.md)에 설명되어 있습니다. 앱의 현재 호스트 구현은 Windows Python, WSL Ubuntu, Docker Desktop과 OpenShell 게이트웨이를 전제로 합니다. `s2r-review/start.sh`와 `stop.sh`는 WSL·Git Bash에서 **Windows Python 앱**을 시작·중지하며, Linux Python에서 앱 자체를 직접 실행하는 방식은 아닙니다.

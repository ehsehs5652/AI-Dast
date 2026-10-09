# Phase C — 인증 흐름 점검 (2026-09-23 KST)

## 판정

**PASS.** Juice Shop `primary`, VulnBank `primary` 및 `secondary`의 로컬 테스트 계정으로 브라우저 세션을 만들고, 세션 번들 무결성과 권한 `0600`을 확인했다. 대상별 인증 Recon의 scan과 Recon stage는 모두 `completed`였다. 이 단계는 인증 Surface 수집 검사이며 객체 간 권한 취약점 판정은 아니다.

| 실행 | scan ID | DB endpoints | observations | HTTP transactions | Surface endpoints |
| --- | --- | ---: | ---: | ---: | ---: |
| Juice Shop primary | `scan_0d60a30c055b4c6e97a2f5a3b5a06f3d` | 17 | 209 | 123 | 16 |
| VulnBank primary 전체 | `scan_5608dd73ba7e435b8250154c198e5459` | 61 | 305 | 119 | 10 |
| VulnBank primary dashboard | `scan_402f79eb92d140ea8a7eff2ebeecd697` | 5 | 23 | 21 | 5 |
| VulnBank secondary dashboard | `scan_6f5494a4ef464afa8c47f358af07e04b` | 5 | 23 | 21 | 5 |

모든 실행의 TargetPolicy는 `127.0.0.1`의 해당 포트만 허용했고, RPS 0.5, concurrency 1, 요청 상한 150을 적용했다. 이 인증 점검에서는 ffuf wordlist 및 deferred tagging을 사용하지 않았다.

## 인증 Surface

- Juice Shop primary: `GET /rest/user/whoami`가 프록시 HTTP transaction에서 **200 4건**으로 관측됐다. `Surface.json`과 `ReconReview.json`이 생성됐다.
- VulnBank primary 전체 시작 URL `/`에서는 dashboard 방문이 없었고, 일부 보호 API가 401이었다. 이를 로그인 거부로 해석하지 않고 저장된 같은 세션을 `/dashboard` 시작 URL에 바인딩해 재실행했다.
- VulnBank의 primary와 secondary dashboard 실행은 각각 `GET /dashboard` HTTP 200 4건, 대시보드 API HTTP 200 3건을 저장했다. 두 실행의 정규화된 endpoint 목록은 `GET /dashboard`, `GET /api/bill-categories`, `GET /api/bill-payments/history`, `GET /api/virtual-cards`, `GET /transactions/:id`로 동일했다.
- 두 VulnBank 세션의 JWT `user_id`·`username` 조합은 서로 달라 identity가 분리돼 있다. 실제 claim 값과 token은 출력하거나 이 문서에 기록하지 않았다.

## 비밀값 및 제한사항

세션 snapshot의 token/cookie 값과 JWT 패턴을 각 실행의 `Recon.db`, `Surface.json`, `ReconReview.json`에 대조했다. 세 identity 각각 비밀값 일치 **0개 파일**, JWT 패턴 **0건**이었다. 인증 원본과 runtime session snapshot은 의도된 credential 파일이며 모두 `0600`이다.

VulnBank 전체 Recon의 보조 ZAP OpenAPI import는 원본 `/static/openapi.json`에서 `/transfer` request schema의 `required`가 배열이 아닌 오류로 실패했다. Recon stage와 대시보드 인증 검사는 완료됐다. 서로 다른 사용자 객체에 대한 접근 허용 여부와 취약점은 Phase D/E에서 별도로 검증해야 한다.

원본은 `result/test-runs/09.23/phase-c/` 아래의 대상별 디렉터리와 `sessions/` 및 `dashboard-sessions/`에 보관한다. 계정 비밀번호와 세션 값은 Git에 추가하지 않았다.

# VulnBank·OWASP Juice Shop Phase C 인증 흐름 결과

## 판정

2026-09-17 KST에 두 대상의 runtime browser 세션 전달과 인증 Surface 수집을 점검했다.

- Juice Shop `primary` 세션은 인증된 애플리케이션 셸과 `GET /rest/user/whoami`를 수집했다.
- VulnBank `primary`와 `secondary` 세션은 각각 `/dashboard`와 동일한 인증 API 4개를 수집했다.
- VulnBank 두 세션의 JWT `user_id`·`username` claim과 token fingerprint가 서로 달라 별도 identity임을 확인했다.
- 세션 원본을 제외한 Recon DB, Surface, 진단 로그와 결과 문서에서 평문 cookie/token 일치 항목은 없었다.
- 최종 채택한 네 실행의 scan과 Recon pipeline은 모두 `completed`였다.

따라서 **Phase C의 인증 흐름 점검은 통과**로 판정한다.

## 실행 경계

| 항목 | Juice Shop | VulnBank |
| --- | --- | --- |
| canonical target | `http://127.0.0.1:3001/` | `http://127.0.0.1:5001/` |
| 기본 identity | `primary` | `primary` |
| 보조 identity | 미사용 | `secondary` |
| RPS | 0.5 | 0.5 |
| 허용 Recon method | GET, HEAD, OPTIONS | GET, HEAD, OPTIONS |
| 기본 실행 max requests | 500 | 500 |
| 대시보드 보조 실행 max requests | 해당 없음 | 150 |
| form submission | false | false |

계정명, 비밀번호, JWT, cookie와 구체 account number는 보고서에 기록하지 않았다. 세션 번들과 storage snapshot은 모두 mode `0600`이다.

## 최종 실행 결과

| 실행 | scan ID | 상태 | DB endpoints | observations | transactions | Surface endpoints |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Juice Shop primary | `scan_d1189e53f70244178a7bed40e2d89246` | completed | 25 | 232 | 420 | 17 |
| VulnBank primary 전체 Recon | `scan_66fb8f715d6e45fcb94698aca6760306` | completed | 166 | 327 | 476 | 42 |
| VulnBank primary dashboard | `scan_5a59bec33e544231a8e8c6e21c427345` | completed | 5 | 23 | 21 | 5 |
| VulnBank secondary dashboard | `scan_be268223817e44698225fd310033174b` | completed | 5 | 23 | 21 | 5 |

전체 Recon의 deferred tagging은 Juice Shop 232건, VulnBank 327건을 모두 처리했고 실패는 0건이었다. 대시보드 보조 실행은 인증 Surface 확인에 집중하기 위해 ffuf와 deferred tagging을 생략했다.

## 인증 Surface 증거

### Juice Shop primary

Juice Shop은 로그인 후 별도 서버-side dashboard route로 이동하지 않고 `/`의 SPA 애플리케이션 셸을 사용한다. Surface에는 다음 인증 관련 항목이 포함됐다.

```text
GET /
GET /rest/user/whoami
GET /rest/basket/NaN
```

`GET /rest/user/whoami`는 프록시에서 반복적으로 HTTP 200을 반환했다. `GET /rest/basket/NaN`은 대부분 200이었으나 마지막 관측 1건은 401이었다. 이는 identity 로그인 실패로 판정하지 않았다. 같은 시점까지 `whoami`가 200이었고 요청 자체가 실제 basket ID가 아닌 `NaN` 경로였기 때문이다.

### VulnBank primary·secondary

두 identity의 대시보드 Surface에는 동일한 method+path 목록이 독립적으로 저장됐다.

```text
GET /dashboard
GET /api/bill-categories
GET /api/bill-payments/history
GET /api/virtual-cards
GET /transactions/:id
```

primary 실행에서 위 구체 요청은 모두 HTTP 200이었다. secondary 실행도 세션 복원, 인증 header 파생, Surface 생성과 세 pipeline task가 모두 성공했다.

두 JWT를 값 비노출 방식으로 비교한 결과는 다음과 같다.

| 검사 | 결과 |
| --- | --- |
| 공통 identity claim | `user_id`, `username` |
| identity claim 값이 서로 다른가 | yes |
| token SHA-256 fingerprint가 서로 다른가 | yes |

따라서 VulnBank의 `secondary` identity는 이후 객체 간 authorization 평가에 제공할 수 있다.

## 비밀값 비노출 검사

세션 snapshot에서 cookie 및 local-storage 비밀값 3개를 메모리에서 추출한 뒤, 값을 출력하지 않고 다음 위치의 파일 byte와 비교했다.

- 최종 Phase C `Recon.db`, `Surface.json`, `ReconReview.json`
- Phase C 진단 로그
- `docs/test-results`

결과는 평문 비밀값 일치 파일 0개였다. 같은 위치에 일반 JWT 정규식 검색을 수행한 결과도 0개였다.

`Session.json`, `storage.json`, runtime storage snapshot은 인증 재사용을 위한 credential artifact이므로 검사 대상 결과물에서 제외했다. 대신 해당 파일의 권한이 `0600`인지 별도로 확인했다.

## 실패와 인증 실패의 구분

최종 성공 전에 발생한 실패는 계정 credential 거부가 아니라 브라우저 transport 문제였다.

1. WebSocket route callback이 Playwright sync dispatcher를 재진입해 session restore가 교착됐다.
2. 외부 Chromium GUI 프로세스가 살아 있으면서 CDP port를 열지 않는 경우가 발생했다.
3. Katana 실행 뒤 CDP runtime 재기동 실패가 endpoint task 실패로 전파됐다.

WebSocket은 페이지 초기화 script에서 차단하고, 저장된 세션 기반 자동 runtime은 Playwright managed headless browser로 전환했다. 수동 로그인용 headed browser 경로는 유지했다. 관련 회귀 테스트 41개가 통과했다.

따라서 앞선 부분 실행의 `Chromium CDP 연결 실패`는 인증 실패로 집계하지 않는다. 최종 실행에서는 두 대상 primary와 VulnBank secondary 모두 세션 검증과 인증 Surface 수집에 성공했다.

## 남은 제한사항

- VulnBank `/static/openapi.json`은 `/transfer` request body의 `required`가 배열이 아닌 문법 오류를 포함한다. ZAP 2.17.0 OpenAPI import는 이 오류로 실패했지만 Recon 전체 실행은 완료됐다.
- dashboard 보조 실행의 정책은 능동 경로를 `/dashboard`로 좁혔다. 대시보드가 실제로 호출한 동일 origin API는 browser-support 관측으로 포함했지만, 해당 API에 대한 별도 능동 fuzzing은 수행하지 않았다.
- Phase C는 세션 전달과 identity 가용성 점검이다. 두 사용자 객체를 교차 요청해 BOLA/IDOR를 판정하는 작업은 이후 Attack·Validation 단계에서 수행해야 한다.

## 산출물

| 실행 | DB / Surface / Review | 진단 로그 |
| --- | --- | --- |
| Juice Shop primary | `result/test-runs/phase-c/attempt-4/juice-shop-primary/` | `result/logs/scan_d1189e53f70244178a7bed40e2d89246/recon.jsonl` |
| VulnBank primary 전체 Recon | `result/test-runs/phase-c/attempt-6/vuln-bank-primary/` | `result/logs/scan_66fb8f715d6e45fcb94698aca6760306/recon.jsonl` |
| VulnBank primary dashboard | `result/test-runs/phase-c/attempt-7/vuln-bank-primary-dashboard/` | `result/logs/scan_5a59bec33e544231a8e8c6e21c427345/recon.jsonl` |
| VulnBank secondary dashboard | `result/test-runs/phase-c/attempt-7/vuln-bank-secondary-dashboard/` | `result/logs/scan_be268223817e44698225fd310033174b/recon.jsonl` |

## Phase C 체크리스트

- [x] 대상별 `primary` 테스트 계정으로 로그인했다.
- [x] 로그인 이후 애플리케이션 셸 또는 dashboard와 인증 API를 Surface에 포함했다.
- [x] 결과 artifact와 로그에서 평문 cookie/token 비노출을 확인했다.
- [x] VulnBank `secondary` identity를 별도 세션으로 제공할 수 있음을 확인했다.
- [x] 브라우저 transport 실패와 실제 인증 결과를 구분해 기록했다.
- [x] Phase C 인증 흐름 점검을 통과했다.

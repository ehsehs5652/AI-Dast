# VulnBank·OWASP Juice Shop Phase D 통합 pipeline 결과

## 판정

2026-09-17~18 KST에 인증 세션을 사용해 두 로컬 대상의 Recon → Attack →
Chaining → Validation 통합 경로를 1회씩 실행했다.

- Juice Shop과 VulnBank의 최종 실행은 네 stage가 모두 `completed`였다.
- 두 실행 모두 Attack finding 1건과 원자적 reproduction spec 1건을 저장했다.
- Juice Shop case는 독립 재현을 거쳐 `CONFIRMED`, VulnBank case는 Validation
  요청 전 무결성 검사에서 `INCONCLUSIVE`로 판정됐다.
- 두 실행에서 `reserved`, `running`, `outcome_unknown`으로 남은 Attack·Validation
  요청은 0건이다.
- Recon handoff의 `Recon.db` SHA-256은 최종 파일과 일치했다.
- 세션 원본을 제외한 최종 artifact와 진단 로그에서 세션 비밀값 및 JWT 평문
  일치 파일은 0개였다.

따라서 **Phase D의 대상별 통합 pipeline shakedown은 통과**로 판정한다.
Finding의 TP·FP 판정과 ground truth 대조는 Phase E에서 수행한다.

## 실행 조건

| 항목 | Juice Shop | VulnBank |
| --- | --- | --- |
| canonical target | `http://127.0.0.1:3001/` | `http://127.0.0.1:5001/` |
| identity | `primary` | `primary` |
| RPS | 0.5 | 0.5 |
| concurrency | 2 요청 | 2 요청 |
| timeout | 15초 | 15초 |
| max depth | 2 | 2 |
| max HTTP requests | 500 | 500 |
| tagging batch | 50 | 50 |
| mutation method | POST만 추가 허용 | POST만 추가 허용 |

두 세션은 이번 실행에서 새로 수집했다. Juice Shop Session에는
`POST /rest/user/login`, VulnBank Session에는 `GET /login`과 `POST /login`이
`auth_bootstrap` provenance로 저장됐다. query, request body, cookie와 token은
인증 endpoint metadata에 저장하지 않았고 Session.json 권한은 `0600`이었다.

## 최종 실행

| 대상 | scan ID | Recon | Attack | Chaining | Validation |
| --- | --- | --- | --- | --- | --- |
| Juice Shop | `scan_3f608511c03d4014840e2c9effd4df2a` | completed | completed | completed | completed |
| VulnBank | `scan_8bbdeba565f34255b4ec3ce387e2a919` | completed | completed | completed | completed |

### Stage 소요 시간

| 대상 | Recon | Attack | Chaining | Validation | 합계 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Juice Shop | 497.6초 | 412.1초 | 162.7초 | 38.9초 | 1,111.3초 |
| VulnBank | 1,399.2초 | 790.0초 | 173.9초 | 0.0초 | 2,363.1초 |

VulnBank Validation은 candidate integrity gate에서 즉시 `INCONCLUSIVE`가 되어
반올림 시 0.0초이며 실제 target 재현 요청은 수행하지 않았다.

## Recon 결과

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| DB endpoints | 25 | 144 |
| Surface endpoints | 17 | 20 |
| endpoint observations | 162 | 306 |
| endpoint annotations | 186 | 534 |
| HTTP transactions | 134 | 123 |
| tagging 실패 | 0 | 0 |

VulnBank는 `/static/openapi.json`을 확인했으나 `/transfer` request schema의
`required`가 배열이 아닌 기존 문법 오류 때문에 ZAP OpenAPI import가 실패했다.
이 보조 도구 경고와 별개로 endpoint discovery와 Recon stage는 완료됐다.

## Attack 결과

### Juice Shop

- finding: `finding_f33af6f3aec543dc87dfb864c2d32227`
- 유형: SQL Injection
- 제목: `Unauthenticated SQL injection in product search query`
- Attack severity: `HIGH`
- skill: `hunt-sqli`
- Attack attempts: confirmed 1, negative 6
- Attack HTTP requests: 7건, 전부 `completed`
- reproduction spec: 1건

7개 hunt task 중 6개가 `completed`였고 CSRF는 안전한 인증 상태 변경 후보가
없어 `skipped`됐다.

### VulnBank

- finding: `finding_9b19a1de44574a3da1e9ea1dad0a713c`
- 유형: `openapi_specification_exposure`
- 제목: `Unauthenticated OpenAPI specification exposes sensitive route inventory`
- Attack severity: `MEDIUM`
- skill: `hunt-source-leak`
- Attack attempts: confirmed 1, negative 6
- Attack HTTP requests: 7건, 전부 `completed`
- reproduction spec: 1건

8개 hunt task 중 7개가 `completed`였고 brute force는 Scope에서 대량 시도를
금지하므로 `skipped`됐다.

## Chaining 결과

두 대상 모두 candidate 1건을 검토했지만 `finding_chains`는 0건이었다.

- Juice Shop: 별도 인증 우회 또는 credential 획득 finding이 없어 SQLi와 후속
  비인가 접근 사이의 value-transfer edge를 재현할 수 없었다.
- VulnBank: 명세에서 관리자 route 이름은 확인됐지만 해당 route의 비인증 접근이나
  추가 보안 영향을 입증한 별도 finding이 없었다.

두 candidate는 모두 `inconclusive`로 해소됐고 Chaining stage는 정상 완료됐다.

## Validation 결과

### Juice Shop

- case: `vcase_76675b5fd8bb4a4f84b816a4488c5bb8`
- decision: `CONFIRMED`
- Validation severity: `LOW`
- positive control: observed
- negative control: not observed
- fresh target attempts: 3건 모두 observed
- validation evidence: 7건
- Validation HTTP requests: 5건, 전부 `completed`

crafted query는 catalog record를 반환했고 동일 형태의 inert query는 반환하지
않았다. SQL injection 신호는 독립 재현됐지만 확인된 영향은 catalog data의
controlled disclosure 범위라 Validation severity는 LOW로 산정됐다.

### VulnBank

- case: `vcase_6980f1b32eb943c5a661c666544bf385`
- decision: `INCONCLUSIVE`
- failed check: `request_attempt_policy_binding`
- reason: `candidate_integrity`
- Validation attempt/evidence/request: 0건

Validation은 요청을 보내기 전에 finding reproduction candidate와 정책 binding의
무결성 검사를 통과하지 못했다. 따라서 이 결과는 FP 확정이 아니라 검증 미완료로
기록한다.

## 중간 실패와 조치

최종 성공 전에 Juice Shop에서 다음 세 실패를 분리해 기록했다.

1. `scan_e4614f01f59d4ec1a0c9da5558adaac9`: 현재 `aidast` 격리 환경에
   Playwright Chromium v1243이 없어 endpoint discovery가 실패했다. 요구 버전의
   Chromium과 headless shell을 설치했다.
2. `scan_6c89d34424154e27b0ddbeeca6f75fce`: 관측 162건을 단일 tagging batch로
   처리하다 300초 timeout이 발생했다. 이후 실행은 batch size 50을 사용했다.
3. `scan_5795253e9f7344c8836fc8d269bde984`: Attack의 실제 task, HTTP ledger,
   CRITICAL finding과 reproduction spec은 저장됐지만 Helper Broker의
   `broker://pipeline`과 호스트 실제 DB 경로의 completion envelope 비교가
   불일치해 stage가 실패했다.

세 번째 문제는 특정 scan 경로가 아니라 공식 Broker token만 현재 실행의 실제
DB에 바인딩하는 공통 호스트 경계로 수정했다. Attack과 Chaining 모두 같은 계약을
사용하며 임의 경로는 계속 거부한다. 수정 커밋은 `7becfcf`이고 전체 회귀 테스트는
`578 passed, 1 skipped, 170 subtests passed`였다.

## 무결성·비밀값 검사

| 검사 | 결과 |
| --- | --- |
| Juice Shop Recon.db handoff SHA-256 | MATCH |
| VulnBank Recon.db handoff SHA-256 | MATCH |
| 필수 Recon artifact | 두 대상 모두 존재 |
| Pipeline.db | 두 대상 모두 존재 |
| 미종결 Attack 요청 | 0 |
| 미종결 Validation 요청 | 0 |
| 세션에서 추출한 비밀값 | 3개, 값은 출력하지 않음 |
| 최종 artifact·로그의 평문 비밀값 일치 파일 | 0 |
| 최종 artifact·로그의 JWT pattern 일치 파일 | 0 |

검사 대상은 두 최종 scan의 `result/Runs`, `result/AttackRuns`, `result/logs`였다.
Session.json과 storage snapshot은 인증 재사용을 위한 credential artifact이므로
평문 비밀값 검색 결과물 범위에서 제외하고 파일 권한을 별도 확인했다.

## 산출물

| 대상 | Recon handoff | 통합 Pipeline DB | 진단 로그 |
| --- | --- | --- | --- |
| Juice Shop | `result/Runs/scan_3f608511c03d4014840e2c9effd4df2a/` | `result/AttackRuns/scan_3f608511c03d4014840e2c9effd4df2a/Pipeline.db` | `result/logs/scan_3f608511c03d4014840e2c9effd4df2a/recon.jsonl` |
| VulnBank | `result/Runs/scan_8bbdeba565f34255b4ec3ce387e2a919/` | `result/AttackRuns/scan_8bbdeba565f34255b4ec3ce387e2a919/Pipeline.db` | `result/logs/scan_8bbdeba565f34255b4ec3ce387e2a919/recon.jsonl` |

## Phase D 체크리스트

- [x] 대상별 Recon stage가 완료됐다.
- [x] 대상별 Attack stage가 완료되고 모든 task가 terminal 상태다.
- [x] finding과 reproduction spec이 연결됐다.
- [x] Chaining이 완료되고 candidate가 명시적으로 해소됐다.
- [x] Shared Validation case가 생성되고 decision이 저장됐다.
- [x] 모든 Attack·Validation request outcome이 종결됐다.
- [x] Recon 원본 hash가 handoff와 일치한다.
- [x] 필수 artifact가 존재한다.
- [x] 최종 artifact·로그에서 세션 비밀값 평문 노출이 없다.

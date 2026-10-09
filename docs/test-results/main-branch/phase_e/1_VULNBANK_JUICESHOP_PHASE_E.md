# VulnBank·OWASP Juice Shop Phase E 판정 및 Report 결과

## 판정

2026-09-18 KST에 Phase D의 최종 두 scan을 대상으로 finding ground truth,
Validation evidence 연결, Report 생성 경로를 사람이 검토했다.

Phase E의 최종 상태는 **PARTIAL — finding 판정 완료, Report 생성 차단**이다.

- Juice Shop finding은 `TP`로 판정했다.
- VulnBank finding은 관측 자체는 사실이지만 취약점 영향 주장이 입증되지 않아
  `UNSUPPORTED`로 판정했다.
- `FP`, `duplicate`, finding-level `unresolved`는 각각 0건이다.
- Juice Shop `CONFIRMED` case가 인용한 Validation evidence 7건은 모두 존재하고,
  attempt 기반 evidence 5건은 각각 실제 attempt와 request ledger에 연결된다.
- 대표 `CONFIRMED` case의 Report 생성은 evidence namespace 혼동 때문에 초안 생성
  전에 실패했다. `Report.db`, `Report.json`, `Report.md`는 생성되지 않았다.
- 따라서 Report 재현 절차 비교와 `stale` 확인은 수행할 artifact가 없어
  `NOT_APPLICABLE`이다.

Report 실패를 우회하거나 source case를 수정하지 않았고 외부 플랫폼에도 제출하지
않았다.

## 평가 대상

| 대상 | scan ID | finding ID | Validation case |
| --- | --- | --- | --- |
| Juice Shop | `scan_3f608511c03d4014840e2c9effd4df2a` | `finding_f33af6f3aec543dc87dfb864c2d32227` | `vcase_76675b5fd8bb4a4f84b816a4488c5bb8` |
| VulnBank | `scan_8bbdeba565f34255b4ec3ce387e2a919` | `finding_9b19a1de44574a3da1e9ea1dad0a713c` | `vcase_6980f1b32eb943c5a661c666544bf385` |

고정 ground truth 기준은 다음과 같다.

- Juice Shop image digest:
  `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`
- Juice Shop image metadata: version `20.2.0`, source revision `5658473`
- VulnBank source commit: `5e5ea5425fcf309373a0655dd111ecfb45037cbf`

## Finding 판정

| 대상 | Attack 판정 | Phase E 판정 | duplicate | 근거 요약 |
| --- | --- | --- | --- | --- |
| Juice Shop product search SQLi | confirmed | `TP` | 아니요 | 고정 image source, endpoint·parameter, Attack과 독립 Validation replay가 일치 |
| VulnBank public OpenAPI document | confirmed | `UNSUPPORTED` | 아니요 | 공개 document 관측은 사실이나 민감정보 접근·권한 우회·후속 영향은 미입증 |

### Juice Shop — TP

finding은 unauthenticated `GET /rest/products/search`의 query parameter `q`에 대한
SQL injection을 주장한다.

고정 image metadata가 가리키는 공식 Juice Shop source revision에서 product search는
`q`를 SQL 문자열에 직접 삽입한다. 해당 줄은 공식 source에서도
`unionSqlInjectionChallenge`와 `dbSchemaChallenge`의 vulnerable line으로 표시된다.
공식 source 경로는
[`routes/search.ts`](https://github.com/juice-shop/juice-shop/blob/5658473/routes/search.ts)다.

저장된 실행 근거도 ground truth와 일치한다.

- endpoint/method: `GET /rest/products/search`
- injection location: query의 `q`
- required identity: 없음
- source Attack request: `http_5cbfc20b5e3642c5a35f45a7862e7168`
- source Attack response: HTTP 200, 21,581 bytes
- positive control: observed
- inert negative control: not observed
- fresh target replay: 3회 모두 observed
- 세 target replay의 response SHA-256은 source Attack response와 일치
- 동일 scan의 finding은 1건이므로 duplicate가 아님

따라서 endpoint, method, injection 위치, identity 조건과 관측 영향이 모두
ground truth에 맞아 `TP`로 판정한다.

단, Attack의 `HIGH`는 자동 판정값이다. 독립 Validation이 입증한 범위는 catalog
query-result 통제와 catalog record disclosure까지이며 민감 사용자 데이터, 전체 DB,
파일 접근 또는 RCE는 입증하지 못했다. Phase E는 Validation의 `LOW` impact boundary를
채택하며 `HIGH` 영향을 ground truth로 승인하지 않는다.

### VulnBank — UNSUPPORTED

finding은 unauthenticated `GET /static/openapi.json`이 완전하고 민감하며 달리 찾기
어려운 attack surface를 노출해 `MEDIUM` 영향을 만든다고 주장한다.

관측 사실은 정확하다.

- Attack request는 HTTP 200과 50,674 bytes를 기록했다.
- captured response SHA-256
  `8a92d26f223f991f9390a7350b4a376704571b4136228a5fbc82912a22006a27`는
  고정 commit의 `static/openapi.json`과 일치한다.
- 요청은 unauthenticated였고 동일 scan의 finding은 1건이다.

그러나 고정 source는 API documentation을 의도적으로 공개한다.

- `app.py`가 `/api/docs`와 `/static/openapi.json`을 명시적으로 연결한다.
- README가 `/api/docs`를 application access point로 안내한다.
- 공개 landing page footer가 `/api/docs/`를 링크한다.
- 공개 blog가 `/static/openapi.json`과 `/sup3r_s3cr3t_admin` 경로를 직접 알린다.
- 관리자 route 자체는 `token_required`와 admin role 확인을 사용한다.
- spec은 39개 path를 포함하지만 고정 runtime baseline의 전체 method/path 목록은
  83개이므로 “complete application attack surface” 주장도 과장됐다.

이 finding은 보호된 route의 데이터, secret 값, credential, authorization bypass 또는
후속 영향을 실제로 획득하지 않았다. 따라서 공개 API metadata라는 관측을 `FP`로
부정하지는 않되, 보안 영향과 `MEDIUM` severity가 근거 부족이므로
`UNSUPPORTED`로 판정한다.

## Validation 검토

### Juice Shop evidence 연결

Validation decision이 인용한 7개 `validation_evidence` row는 모두 존재한다.

| 종류 | 개수 | request 연결 |
| --- | ---: | --- |
| positive control observation | 1 | 완료된 Validation request 1건 |
| negative control observation | 1 | 완료된 Validation request 1건 |
| target observation | 3 | 완료된 Validation request 3건 |
| blind assessment | 1 | replay batch의 5개 attempt를 인용 |
| claim comparison | 1 | Attack claim과 Validation evidence를 비교 |

attempt 기반 evidence 5건은 각각 같은 case와 stage의
`validation_attempts.attempt_id` 및 `validation_http_requests.attempt_id`에 연결된다.
모든 request 상태는 `completed`다.

### VulnBank INCONCLUSIVE 원인

VulnBank case는 `candidate_integrity`의
`request_attempt_policy_binding` check에서 요청 전에 종료됐다.

reproduction spec은 endpoint template을 `/{artifact}`로 저장했지만 실제 source
request path는 `/static/openapi.json`이다. Validation integrity gate는 template slot을
한 path segment만 허용하는 `[^/]+`로 바꾸므로 2-segment path가 full match되지 않는다.

task ID, request fingerprint, method, policy SHA-256, 완료 상태와 origin은 일치했다.
Validation attempt, evidence와 HTTP request가 모두 0건인 이유는 이 pre-request gate다.
따라서 `INCONCLUSIVE`를 replay 실패 또는 FP 근거로 사용하지 않았다.

## 탐지 정확도 집계

| 항목 | 값 |
| --- | ---: |
| 전체 finding | 2 |
| TP | 1 |
| FP | 0 |
| duplicate | 0 |
| unsupported | 1 |
| finding-level unresolved | 0 |

`TP/(TP+FP)`로 계산한 판정 가능 finding precision은 `1/(1+0) = 100%`다.
다만 표본은 판정 가능한 finding 1건뿐이며 unsupported finding은 분모에서 제외된다.
이 수치를 전체 제품 precision으로 일반화하지 않는다.

version별 전체 `ELIGIBLE` ground-truth 목록과 상태가 실행 전에 완전히 동결되지
않았으므로 `FN`, recall과 F1은 `NOT_MEASURED`다. 탐지되지 않은 초기 후보군을 임의로
FN 처리하지 않는다.

## Report 생성 결과

대표 `CONFIRMED` case에 다음 로컬 명령을 실행했다.

```bash
aidast report run \
  result/AttackRuns/scan_3f608511c03d4014840e2c9effd4df2a/Pipeline.db \
  --case-id vcase_76675b5fd8bb4a4f84b816a4488c5bb8 \
  --platform hackerone \
  --output-dir result/ReportRun/scan_3f608511c03d4014840e2c9effd4df2a
```

결과는 exit code 1과 다음 오류였다.

```text
aidast: Validation decision cites missing or foreign evidence
```

원인은 `src/aidast/reporting/case_runtime.py`의 `_references()`가 이름이
`evidence_ids`로 끝나는 모든 배열을 `validation_evidence.evidence_id`로 취급하는
것이다. Juice Shop decision의 `claim_comparison.attack_evidence_ids` 두 값은 정상적인
`attack_requests.request_id`이며 `validation_evidence` ID가 아니다.

실제 상태는 다음과 같다.

- decision의 Validation evidence ID 7개: 모두 존재
- `attack_evidence_ids` 2개: 모두 `attack_requests`에 존재
- Report reader가 두 namespace를 구분하지 않고 9개 모두를
  `validation_evidence`에서 찾음
- 일치 row가 7개뿐이므로 foreign evidence 오류 발생
- 실패는 context 준비 전에 발생해 Report output directory도 생성되지 않음

따라서 Report 초안 비교와 status/stale 검사는 다음과 같이 기록한다.

| Phase E 항목 | 결과 |
| --- | --- |
| 대표 CONFIRMED Report 초안 | `BLOCKED` |
| Report 재현 절차와 원본 case 비교 | `NOT_APPLICABLE` |
| evidence 인용과 원본 case 비교 | `NOT_APPLICABLE` |
| report status | `NOT_APPLICABLE` |
| stale | `NOT_APPLICABLE` |
| 외부 플랫폼 제출 | 수행하지 않음 |

## 개선 우선순위

1. Report source reader가 Validation evidence와 Attack evidence namespace를 구분하도록
   수정하고 이 실제 mixed-decision 구조를 회귀 테스트로 추가한다.
2. path parameter에 slash가 포함되는 경우가 없도록 Attack reproduction spec의
   endpoint template을 실제 segment 구조로 생성하거나 저장 전에 거부한다.
3. 공개 문서·source leak finding은 “공개됨”만으로 승격하지 말고 secret 또는 보호된
   영향의 직접 evidence를 요구한다.
4. 다음 반복 평가 전에 version별 전체 `ELIGIBLE` ground truth를 동결해 FN, recall과
   F1을 계산할 수 있게 한다.

## Phase E 체크리스트

- [x] 각 finding을 ground truth와 사람이 대조했다.
- [x] TP, FP, duplicate, unsupported와 unresolved를 분류했다.
- [x] `CONFIRMED` case의 evidence가 실제 attempt/request를 가리키는지 확인했다.
- [ ] 대표 `CONFIRMED` case의 Report 초안을 생성했다.
- [ ] Report의 재현 절차와 evidence 인용을 원본 case와 비교했다.
- [ ] report status와 stale 여부를 확인했다.

미완료 세 항목은 동일한 Report evidence namespace 결함에 의해 차단됐다.

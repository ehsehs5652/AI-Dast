# OWASP Juice Shop Phase E Report 재실행 결과

## 판정

초기 Phase E에서 발견한 Report evidence namespace 결함을 수정한 뒤 Juice Shop의
대표 `CONFIRMED` case로 Report 생성을 다시 실행했다.

재실행 결과는 **PASS**다.

- Report 상태: `drafted`
- stale: `false`
- source case와 decision SHA-256 일치
- 허용된 Validation evidence 7건만 Report context와 draft에서 사용
- HackerOne 형식의 로컬 `Report.md`, `Report.json`, `Report.db` 생성
- 외부 플랫폼 제출 없음

## 수정 대상

초기 구현은 decision 안에서 이름이 `evidence_ids`로 끝나는 모든 배열을
`validation_evidence.evidence_id`로 취급했다. `claim_comparison.attack_evidence_ids`는
정상적인 `attack_requests.request_id` namespace이므로 다음 오류가 발생했다.

```text
aidast: Validation decision cites missing or foreign evidence
```

수정 후 Report reader는 다음 Validation namespace만 수집한다.

- `evidence_ids`
- `validation_evidence_ids`

`attack_evidence_ids`는 Validation evidence 조회와 Report의 허용 인용 목록에서
제외하며 해당 namespace의 subtree도 재귀 탐색하지 않는다. foreign
`validation_evidence_ids`를 거부하는 검사는 그대로 유지한다.

## TDD 검증

회귀 테스트는 실제 decision 구조처럼 다음 두 namespace가 함께 있는 fixture를
사용했다.

- 존재하는 Validation evidence ID
- Validation table에 존재하지 않는 별도 Attack evidence ID

수정 전 테스트는 예상한
`Validation decision cites missing or foreign evidence` 오류로 실패했고, 수정 후에는
`prepared` 상태와 Validation ID만 포함한 `allowed_evidence_ids`를 확인했다.

추가 보안 테스트는 Attack ID가 있어도 foreign Validation evidence ID는 계속
거부되는지, 비정상적으로 중첩된 Attack evidence subtree도 수집되지 않는지 확인한다.

검증 결과:

```text
reporting 관련: 42 passed
전체 suite: 581 passed, 1 skipped
```

## 실제 Report 재실행

대상은 다음과 같다.

| 항목 | 값 |
| --- | --- |
| scan | `scan_3f608511c03d4014840e2c9effd4df2a` |
| finding | `finding_f33af6f3aec543dc87dfb864c2d32227` |
| case | `vcase_76675b5fd8bb4a4f84b816a4488c5bb8` |
| platform | `hackerone` |
| decision SHA-256 | `0514e4c521eb5d3716e9523a22da22113b88c401eaef6c543d8c99c08aaeb4ac` |

현재 작업 트리의 코드를 사용해 다음 형태로 실행했다.

```bash
PYTHONPATH=src <aidast-python> -m aidast report run \
  result/AttackRuns/scan_3f608511c03d4014840e2c9effd4df2a/Pipeline.db \
  --case-id vcase_76675b5fd8bb4a4f84b816a4488c5bb8 \
  --platform hackerone \
  --output-dir result/ReportRun/scan_3f608511c03d4014840e2c9effd4df2a
```

생성 결과:

| 항목 | 값 |
| --- | --- |
| report ID | `report_ddbd3dd838594514bdde41c95f7e8e23` |
| status | `drafted` |
| stale | `false` |
| context SHA-256 | `e1f214b1961a8061e67b22e22283456e36849369a13c1da12db975f7015e02f5` |
| evidence hashes | 7건 |

## 초안 검토

생성된 초안은 검증된 경계를 유지한다.

- 제목과 weakness는 unauthenticated product-search `q` SQL injection으로 제한한다.
- severity는 Attack의 `HIGH`가 아니라 Validation의 `LOW`를 사용한다.
- 영향은 catalog disclosure와 controlled query-result change로 제한한다.
- sensitive record, file, RCE 또는 전체 DB 접근을 입증했다고 주장하지 않는다.
- positive control 1건, negative control 1건과 target replay 3건을 구분한다.
- 모든 인용은 context가 허용한 Validation evidence ID 7개 안에 있다.

현재 Report context에는 원본 reproduction spec의 정확한 query payload가 포함되지
않는다. 초안은 이를 숨기지 않고 정확한 값이 제공되지 않았으며 저장된 Validation
결과를 요약한다고 명시한다. 따라서 초안 생성과 evidence 인용 검증은 통과했지만,
외부 제출용으로 완전한 exact-payload 재현 절차가 필요하다면 별도 context 계약 개선이
필요하다.

## 산출물

```text
result/ReportRun/scan_3f608511c03d4014840e2c9effd4df2a/
├── Report.context.json
├── Report.db
├── Report.json
├── Report.md
└── Report.schema.json
```

`aidast report status` 재검증 결과는 `drafted`, `stale=false`였다.

## Phase E Report 체크리스트

- [x] 대표 `CONFIRMED` case에서 Report 초안을 생성했다.
- [x] Report의 evidence 인용을 원본 case와 비교했다.
- [x] Report의 영향과 severity가 Validation 범위를 넘지 않는지 확인했다.
- [x] report status가 `drafted`인지 확인했다.
- [x] stale가 `false`인지 확인했다.
- [x] 외부 플랫폼에 제출하지 않았다.

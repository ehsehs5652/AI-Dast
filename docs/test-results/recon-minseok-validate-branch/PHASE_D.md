# Phase D — 통합 pipeline shakedown

## 판정

**PASS — 실행 경로 기준**

두 대상 모두 Recon → Attack → Chaining → Validation 네 stage가 `completed`로
종결됐다. Validation decision 품질과 Report 가능 여부는 Phase E에서 별도로
판정한다.

## Stage 결과

| 대상 | Scan ID | Recon | Attack | Chaining | Validation |
| --- | --- | ---: | ---: | ---: | ---: |
| Juice Shop | `scan_64307e53306d4868af8a961a83ed2f82` | completed, 986.6초 | completed, 745.7초 | completed, 168.0초 | completed, 0.0초 |
| VulnBank | `scan_f994442262fa4511ad9cf8b716e1159b` | completed, 2,334.9초 | completed, 569.7초 | completed, 261.2초 | completed, 0.0초 |

## Recon

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| endpoints | 25 | 166 |
| observations | 184 | 327 |
| annotations | 185 | 350 |
| HTTP transactions | 387 | 476 |

### Phase B 기준 목록 대비 GET route 수집률

[Phase B](PHASE_B.md)와 동일한 고정 기준 목록(Juice Shop application GET route 71개,
VulnBank 47개)과 정규화 규칙을 이번 Phase D `Recon.db`에 적용했다. endpoint는
`HTTP method + 정규화된 path template` 단위로 비교했다. trailing slash를 제거하고
실제 경로의 parameter segment를 template과 맞췄으며, 정적 asset, Swagger UI 내부
모듈, Socket.IO transport, generic middleware route와 ffuf candidate는 집계에서
제외했다.

| 대상 | 평가 기준 GET route | 수집 route | 누락 route | 수집률 |
| --- | ---: | ---: | ---: | ---: |
| Juice Shop | 71 | 9 | 62 | 12.7% |
| VulnBank | 47 | 11 | 36 | 23.4% |
| 합계 | 118 | 20 | 98 | 16.9% |

합계는 `20 / 118 × 100`으로 계산했다. 위의 `endpoints` 25개와 166개에는 정적
파일과 평가 기준 밖의 경로도 포함되므로 수집률의 분자로 사용하지 않았다.

Juice Shop의 기준 route 적중은 Phase B의 7개에 `GET /rest/user/whoami`와
`GET /rest/basket/:id`가 추가된 9개다. 후자는 실제 관측 경로
`GET /rest/basket/NaN`을 Phase B의 parameter-template 일치 규칙에 따라 센 것이다.
따라서 이 적중은 유효한 basket ID를 확보했다는 뜻은 아니다. VulnBank의 적중
11개는 Phase B와 동일하다.

이 16.9%는 **비인증 application GET route 수집률**이며 취약점 finding 탐지율이나
recall이 아니다. 기준 목록과 전체 산정 범위는 [Phase B 기준 문서](../main-branch/phase_b/PHASE_B_ENDPOINT_BASELINE.md)를 따른다.

Handoff의 Recon.db SHA-256과 최종 파일 hash는 일치했다.

- Juice Shop: `0254be190f3bb75882a98757cee59e9c03b16d3fc4a3ec2341c734626a775a3b`
- VulnBank: `0bf911ccc3ba7683702a758592a64c8495560260d527c777906497e8a034cece`

## Attack, Chaining, Validation

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| Attack task completed / skipped | 4 / 4 | 6 / 4 |
| attempts | 7 | 7 |
| confirmed attack attempts | 1 | 2 |
| findings | 1 | 2 |
| reproduction specs | 1 | 2 |
| finding chains | 0 | 0 |
| Validation cases | 1 | 2 |
| Validation decision | INCONCLUSIVE 1 | INCONCLUSIVE 2 |

모든 `attack_http_requests`는 terminal 상태였다. Juice Shop은 completed 7건,
VulnBank는 completed 7건과 failed 1건이었다. VulnBank failed request는
`GET /static/openapi.json` 응답 200을 받은 뒤 `RequestGuardError`로 terminal
처리됐다. `reserved`, `running`, `outcome_unknown` request는 남지 않았다.

Validation은 candidate preflight에서 끝나 실제 validation attempt/evidence/request가
생성되지 않았다. 사유는 다음과 같다.

- Juice Shop SQL injection: `http_runtime_contract_missing`
- VulnBank OpenAPI exposure: `http_runtime_contract_missing`
- VulnBank authentication bypass: `candidate_integrity`

산출물:

- `result/test-runs/current-branch-f54af46/phase-d/Runs/scan_64307e53306d4868af8a961a83ed2f82/`
- `result/test-runs/current-branch-f54af46/phase-d/AttackRuns/scan_64307e53306d4868af8a961a83ed2f82/Pipeline.db`
- `result/test-runs/current-branch-f54af46/phase-d/Runs/scan_f994442262fa4511ad9cf8b716e1159b/`
- `result/test-runs/current-branch-f54af46/phase-d/AttackRuns/scan_f994442262fa4511ad9cf8b716e1159b/Pipeline.db`

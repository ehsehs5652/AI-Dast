# Phase E — 판정 및 Report

## 판정

**PARTIAL — ground-truth 대조 완료, Report 생성 차단**

Attack finding과 연결된 attempt, request, reproduction spec을 고정된 로컬 fixture의
ground truth와 대조했다. Validation case 세 건은 모두 `INCONCLUSIVE`였고 Report
gate는 세 초안 생성을 모두 fail-closed로 거부했다.

## Finding 판정

| 대상 | Finding | Attack evidence | Phase E 판정 |
| --- | --- | --- | --- |
| Juice Shop | unauthenticated product-search SQL injection | crafted request 200과 별도 negative control 2건, request-bound reproduction spec | TP |
| VulnBank | login SQL injection authentication bypass | invalid control 401, crafted request 200, administrator authentication 신호와 reproduction spec | TP |
| VulnBank | unauthenticated OpenAPI specification exposure | `/static/openapi.json` 200과 reproduction spec은 존재하지만 독립적인 보안 영향은 미입증 | UNSUPPORTED |

위 TP는 고정 fixture의 ground truth와 Attack evidence를 사람이 대조한 판정이다.
Shared Validation에서 `CONFIRMED`됐다는 뜻은 아니다. Validation decision은 모두
`INCONCLUSIVE`이며 precision/recall의 확정 수치에는 포함하지 않는다.

## Report gate

HackerOne 형식의 로컬 초안 생성을 각 case에 대해 실행했다.

| Case | Decision | Report 결과 |
| --- | --- | --- |
| `vcase_5027fe014cd44475994bb3756da234d2` | INCONCLUSIVE | exit 1, `report requires a current completed CONFIRMED Validation case` |
| `vcase_cd9bd36ef2a94db39db8cf80833a989d` | INCONCLUSIVE | exit 1, 동일한 gate로 거부 |
| `vcase_daf7a9c9b997427ca162d9f8492e6106` | INCONCLUSIVE | exit 1, 동일한 gate로 거부 |

`result/test-runs/current-branch-f54af46/phase-e/reports/` 아래에 Report 파일은
생성되지 않았다. 외부 플랫폼 제출도 수행하지 않았다.

## 후속 blocker

1. request-bound reproduction spec에 Validation HTTP runtime contract를 일관되게
   포함해야 한다.
2. VulnBank 인증 우회 reproduction candidate의 policy/request binding 무결성 불일치를
   해소해야 한다.
3. 위 수정 후 같은 case를 새 scan에서 다시 Validation하고 `CONFIRMED` case에만
   Report 생성을 재시도해야 한다.

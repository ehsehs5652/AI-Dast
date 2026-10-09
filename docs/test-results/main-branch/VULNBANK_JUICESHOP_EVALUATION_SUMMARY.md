# VulnBank·OWASP Juice Shop 통합 평가 결과

## 종합 판정

2026-09-17~18 KST에 두 로컬 대상을 대상으로 사전 점검부터 결과 보고서 생성까지 평가했다. Phase A~E의 최종 실행은 모두 통과했으며, 전체 Recon → Attack → Chaining → Validation → Report 흐름이 정상적으로 완료됐다.

| 단계 | 목적 | 핵심 결과 | 최종 상태 |
| --- | --- | --- | --- |
| Phase A | 환경·도구·Scope·Policy 사전 검증 | 두 대상의 가용성, 도구 준비 상태, loopback/port/method 정책 경계를 확인했다. | PASS |
| Phase B | 비인증 Recon과 endpoint 수집 경로 점검 | 두 대상의 Recon과 태깅이 완료됐다. application GET route 기준 수집률은 합계 15.3%였다. | PASS |
| Phase C | 인증 세션 전달과 다중 identity 확인 | Juice Shop primary 및 VulnBank primary/secondary 세션으로 인증 Surface를 수집했고 비밀값 비노출을 확인했다. | PASS |
| Phase D | Recon부터 Validation까지 통합 실행 | 두 대상 모두 네 stage가 완료됐고 finding과 Validation 결과가 저장됐다. | PASS |
| Phase E | Ground truth 판정과 Report 생성 | TP 1건, UNSUPPORTED 1건으로 판정했다. Report 결함 수정 후 로컬 초안 생성과 무결성 검증을 완료했다. | PASS |

## 단계별 핵심 결과

### Phase A — 사전 점검

- Juice Shop, VulnBank 및 VulnBank DB의 실행 상태와 HTTP·브라우저 접근을 확인했다.
- Playwright, Katana, ffuf, mitmproxy 등 평가 도구의 준비 상태를 확인했다.
- 대상별 승인 Scope와 TargetPolicy를 생성하고 `127.0.0.1`, 지정 port, 허용 method만 사용할 수 있도록 경계를 고정했다.
- active POST 정책 재검증 시 승인 근거가 누락되던 문제를 수정하고 회귀 테스트 24개를 통과했다.

### Phase B — 비인증 Recon

- 최종 Recon에서 Juice Shop 23개, VulnBank 166개의 unique endpoint를 수집했으며 모든 관측 태깅과 핵심 산출물 생성을 완료했다.
- 고정 소스의 `method + path pattern`을 기준으로 전체 runtime route는 Juice Shop 144개, VulnBank 83개였다.
- Phase B 정책에 맞춘 application GET route 수집률은 다음과 같다.

| 대상 | 기준 route | 수집 route | 수집률 |
| --- | ---: | ---: | ---: |
| Juice Shop | 71 | 7 | 9.9% |
| VulnBank | 47 | 11 | 23.4% |
| 합계 | 118 | 18 | 15.3% |

- ZAP은 정상 설치·실행됐으나 VulnBank OpenAPI 문서의 schema 오류로 import에 실패했다. 이는 도구 설치 문제가 아닌 대상 fixture의 제한이다.

### Phase C — 인증 흐름

- Juice Shop primary 세션에서 인증 셸과 `GET /rest/user/whoami`를 수집했다.
- VulnBank primary와 secondary 세션에서 대시보드 및 인증 API를 각각 수집했으며, 서로 다른 사용자 identity임을 확인했다.
- 최종 네 실행의 Recon pipeline이 모두 완료됐다.
- 세션 원본을 제외한 DB, Surface, 로그와 결과 문서에서 평문 cookie·token 노출은 발견되지 않았다.

### Phase D — 통합 Pipeline

- 최종 scan에서 두 대상 모두 Recon, Attack, Chaining, Validation이 `completed`로 종료됐다.
- 미종결 Attack·Validation 요청은 없었고 Recon handoff hash도 일치했다.
- Chaining은 검토할 근거가 부족해 두 대상 모두 입증된 chain 없이 종료됐다.

| 대상 | Attack finding | Validation 결과 | 검증된 영향 |
| --- | --- | --- | --- |
| Juice Shop | 비인증 product search SQL injection | `CONFIRMED`, LOW | catalog query 결과 통제 및 catalog data 노출 |
| VulnBank | 공개 OpenAPI 명세 노출 | `INCONCLUSIVE` | 실제 보안 영향 미입증 |

- 중간에 발생한 Playwright browser 누락, tagging timeout, Helper Broker 경로 binding 문제를 해결한 뒤 최종 실행을 완료했다.

### Phase E — 판정 및 Report

- Juice Shop SQL injection은 고정 소스와 독립 재현 결과가 일치해 `TP`로 판정했다.
- VulnBank OpenAPI 노출은 관측 자체는 사실이나 민감정보 접근이나 권한 우회가 입증되지 않아 `UNSUPPORTED`로 판정했다.
- 최초 Report 생성은 Attack evidence와 Validation evidence namespace를 혼동해 차단됐다.
- namespace를 분리한 뒤 전체 테스트 `581 passed, 1 skipped`를 통과했고, Juice Shop Report를 `drafted`, `stale=false` 상태로 생성했다.
- Report는 Validation이 확인한 LOW 영향만 기술하며 외부 플랫폼에는 제출하지 않았다.

## 최종 지표와 한계

| 항목 | 결과 |
| --- | ---: |
| 전체 finding | 2 |
| TP | 1 |
| FP | 0 |
| UNSUPPORTED | 1 |
| duplicate | 0 |
| 판정 가능 finding precision | 100% (`1 / 1`) |

- precision은 판정 가능한 finding 1건만을 대상으로 하므로 제품 전체 성능으로 일반화할 수 없다.
- 버전별 전체 `ELIGIBLE` ground truth가 실행 전에 동결되지 않아 FN, recall, F1은 측정하지 않았다.
- Phase B의 15.3%는 비인증 application GET route 수집률이며 취약점 탐지율이 아니다.
- 생성된 Report에는 원본 query payload의 정확한 값이 포함되지 않아 외부 제출 수준의 완전한 재현 절차에는 context 계약 개선이 필요하다.

## 근거 문서

- [Phase A 결과](phase_a/VULNBANK_JUICESHOP_PHASE_A.md)
- [Phase B 최초 결과](phase_b/1_VULNBANK_JUICESHOP_PHASE_B.md)
- [Phase B 재실행 결과](phase_b/2_VULN_BANK_JUICESHOP_PHASE_B.md)
- [Phase B endpoint 기준](phase_b/PHASE_B_ENDPOINT_BASELINE.md)
- [Phase C 결과](phase_c/1_VULNBANK_JUICESHOP_PHASE_C.md)
- [Phase D 결과](phase_d/1_VULNBANK_JUICESHOP_PHASE_D.md)
- [Phase E 판정](phase_e/1_VULNBANK_JUICESHOP_PHASE_E.md)
- [Phase E Report 재실행](phase_e/2_VULNBANK_JUICESHOP_PHASE_E_REPORT_RETRY.md)

# Phase B — Recon-only shakedown

## 판정

**PASS — attempt 3 채택**

두 대상의 최종 anonymous Recon scan과 Recon stage가 모두 `completed`였고,
deferred tagging 실패는 0건이었다.

## Attempt 이력

| Attempt | Juice Shop | VulnBank | 처리 |
| --- | --- | --- | --- |
| 1 | `scan_d2724ce7a2c144748e902693cf30e9b8`, failed | `scan_40288876d2474f84beabacbba9631b6d`, failed | Playwright Chromium v1234 부재를 확인했다. |
| 2 | `scan_9f81d8cbb77f4e8d8f722b53668de21b`, interrupted | `scan_20591221f6c7407e9509885383bbc177`, interrupted | non-TTY 선택적 로그인 대기 중 상태 확인을 위해 operator interrupt했다. 결과로 채택하지 않았다. |
| 3 | `scan_8e172b07dc584c02ba771652d9b50c6e`, completed | `scan_57fdcbce22974b5ea9e8e96468c25942`, completed | TTY에서 로그인 입력 없이 anonymous session으로 진행한 최종 결과다. |

앞선 attempt의 DB와 로그는 덮어쓰지 않았다.

## 최종 결과

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| Recon 시간 | 1,234.0초 | 2,360.8초 |
| endpoints | 23 | 166 |
| endpoint observations | 168 | 328 |
| endpoint annotations | 205 | 436 |
| HTTP transactions | 355 | 476 |
| tagging 처리 | 168 | 328 |
| tagging 실패 | 0 | 0 |

## Endpoint 기준 목록 대비 탐지율

기존 Phase B와 동일한 고정 기준 및 정규화 규칙을 이번 attempt-3 `Recon.db`에
적용했다.

- Juice Shop 20.2.0의 source-declared application GET route 71개
- VulnBank commit `5e5ea5425fcf309373a0655dd111ecfb45037cbf`의
  source-declared application GET route 47개
- endpoint 단위는 `HTTP method + 정규화된 path template`
- trailing slash를 제거하고 Flask converter와 concrete parameter segment를
  `:parameter` template에 맞춰 비교
- 정적 asset, Swagger UI 내부 모듈, Socket.IO transport, generic middleware route와
  ffuf candidate는 분모와 분자에서 제외

| 대상 | 평가 기준 GET route | 탐지 route | 누락 route | 탐지율 |
| --- | ---: | ---: | ---: | ---: |
| Juice Shop | 71 | 7 | 64 | 9.9% |
| VulnBank | 47 | 11 | 36 | 23.4% |
| 합계 | 118 | 18 | 100 | 15.3% |

합계는 대상별 비율의 단순 평균이 아니라 `18 / 118 × 100`으로 계산했다.

Juice Shop에서는 `/`, `/api/Challenges`, `/api/Quantitys`, 세 개의 공개 admin/language
metadata route와 `/rest/products/search`가 기준 목록에 적중했다. VulnBank에서는 `/`,
`/blog`, `/careers`, `/compliance`, `/forgot-password`, `/login`, 두 merchant 인증 route,
`/privacy`, `/register`, `/terms`가 적중했다.

118개 기준 route는 기존 main-branch Phase B에서 확정한 고정 inventory를 재사용했다.
이번 DB의 기준 route 적중 집합은 기존 재실행과 동일했다.

이 15.3%는 **비인증 application GET route 수집률**이다. 취약점 finding의 탐지율이나
recall을 뜻하지 않는다. 인증 뒤에만 노출되는 route와 실제 parameter 값을 알아야 하는
route는 anonymous Recon에서 발견하기 어렵고, VulnBank OpenAPI import 실패로 명세 기반
route 보강도 수행되지 않았다.

Juice Shop의 첫 ffuf root는 180초 timeout 경고가 있었지만 이후 root와 Recon
stage는 완료됐다. VulnBank의 `/static/openapi.json`은 발견됐으나 대상 fixture의
`requestBody.schema.required` 형식 오류 때문에 ZAP OpenAPI import가 실패했다.
이 오류도 보조 도구 경고로 격리됐고 Recon stage는 완료됐다.

최종 산출물:

- `result/test-runs/current-branch-f54af46/phase-b/attempt-3/juice-shop/`
- `result/test-runs/current-branch-f54af46/phase-b/attempt-3/vuln-bank/`
- `result/logs/scan_8e172b07dc584c02ba771652d9b50c6e/recon.jsonl`
- `result/logs/scan_57fdcbce22974b5ea9e8e96468c25942/recon.jsonl`

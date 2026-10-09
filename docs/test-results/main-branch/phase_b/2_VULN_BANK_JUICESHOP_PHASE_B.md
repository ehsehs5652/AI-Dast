# 2차 VulnBank·OWASP Juice Shop Phase B 재실행 결과

## 판정

2026-09-17 KST에 다음 조치를 적용해 Phase B를 다시 실행했다.

- deferred tagging batch 크기를 CLI의 `--tag-batch-size 50`으로 제한했다.
- 평가 wordlist를 `--ffuf-wordlist resources/wordlists/common.txt`로 연결했다.
- 설치된 ZAP 2.17.0을 VulnBank OpenAPI 보조 탐색에 사용했다.
- Playwright runtime 종료가 route callback을 무기한 기다리지 않도록 cleanup 경로를 수정했다.

두 대상 모두 scan과 Recon stage가 `completed`로 끝났고, 모든 관측 태깅과 세 가지 핵심 산출물 생성을 완료했다. 따라서 **Phase B의 실행 안정성 및 정책 경계 shakedown은 통과**로 판정한다.
endpoint 기준 목록은 이후 고정 소스의 GET application route로 확정해 아래에서 수집률을 계산했다. VulnBank의 ZAP OpenAPI 보조 탐색은 설치 문제가 아니라 대상의 `/static/openapi.json` 문법 오류로 결과를 만들지 못했으며, 이는 Phase B 통과와 분리된 대상 fixture 제한사항으로 남긴다.

## 실행 결과

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| scan ID | `scan_67d082c0a8ab43e8a31ed858ac9e79c6` | `scan_75cee012b9774cdbb2427d7ace3dad0a` |
| scan/stage 상태 | completed / completed | completed / completed |
| 실행 시간 | 18분 54초 | 37분 29초 |
| unique endpoints | 23 | 166 |
| endpoint observations | 155 | 328 |
| HTTP transactions | 442 | 477 |
| proxy 허용 / 차단 | 442 / 29 | 477 / 347 |
| annotation runs | 4 completed | 7 completed |
| 미태깅 observations | 0 | 0 |
| `Surface.json` | 생성 (184 KiB) | 생성 (220 KiB) |
| `ReconReview.json` | 생성 | 생성 |

VulnBank는 ffuf에서 23개 candidate endpoint가 추가되어 최종 endpoint 수가 최초 실행의 143개에서 166개로 늘었다. Juice Shop에서는 wordlist가 네 root에 실행됐으나 새 endpoint는 나오지 않았다.

## endpoint 기준 목록 대비 수집률

기준 목록은 실행 결과에서 역산하지 않고 다음 고정 소스에서 독립적으로 산출했다.

- Juice Shop 20.2.0, image digest `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`
- VulnBank commit `5e5ea5425fcf309373a0655dd111ecfb45037cbf`

전체 endpoint inventory의 단위는 `HTTP method + runtime route path pattern`으로 고정한다. framework router에 명시적으로 등록된 유한 pattern은 Juice Shop 144개, VulnBank 83개다. 이는 전체 표면 크기이며, Phase B에서 금지된 POST/PUT/PATCH/DELETE까지 포함하므로 Phase B 수집률의 분모로 직접 사용하지 않는다.

Phase B의 허용 method는 GET/HEAD/OPTIONS지만, HEAD는 GET에서 자동 파생되고 OPTIONS는 global/wildcard 처리가 포함되어 별도 business resource 수로 보지 않았다. 따라서 소스에 선언된 GET application route를 분모로 사용했다. endpoint 단위는 `HTTP method + 정규화된 path template`이며 trailing slash를 제거하고 Flask의 `<int:id>`와 Express의 `:id`를 같은 template 형식으로 정규화했다.

| 대상 | 평가 기준 application GET route | 수집 route | 수집률 |
| --- | ---: | ---: | ---: |
| Juice Shop | 71 | 7 | 9.9% |
| VulnBank | 47 | 11 | 23.4% |
| 합계 | 118 | 18 | 15.3% |

이 비율은 source-declared application route coverage다. 서버가 응답할 수 있는 모든 URL의 절대 개수를 뜻하지 않는다. 정적 asset, Swagger UI 내부 모듈, Socket.IO transport, generic middleware route와 ffuf 후보는 분모와 분자에서 제외했다. 인증 필요 route와 path parameter route는 실제 애플리케이션 공격 표면이므로 분모에 포함했지만, 이번 비인증 Phase B에서는 대부분 수집되지 않았다.

평가 기준 목록과 hit/miss는 `docs/test-results/phase_b/PHASE_B_ENDPOINT_BASELINE.md`에 기록했다.

## ZAP 제한사항

ZAP 자체는 실행되었지만 VulnBank OpenAPI 문서의 다음 schema 오류로 Automation Framework의 OpenAPI import가 실패했다.

```text
paths.'/transfer'(post).requestBody.content.'application/json'.schema.required is not of type array
```

Recon 전체는 이 선택적 보조 탐색 실패를 격리하고 정상 완료했다.

## 산출물

| 대상 | DB / Surface / Review | 진단 로그 |
| --- | --- | --- |
| Juice Shop | `result/test-runs/phase-b-rerun/attempt-2/juice-shop/` | `result/logs/scan_67d082c0a8ab43e8a31ed858ac9e79c6/recon.jsonl` |
| VulnBank | `result/test-runs/phase-b-rerun/attempt-2/vuln-bank/` | `result/logs/scan_75cee012b9774cdbb2427d7ace3dad0a/recon.jsonl` |

## Phase B 체크리스트

- [x] 두 대상의 scan 및 Recon stage가 완료됐다.
- [x] 모든 관측 태깅을 완료했다.
- [x] `Recon.db`, `Surface.json`, `ReconReview.json`을 생성했다.
- [x] ffuf에 평가 wordlist를 연결했다.
- [x] ZAP 설치와 실제 호출을 확인했다.
- [x] 정책 프록시의 허용·차단 기록을 확인했다.
- [x] Phase B 실행 안정성 및 정책 경계 shakedown을 통과했다.
- [x] endpoint 기준 목록 대비 수집률을 계산했다.

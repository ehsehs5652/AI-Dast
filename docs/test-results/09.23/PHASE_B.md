# Phase B — 익명 Recon-only shakedown (2026-09-23 KST)

## 실행 기준

Phase A에서 검증한 별도 승인 Scope와 정책으로 두 대상을 실행했다. 공통 상한은 0.5 RPS, 요청 500, depth 2, timeout 15초이며 생성 정책의 concurrency는 1이었다. `--login-mode none`, `--execute`, `--tag-after`, `--tag-batch-size 50`, `resources/wordlists/common.txt`를 사용했다. 산출물은 대상별 `result/test-runs/09.23/phase-b/` 아래에 분리했다.

## 선행 CLI 회귀

첫 Juice Shop 실행은 대상 요청 이전에 `AttributeError: Namespace has no attribute run_root`로 종료됐다. `recon` 명령에는 `run_root`가 없지만 공통 실행 함수가 `run` 전용 경로를 참조한 것이 원인이었다. 해당 오류를 재현하는 회귀 테스트를 먼저 실패시킨 뒤, 통합 `run` 경로에서만 두 출력 경로를 계산하도록 수정했다. 수정 후 `ReconCliTests` **13 passed**, `test_recon_workflow.py`와 `test_recon_policy.py` 합계 **69 passed, 14 subtests passed**였다. 아래 scan은 이 수정 후 시작했다.

## VulnBank — 안전 경계 위반으로 중단

Scan ID: `scan_38c731112b1e4125a315525804846cca`.

프록시 캡처를 host, 차단 여부 및 상태 코드로 집계한 결과, 범위 밖 `fonts.googleapis.com` **11건**, `fonts.gstatic.com` **23건**이 `policy_blocked=false`, HTTP 200이었다. 다른 외부 요청은 차단됐지만 이 **34건의 외부 요청 허용**은 평가 계획의 외부 통신 금지 및 중단 조건에 해당한다. 따라서 `SIGINT`로 실행을 중단했으며 프로세스 exit 130, DB의 scan과 Recon stage는 모두 `failed`였다. 종료 시 프록시 집계는 허용 159건, 차단 72건이었다.

원인 조사에서 브라우저 `passive` 지원 모드가 대상 host와 무관한 HTTPS GET을 허용하는 경로를 확인했다(`src/aidast/recon/tools/mitm_addon.py`의 `_authorized_browser_support`). VulnBank의 고정 소스 CSS가 Google Fonts를 요청한다. 이 안전 경계가 해결되기 전에는 VulnBank Recon 재실행이나 통합 pipeline을 진행하지 않는다.

중단 시 `Recon.db`에는 endpoint 143개, endpoint observation 295개, HTTP transaction 125개가 있었으나 최종 Surface 및 ReconReview는 생성되지 않았다. 이 부분 수집값을 수집률 분자로 사용하지 않는다.

## Juice Shop — 태깅 실패로 중단

Scan ID: `scan_a81aa7ba2eb54c37bfb81a0c97465f7a`.

Endpoint Discovery는 종료됐다. 최종 병합 출력은 unique endpoint 29개였고 DB에는 endpoint 15개, endpoint observation 225개, HTTP transaction 393개가 저장됐다. 이 차이는 최종 병합 후보와 저장·정규화된 endpoint의 집계 단위가 다르므로 동일 지표로 비교하지 않는다. 저장된 GET endpoint 중 고정 [기준 목록](../main-branch/phase_b/PHASE_B_ENDPOINT_BASELINE.md)과 일치한 항목은 71개 중 7개(9.9%)였다. 이는 **미완료 실행의 관측값**이며 Phase B 완료 수집률은 아니다.

프록시가 관측한 외부 host 요청은 `accounts.google.com` 3건, `content-autofill.googleapis.com` 1건, `burpsuite` 1건이었고 모두 정책 차단 HTTP 403이었다. Endpoint Discovery 종료 출력에는 허용 요청 적재 393건, 정책 차단 102건으로 표시됐다. 요청 상한 500을 넘지 않았다.

`--tag-after`의 첫 배치는 50건 성공했으나 두 번째 배치 50건이 `MainAgentError`로 실패했다. 태깅 함수는 실패 건수를 누적해 Recon을 완료할 수 없으므로 추가 모델 호출을 막기 위해 실행을 중단했다(exit 130). DB의 scan과 Recon stage는 `failed`, annotation run은 `completed` 1개, `failed` 1개, 중단 당시 `running` 1개다. 최종 `Surface.json`과 `ReconReview.json`은 생성되지 않았다.

두 번째 annotation run의 시각은 `12:23:28.159762Z`부터 `12:28:28.226423Z`까지로 **300.07초**다. `CodexMainAgent`의 기본 timeout은 300초이고, timeout 예외가 `MainAgentError`로 변환된다. DB에는 오류 클래스만 저장되므로 세부 예외 메시지는 남지 않았지만, 경과 시간은 timeout과 일치한다.

## 이전 `recon-minseok-validate` PASS와 비교

이전 commit `f54af467909b751d2424330a38f1ff819b670e89`의 브라우저 `passive` 분류 및 mitmproxy 허용 조건을 현재 코드와 대조했다. **외부 HTTPS GET 지원 경로는 당시에도 동일했다.** 따라서 이번 VulnBank 결과를 새 코드만의 회귀로 단정할 수 없다. 이전 [Phase B 결과](../recon-minseok-validate-branch/PHASE_B.md)는 Recon stage 완료와 태깅 실패 0을 기록했지만, 외부 font 요청의 프록시 원본 판정은 기록하지 않았다. 당시에도 실제 외부 응답이 있었는지는 남은 산출물만으로 확인되지 않는다.

Juice Shop은 이전 실행에서 observation 168개에 대한 annotation run 4개가 모두 약 108~126초에 완료됐다. 이번에는 observation 225개가 저장됐고 두 번째 50건 배치가 300초 상한에 도달했다. 현재 annotator는 이전보다 URL parameter metadata를 payload에 추가한다. 데이터량·입력 내용 또는 Codex CLI 버전(이전 0.154.0, 현재 0.155.1)의 영향은 이 한 번의 실패만으로 분리할 수 없다.

## 1차 실행 판정과 후속 게이트

**FAIL.** 두 대상 모두 Recon stage가 `failed`로 끝났다. 계획의 “Recon에서 실패가 발생하면 통합 실행으로 넘어가지 않는다”는 조건에 따라 이 1차 결과 세트에서는 Phase D 통합 pipeline과 Phase E/F를 실행하지 않았다. 아래에는 수정 후 새 scan에서 다시 실행한 결과를 별도로 기록한다.

## 실패 원인 보강 및 수정

- 이전 `recon-minseok-validate`의 태깅 배치도 **50건**이었다. 당시 50건 입력은 약 7.9~26.1 KiB였고 이번 첫 실행은 약 16.2~37.3 KiB였다. 첫 Juice Shop 실패 배치는 300.07초로 기본 Codex 300초 제한에 도달했다. 같은 기존 관측치의 미처리 175건을 **25건씩 7배치**로 별도 재처리한 결과 175건 성공, 실패 0건이었다. 각 배치는 약 2분 30초였다.
- VulnBank 외부 font 요청은 브라우저의 `passive` 지원 경로와 프록시 허용 경로 양쪽에서 발생했다. loopback host를 포함한 Scope에서는 두 경로 모두 범위 밖 passive 요청을 허용하지 않도록 수정했다. 양쪽 회귀 테스트를 실패 상태에서 시작해 수정 후 통과시켰다.
- VulnBank의 첫 25건 재실행에서는 일곱 번째 배치가 14초 후 `ValueError`로 실패했다. 300초 timeout과 다른 오류다. 태깅 코드가 모델 결과의 관측 ID 전체 일치 또는 허용 태그 조건을 검사하는 두 지점에서 `ValueError`를 던지며, DB에는 클래스만 저장돼 둘 중 어느 조건인지는 확인할 수 없다. 계약 오류가 발생하면 해당 배치만 절반씩 재분류하고 단일 관측치까지 실패하면 그대로 보고하도록 수정했다. 불완전한 모델 결과를 재현하는 테스트는 수정 전 실패, 수정 후 통과했다.
- 로컬 평가 계획의 태깅 설정을 **25건 배치, Codex 제한 600초**로 바꿨다. 수정 후 전체 Python 테스트는 **1046 passed, 6 skipped, 642 subtests passed**였다. 전체 테스트는 로컬 소켓 접근 권한과 `TMPDIR=/private/tmp`를 적용해 실행했다.

## 수정 후 새 Phase B scan

| 대상 | scan ID | Recon stage | observations | HTTP transactions | 태깅 | Surface / Review |
| --- | --- | --- | ---: | ---: | --- | --- |
| Juice Shop | `scan_e427fc7ccb614d24af3a014932b77e73` | `completed` | 232 | 391 | 10배치, 232건 성공·0건 실패 | 둘 다 생성 |
| VulnBank | `scan_13f614d057de40d0ac217a66fcd5de9b` | 진행 중 | 305 | 399 | 진행 중 | 진행 중 |

Juice Shop의 DB endpoint는 15개였고 고정 application GET 기준 71개 중 7개(9.9%)를 수집했다. 새 스캔의 모든 annotation run은 `completed`이고, scan도 `completed`다. HTTP transaction 391건은 전부 loopback host였다. 프록시 종료 집계는 허용 391건, 정책 차단 25건이며 요청 상한 500 이내다.

VulnBank의 새 스캔도 엔드포인트 수집을 마쳤다. DB endpoint는 61개이고 HTTP transaction 399건은 전부 loopback host였다. 프록시 종료 집계는 허용 399건, 정책 차단 424건이다. 차단 건에는 ffuf 예산 보류 후보가 포함되므로 허용 요청 상한 500을 넘은 것이 아니다. 태깅 완료 전에는 VulnBank의 최종 Phase B 판정을 내리지 않는다.

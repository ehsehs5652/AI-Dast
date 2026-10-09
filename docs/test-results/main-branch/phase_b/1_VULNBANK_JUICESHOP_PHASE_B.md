# 1차 VulnBank·OWASP Juice Shop Phase B 결과

## 판정

Phase B Recon-only shakedown을 2026-09-17 KST에 수행했다. 두 대상 모두 네트워크 Recon과 정책 프록시 제어는 동작했지만, `--tag-after` 태깅이 일부 또는 전체 실패해 scan과 Recon stage가 `failed`로 종료됐다.

수집된 원본 관측과 HTTP transaction은 대상별 `Recon.db`에 보존되었다.

## 실행 경계

두 대상 모두 실행 직전 승인 Scope 무결성 검증을 통과했다. 실제 적용된 정책은 다음과 같다.

| 항목 | Juice Shop | VulnBank |
| --- | --- | --- |
| canonical target | `http://127.0.0.1:3001/` | `http://127.0.0.1:5001/` |
| scheme/host/port | `http`, `127.0.0.1`, `3001` | `http`, `127.0.0.1`, `5001` |
| Recon methods | GET, HEAD, OPTIONS | GET, HEAD, OPTIONS |
| RPS | 0.5 | 0.5 |
| concurrency | 1 | 1 |
| timeout | 15초 | 15초 |
| max depth | 2 | 2 |
| max requests | 500 | 500 |
| form submission | false | false |
| GraphQL active probe | disabled | `/graphql`만 허용 |

CLI에서 concurrency 2를 요청했지만 Scope에서 생성한 정책이 더 보수적인 1을 적용했다. 진단 로그에 등장한 URL host는 두 scan 모두 `127.0.0.1`뿐이었다.

## 실행 결과

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| scan ID | `scan_6fa6b8b135fe4ce1b3dc740724b9d670` | `scan_abca9816cd2a49e198db52bf10d8f482` |
| scan/stage 상태 | failed / failed | failed / failed |
| assets / origins | 1 / 1 | 1 / 1 |
| unique endpoints | 23 | 143 |
| endpoint observations | 174 | 306 |
| endpoint 초과 반복 관측 | 151 | 163 |
| HTTP transactions | 120 | 105 |
| 실제 HTTP method | GET 120 | GET 105 |
| proxy 허용 / 차단 | 120 / 15 | 105 / 101 |
| 성공 태깅 | 0 | 106 |
| 실패 태깅 | 174 | 200 |
| `Surface.json` | 미생성 | 미생성 |
| `ReconReview.json` | 미생성 | 미생성 |

Juice Shop에서 `POST /socket.io/`가 endpoint metadata로 관측되었지만, 저장된 HTTP transaction 120건은 모두 GET이었다. 따라서 Recon이 정책 밖 POST를 실제 전송했다는 근거는 없다.

endpoint 기준 목록이 아직 확정·저장되지 않아 기준 목록 대비 수집률은 계산하지 않았다.

## 실패 원인과 기능 공백

### 1. 대용량 태깅 batch timeout

Juice Shop의 174건 batch는 정확히 300초 후 `MainAgentError`로 실패했다. VulnBank의 첫 200건 batch도 정확히 300초 후 같은 오류로 실패했지만, 나머지 106건 batch는 227초에 완료됐다.

이 결과는 기본 `tag-after` batch size 200이 현재 Codex structured-output 경로의 300초 제한에서 안정적이지 않음을 보여준다. 태깅 실패가 예외로 전파되어 offline review와 `Surface.json` export 전에 Recon 전체가 실패했다.

### 2. ffuf wordlist 미연결

두 실행 모두 정책에서 ffuf가 enabled였지만 CLI에 `--ffuf-wordlist`를 주지 않아 ffuf 단계가 건너뛰었다. 평가 계획의 예시 명령에도 해당 인자가 없으므로, 재실행 전 계획 명령에 프로젝트 wordlist를 명시해야 한다.

### 3. VulnBank OpenAPI 보조 탐색의 ZAP 의존성

VulnBank에서 `/static/openapi.json`을 확인했지만 `zaproxy`가 설치되지 않아 OpenAPI 2차 Discovery가 실패했다. ZAP은 현재 평가 계획의 실행 전 도구 의존성 목록에 없다.

### 4. Playwright cleanup 경고

VulnBank 브라우저 종료 과정에서 route callback의 `asyncio.exceptions.CancelledError`가 출력됐다. endpoint 저장과 proxy capture ingest는 이후 완료되어 직접적인 scan 실패 원인은 아니지만, 반복 실행 노이즈로 기록한다.

## 산출물

| 대상 | DB | 진단 로그 |
| --- | --- | --- |
| Juice Shop | `result/test-runs/phase-b/juice-shop/Recon.db` | `result/logs/scan_6fa6b8b135fe4ce1b3dc740724b9d670/recon.jsonl` |
| VulnBank | `result/test-runs/phase-b/vuln-bank/Recon.db` | `result/logs/scan_abca9816cd2a49e198db52bf10d8f482/recon.jsonl` |

## Phase B 체크리스트

- [x] 두 대상의 승인 Scope와 정책 경계를 재검증했다.
- [x] DNS/HTTP/origin/endpoint Recon task를 대상별로 실행했다.
- [x] `Recon.db`와 진단 로그를 대상별로 분리해 보존했다.
- [x] 진단 로그 URL host가 `127.0.0.1`로 제한됨을 확인했다.
- [x] proxy 허용·차단 건수를 확인했다.
- [ ] 모든 관측 태깅을 완료했다.
- [ ] `Surface.json`을 생성했다.
- [ ] `ReconReview.json`을 생성했다.
- [ ] endpoint 기준 목록 대비 수집률을 계산했다.
- [ ] Phase B를 통과했다.

## 다음 조치

Phase B를 재실행하기 전에 다음을 처리한다.

1. deferred tagging batch size를 작게 제한하거나 batch size와 제한시간을 CLI에서 조정 가능하게 한다.
2. 태깅 부분 실패 시 성공 batch를 보존하면서 재개할 수 있는지 검증한다.
3. 평가 명령에 `--ffuf-wordlist resources/wordlists/common.txt`를 명시한다.
4. ZAP을 필수 의존성으로 설치할지, ZAP 미설치 시 OpenAPI 보조 탐색을 선택 기능으로 기록할지 결정한다.
5. 대상별 endpoint 기준 목록을 고정한 뒤 수집률을 계산한다.

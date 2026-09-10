# Recon → Attack 통합 변경 기록

이 문서는 `AI-Dast-main`의 Recon 기능을 유지하면서 `Scope 수집 → Recon Agent → Attack Agent` 단계 계약을 통합하는 작업의 전후 차이를 누적 기록한다.

## 2026-09-08: 통합 기반 및 안전 경계

### HTTP 요청 경계

문제/이유: redirect가 Scope 밖으로 이동하거나 정책 없는 요청이 실행되면 버그바운티 허용 범위를 벗어날 수 있었다. 모든 실제 HTTP 이동을 한 경계에서 검사하도록 수정했다.

| 변경 전 | 변경 후 |
|---|---|
| `http_probe`가 표준 `urlopen` 동작에 의존해 redirect 목적지를 정책으로 다시 검사하지 않음 | `RequestBroker`가 최초 URL과 각 redirect의 scheme, host, port, path, method를 `TargetPolicy`로 재검증 |
| 정책이 없어도 HTTP 요청 가능 | 정책이 없으면 네트워크 전송 전에 fail-closed |
| origin이 바뀌는 redirect에도 민감 헤더 전달 가능 | cross-origin redirect에서 인증·쿠키 등 민감 헤더 제거 |
| 요청 수가 probe 경계에서 제한되지 않음 | 정책의 `max_requests`와 redirect 횟수 적용 |
| 모델이 승인되지 않은 추가 host나 POST 같은 변경 메서드를 정책에 넣을 여지가 있음 | canonical host 밖의 값과 state-changing method를 Python 검증에서 거부 |

영향 파일:

- `src/aidast/core/request_broker.py`
- `src/aidast/core/http_safety.py`
- `src/aidast/recon/tools/http_probe.py`
- `src/aidast/recon/executor.py`

### 프록시 캡처와 민감정보

문제/이유: 기존 캡처에는 로그인 토큰, 쿠키, 요청·응답 본문이 그대로 남을 수 있었다. 다음 Agent에는 필요한 증거만 넘기고 비밀정보는 남기지 않도록 기본값을 바꿨다.

| 변경 전 | 변경 후 |
|---|---|
| mitm 캡처가 요청·응답 body를 항상 기록 | `mitm_capture_bodies`가 명시적으로 참인 경우에만 body 기록 |
| Authorization, Cookie 등 헤더 원문 저장 | 캡처와 DB 적재 양쪽에서 민감 헤더 마스킹 |
| 정책 파일 오류나 필수 프록시 시작 실패가 조용히 넘어갈 수 있음 | 정책 강제 모드에서는 설정·실행 실패를 오류로 처리 |

영향 파일:

- `src/aidast/recon/policy.py`
- `src/aidast/recon/tools/mitm_addon.py`
- `src/aidast/recon/tools/mitm_proxy.py`

### 브라우저 상호작용

문제/이유: form 안의 타입 없는 버튼은 실제로 제출 버튼인데 일반 버튼처럼 클릭할 수 있었다. 의도치 않은 데이터 생성·변경을 막기 위해 명시적 허용 없이는 건드리지 않는다.

| 변경 전 | 변경 후 |
|---|---|
| `<form>` 내부에서 `type`이 생략된 `<button>`을 일반 버튼처럼 누를 수 있음 | HTML 기본 submit 동작으로 판단하고 명시적 허용이 없으면 클릭하지 않음 |

영향 파일:

- `src/aidast/recon/tools/playwright_driver.py`
- `src/aidast/recon/tools/endpoint_discovery.py`

### Recon Agent 계층

문제/이유: 기존 Recon은 정해진 도구 순서를 잘 실행하지만, 수집 결과를 보고 다음 조사 방향을 조정하는 계층이 없었다. 기존 기능은 유지하고 근거 기반 제안 계층만 위에 추가했다.

| 변경 전 | 변경 후 |
|---|---|
| 고정된 Recon task 실행과 결과 저장만 존재 | 기존 실행기를 유지한 채, 저장된 근거를 읽어 다음 Recon 제안을 구조화하는 `OfflineReconReview` 추가 |
| 에이전트 제안의 반복·타깃 확장에 대한 별도 한도 없음 | canonical Scope/TargetPolicy 검증, 중복 제거, iteration/task budget 적용 |
| 제안과 네트워크 실행이 분리되지 않음 | review 계층은 read-only이며 자동 네트워크 실행 경로를 갖지 않음 |

영향 파일:

- `src/aidast/recon/agent.py`
- `tests/test_recon_agent.py`

### 통합 DB 및 handoff 계약

문제/이유: Recon과 Attack이 서로 다른 테이블과 완료 상태를 기대해 그대로는 연결할 수 없었다. 하나의 DB schema와 검증 가능한 handoff 파일을 두 단계의 공용 계약으로 만들었다.

| 변경 전 | 변경 후 |
|---|---|
| Recon DB와 외부 Attack SQL이 서로 다른 테이블·상태를 기대 | 기존 Recon 테이블을 보존하는 additive schema v4에 단계·Attack evidence 테이블 통합 |
| Recon 결과 소비자가 파일 경로와 완료 여부를 관례로 추측 | SHA-256/크기/상대 경로를 담는 `HandoffManifest`로 명시적 전달 |
| 단계 및 task 상태 전이·감사 로그가 통일되지 않음 | `stage_runs`, `attack_tasks`, append-only `audit_events`와 검증된 상태 전이 사용 |
| 세션/자격증명 저장 경계가 불명확 | 실제 secret 대신 `env://`, `keyring://`, `vault://` 참조만 저장 |

영향 파일:

- `src/aidast/pipeline/schema.py`
- `src/aidast/pipeline/models.py`
- `src/aidast/pipeline/lifecycle.py`
- `src/aidast/recon/db.py`

### 검증 현황

- HTTP broker/프록시 신규 오프라인 테스트: 통과
- Recon Agent 신규 오프라인 테스트: 통과
- DB/handoff 계약 신규 오프라인 테스트: 통과
- Attack handoff consumer 신규 오프라인 테스트: 통과
- 전체 테스트: 최종 통합 기준 141개 통과. `git diff --check`도 통과.

### 단일 실행 CLI와 Attack handoff consumer

문제/이유: 기존에는 Recon 결과를 만든 뒤 어떤 DB와 파일을 Attack 쪽에 넘길지 사람이 맞춰야 했고, scan도 계속 `running`으로 남았다. `aidast run`이 완료 상태와 해시를 확정한 뒤 검증된 검토 큐까지 자동으로 준비하게 했다.

| 변경 전 | 변경 후 |
|---|---|
| Scope와 Recon 명령만 존재 | `aidast run`으로 Scope → Recon → handoff → Attack review 준비 연결 |
| Recon 성공 후에도 `scans.status='running'` | 성공 시 `completed`/종료 시각, 실패 시 `failed`/종료 시각 기록 |
| Recon 산출물 위치·내용을 다음 단계가 신뢰 | DB, Surface, Scope, Approval, Policy, ReconReview를 SHA-256으로 검증 |
| 외부 Attack 폴더가 별도 DB 형태를 가정 | 설치 패키지 안의 offline consumer가 공용 v4 schema를 read-only로 소비 |
| 능동 Attack 실행 여부가 모호 | 현재는 evidence-review plan만 지원하고 active/network 요청은 명시적으로 거부 |

영향 파일:

- `src/aidast/cli.py`
- `src/aidast/agents/main.py`
- `src/aidast/attack/evidence.py`
- `src/aidast/attack/runtime.py`
- `src/aidast/skills/attack/controller.md`
- `src/aidast/skills/attack/manifest.json`
- `pyproject.toml`
- `README.md`

## 2026-09-09: 동적 Attack Agent 병합 설계

문제/이유: 외부 `attack` 폴더는 실제 Agent 실행 코드가 아니라 Markdown playbook과 SQL 조각이라 그대로 복사해도 동작하지 않고, 현재 immutable handoff·credential·정책 경계와도 충돌했다. 실행 주체와 데이터 계약을 분리한 단계별 병합 설계를 추가했다.

| 변경 전 | 변경 후 |
|---|---|
| 외부 controller가 한 Codex 세션과 writable Recon DB를 가정 | 새 AI 세션과 DB 기반 재개, immutable Recon DB와 writable Attack DB 분리 |
| playbook이 shell/network 동작을 직접 지시 | disabled catalog + 검토된 fixed adapter + 공용 broker 구조 |
| Scope 승인을 Attack 승인으로 오해할 수 있음 | plan/policy/catalog/task/budget/identity에 묶인 별도 `RunAuthorization` 설계 |
| process별 요청 수 제한 | restart 후에도 유지되는 전역 budget·lease·receipt 설계 |

설계 문서:

- `docs/design/ATTACK_AGENT_MERGE_DESIGN.md`

## 2026-09-09: 제한형 동적 Attack Agent 구현

문제/이유: 외부 Attack 폴더는 문서와 SQL뿐이라 직접 실행할 Agent, 승인 경계, 재시작 가능한 저장소가 없었다. 먼저 안전하게 검증 가능한 응답 메타데이터 관찰 범위로 실행 코어를 만들었다.

| 변경 전 | 변경 후 |
|---|---|
| 59개 playbook의 포함 범위와 출처를 런타임에서 확인할 수 없음 | 59개 library 항목과 controller를 해시 inventory로 보존하고 모두 비활성 메타데이터로 등록 |
| Recon DB를 Attack이 직접 수정할 위험 | handoff와 파일 hash를 재검증한 뒤 별도 writable `Attack.db`를 만들고 원본 hash를 보존 |
| v4에는 plan revision, 승인, lease, model iteration 저장 계약이 없음 | opt-in schema v5와 run/scan 경계를 검증하는 저장 API 추가 |
| 승인 파일의 진위·만료·정확한 task binding을 강제할 곳이 없음 | 서명된 `RunAuthorization`과 정확한 `RequestIntent` digest를 매 요청 검증 |
| 요청 budget이 process 재시작이나 여러 worker에서 초기화될 수 있음 | SQLite 원장에 전송 전 reservation/receipt를 기록하고 request/byte/time/rate/concurrency를 공유 |
| API 후보 요청, ffuf, Playwright 일부 경로가 공용 정책을 우회할 수 있음 | API broker 공유, ffuf proxy 전달, Playwright route guard/WebSocket 차단과 proxy 필수화 적용 |
| browser session이 host/port만으로 구분됨 | run/identity/target hash로 session 파일을 분리하고 executor가 scan ID를 전달 |
| 모델 결과가 URL·명령·임의 task를 실행 입력으로 만들 수 있음 | 모델은 기존 ID만 고르고 Python validator가 forged/duplicate/과대 결과를 거부 |
| Attack 실행 주체가 없음 | 재시작·철회·예산을 확인하는 `AttackAgent`와 고정 HEAD/GET/OPTIONS 메타데이터 adapter 추가 |
| CLI는 legacy offline review 한 가지뿐 | legacy 호환을 유지하며 `plan/status/revoke` 추가; `approve/execute`는 신뢰 workflow 없으면 거부 |

영향 파일:

- `src/aidast/attack/agent.py`, `planner.py`, `adapters.py`, `authorization.py`, `catalog.py`, `store.py`
- `src/aidast/core/policy_service.py`, `request_broker.py`
- `src/aidast/pipeline/schema.py`
- `src/aidast/recon/tools/api_secondary_discovery.py`, `endpoint_discovery.py`, `playwright_driver.py`
- `src/aidast/recon/executor.py`, `src/aidast/cli.py`, `pyproject.toml`, `README.md`
- `src/aidast/skills/attack/catalog/index.json`, `docs/third-party/claude-bughunter/`

현재 제한/이유: 실제 bug bounty target에서의 능동 exploit adapter는 안전성과 프로그램별 허용 범위를 별도로 검토해야 한다. 그래서 기본 CLI는 plan까지만 제공하고, 검증 workflow가 없는 `approve/execute`와 외부 playbook 실행은 fail-closed 상태로 남겼다.

검증: 외부 네트워크를 쓰지 않는 전체 219개 테스트와 `git diff --check`가 통과했다. wheel을 직접 빌드해 59개 비활성 catalog resource가 설치 결과에서도 로드되는 것을 확인했다.

## 2026-09-09: Attack 전용 thin DB 재설계

문제/이유: Attack 상태를 저장하려고 Recon 전체 DB를 복제해 데이터와 용량이 중복됐다. Recon은 읽기 전용 원본으로 두고 Attack 데이터만 별도 DB에 저장하도록 단순화했다.

| 변경 전 | 변경 후 |
|---|---|
| Recon.db 전체를 복사한 뒤 schema v5 적용 | 빈 thin schema v6 `Attack.db`를 만들고 Attack 테이블만 생성 |
| Attack DB 안의 복제된 endpoint를 FK/trigger로 확인 | 별도 read-only Recon 연결에서 `endpoint → origin → asset → scan` 귀속을 Python API가 확인 |
| Attack DB만 열면 오래된 Recon 사본도 계속 사용 가능 | 생성·재개마다 Handoff, Recon hash, 완료 scan, WAL/journal/SHM 부재를 재검증 |
| 원본 Handoff와 DB의 절대 경로 저장 | Attack/review 위치 기준 상대 locator를 저장해 두 묶음을 함께 이동 가능 |
| 저장 plan digest에 환경별 절대 출력 경로 포함 | portable plan에는 상대 config/queue locator만 포함 |
| `aidast run`이 review queue까지만 준비 | Recon 완료 후 thin `Attack.db`와 revision 1 plan까지 자동 생성 |
| 복제형 DB와 새 형식을 같은 v5로 오인할 가능성 | thin 형식은 v6로 구분하고 기존 복제형 v5는 새 출력 디렉터리 사용을 안내하며 거부 |

영향 파일:

- `src/aidast/attack/store.py`, `runtime.py`
- `src/aidast/pipeline/schema.py`
- `src/aidast/cli.py`, `README.md`
- `tests/test_attack_store.py`, `test_attack_runtime.py`, `test_attack_cli.py`, `test_pipeline_cli.py`

검증: 외부 네트워크 없이 전체 229개 테스트와 `git diff --check`가 통과했다. Attack DB에 Recon inventory 테이블이나 기존 Recon attempt가 복제되지 않고, 원본 변경·누락·다른 scan endpoint·sidecar·구형 v5가 모두 거부되는 것을 확인했다.

## 2026-09-09: Validation Agent 추가

변경 전: Attack 후보의 7문항·PoC 검증 결과를 분리해서 기록하는 단계가 없었다. 변경 후: 프로젝트 Skill로 기존 증거를 검토하고 원본 hash와 Finding/증거 ID를 별도 `Validation.db`에 저장한다.

이유: Attack의 발견 상태와 검증 판단이 섞이거나 근거가 부족한 후보가 확정되는 문제를 막기 위해 추가했다.

| 변경 전 | 변경 후 |
|---|---|
| 검증 규칙과 결과 저장 계약 없음 | `aidast-validation` Skill + Python 7Q/PoC 검증 + append-only `Validation.db` |
| 모델 설명만으로 확정될 가능성 | 7개 답변과 실제 evidence/request hash 연결이 모두 맞아야 `confirmed` |
| Attack DB에 검증 결과를 함께 기록 | Recon/Attack은 읽기 전용으로 두고 Validation 이력만 별도 저장 |

## 2026-09-09: 3개 플랫폼 Report Agent 추가

변경 전: 검증된 finding을 플랫폼 양식으로 옮기는 단계가 없었다. 변경 후: `confirmed` Validation만 HackerOne·Intigriti·Bugcrowd용 Skill로 작성해 별도 `Report.db/JSON/MD`에 저장한다.

이유: 확인되지 않은 내용이나 존재하지 않는 증거가 보고서에 섞이지 않도록, 모든 사실을 검증된 evidence ID에 묶고 자동 제출 기능은 제외했다.

| 변경 전 | 변경 후 |
|---|---|
| 수동으로 플랫폼별 보고서 작성 | `aidast report run --platform hackerone\|intigriti\|bugcrowd` |
| 보고서가 원본 검증 결과와 느슨하게 연결 | Validation DB·decision·context hash와 evidence ID를 강제 검증 |
| 생성과 제출 경계가 불명확 | 로컬 초안만 생성하며 네트워크 제출 기능 없음 |

검증: 전체 295개 테스트, 두 Skill 구조 검증, `git diff --check`, wheel 패키지 내 Skill·3개 플랫폼 reference 포함 확인이 모두 통과했다.

## 2026-09-09: 팀 전달용 폴더 재구성

변경 전: 설계·변경 문서, wordlist, 배포 ZIP이 프로젝트 루트에 섞여 있었다. 변경 후: 각각 `docs/design`, `docs/changes`, `resources/wordlists`, `dist`로 분리했다.

이유: 소스·문서·공용 자원·배포물과 Scope/세션/DB 같은 로컬 실행 산출물을 팀원이 바로 구분할 수 있게 하기 위해서다.


## Scope 수치 우선 적용 및 기본 프로파일 제거

`run`과 `recon`의 기본 safe-recon 프로파일을 제거했다. 프로파일은 명시적으로
선택한 경우에만 추가 상한으로 적용한다. Scope 원문 근거가 있는 수치는 내부
기본값보다 커도 보존하며, 근거 없는 모델 수치 변경은 기존처럼 기본값으로
되돌린다. 명시되지 않은 항목의 기본값과 스키마 지원 범위는 유지한다.
Scope의 10 RPS가 정책 정규화와 기본 CLI 적용 후에도 보존되는 회귀 검증을 추가했다.


## 2026-09-10: 수동 로그인과 Recon Scope 전환

문제: 타깃 Scope 밖의 로그인/SSO 경로가 차단되었다. 로그인 중 Scope 예외만
적용하는 초기 수정 이후에도 프록시를 통한 Chromium 로그인에서는 Cloudflare
검증이 반복되고 일반 Chrome에서는 로그인되는 사례가 보고되었다. 원인이
프록시 하나로 확정된 것은 아니므로, 수동 로그인과 자동 수집의 연결 경로를 분리한다.

현재 동작: 전용 Chromium 로그인 창은 직접 연결하며 Playwright/CDP 클라이언트는
Enter 이후에만 연결한다. 로그인 중에는 route 및 관측 hook을 설치하지 않는다.
Enter → 타깃 쿠키/스토리지 저장 → 직접 연결 창 종료 → 프록시 및 Scope가 적용된
Chromium 실행 → 타깃 세션 복원 → 승인된 start URL 복귀 → 자동 탐색 순서로 진행한다.
로그인 취소, 세션 저장 또는 타깃 복귀 실패 시 자동 탐색을 시작하지 않는다.
재로그인도 같은 절차를 따른다. 수동 로그인 트래픽은 Recon 관측으로 수집하지 않는다.
이전 프록시 로그인 토큰/제어 파일은 제거했으며, 프록시는 Scope를 계속 적용한다.
기존 Scope 제한, 도구 실행 상한 및 Attack 흐름은 유지한다.

한계: 평소 Chrome과 같은 프로필이나 브라우저 실행 파일을 사용하는 것은 아니다.
Cloudflare 검증 통과 및 프록시 전환 후 세션 유지 여부는 실제 서비스에서 확인해야 한다.
사이트별 인증 검사 URL이 없으면 기존처럼 타깃 복귀·HTTP 상태·세션 저장을 확인하며,
서비스의 로그인 성공 여부를 범용적으로 확정하지 않는다.

검증: 직접 로그인 창의 proxy 미사용과 CDP 연결 지연, 로그인 후 창 교체 순서,
재로그인/취소/저장 실패/타깃 복귀 실패, 타깃 세션 필터 및 기존 Scope 검사를
로컬 테스트로 확인한다. 실제 Shopify 로그인은 이번 테스트에서 실행하지 않는다.

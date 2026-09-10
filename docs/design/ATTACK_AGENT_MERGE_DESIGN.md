# 동적 분석용 Attack Agent 병합 설계

작성일: 2026-09-09  
대상 소스: `C:\Users\yeonbug\Desktop\attack`  
대상 프로젝트: `AI-Dast-main`

## 1. 결론

`attack` 폴더는 실행 가능한 Agent가 아니라 controller 1개, 취약점별 Markdown skill 59개, SQLite CLI SQL 4개와 출처 자료로 구성된 **지식 리소스 묶음**이다. 따라서 폴더를 그대로 복사해도 Attack Agent는 동작하지 않는다.

병합은 다음 원칙으로 진행한다.

1. Recon의 해시 검증된 결과물은 읽기 전용 원본으로 유지한다.
2. Attack Agent는 새 AI 세션으로 시작하며 대화 기억 대신 DB 상태를 사용한다.
3. `attack`의 skill은 실행 권한이 없는 버전 고정 카탈로그로 가져온다.
4. 모델은 test family와 근거를 제안하고, Python coordinator만 승인된 adapter를 실행한다.
5. 실제 요청은 모두 하나의 정책·승인·예산 broker를 통과한다.
6. 시도, 사실, 후보 finding, 검토 결과를 별도 writable Attack DB에 기록한다.

```text
Approved Scope
      │
      ▼
Recon Agent ──► immutable Recon handoff
                         │ verify hashes/scope/policy
                         ▼
              create thin writable Attack.db
                         │
                         ▼
                  Attack Coordinator
              ┌──────────┼───────────┐
              ▼          ▼           ▼
         Planner     Approval     State Store
              │          │           ▲
              └────► Policy Broker ──┘
                         │
                         ▼
                 fixed test adapters
```

## 2. 왜 새 AI 세션으로 충분한가

Recon Agent의 대화 세션은 유지하지 않는다. `Recon.db`, `Surface.json`, `ReconReview.json`, `Scope.json`, `Approval.json`, `TargetPolicy.json`과 `Handoff.json`이 필요한 상태를 제공한다.

Attack Agent 역시 하나의 긴 Codex 대화를 필수로 만들지 않는다. 매 iteration마다 authoritative DB에서 다음 내용을 다시 구성해 구조화된 모델 호출을 수행한다.

- 현재 scan/run/task ID
- canonical target과 정책 digest
- endpoint, parameter, observation, annotation ID
- 완료·실패·보류된 이전 attempt
- 검증된 fact와 finding candidate
- 남은 요청·시간·byte 예산
- 허용된 test catalog ID와 버전

모델 세션이 끊겨도 DB에서 같은 상태를 재구성할 수 있어야 한다. 모델 응답의 재현성 대신 입력 hash, 모델 응답, 검증 결과를 저장해 결정 과정을 replay한다.

웹 로그인 세션은 별도 문제다. 인증 검사가 필요하면 secret 자체가 아니라 `credential_references`의 opaque reference만 전달하고, broker가 전송 직전에 해석한다. principal, tenant, origin, role, 만료시간이 다른 세션은 분리한다.

## 3. 병합 대상 분류

| `attack` 소스 | 처리 | 프로젝트 내 위치 |
|---|---|---|
| `vendor/LICENSE`, `CREDITS.md`, `SOURCE.json` | 원문 출처와 라이선스 보존 | `docs/third-party/claude-bughunter/` |
| `library/hunt-*/SKILL.md` | 읽기 전용 참고 카탈로그로 vendoring | `src/aidast/skills/attack/catalog/<skill>/SKILL.md` |
| `library/hunt-dispatch/SKILL.md` | signal→skill 규칙만 typed dispatcher로 재구현 | `src/aidast/attack/catalog.py` |
| `library/chain/SKILL.md` | finding 간 후속 후보 추천 규칙으로만 사용 | `src/aidast/attack/chains.py` |
| `controller/SKILL.md` | 요구사항 참고용으로 보존하되 실행 controller로 사용하지 않음 | `docs/third-party/claude-bughunter/controller-reference.md` |
| `controller/scripts/*.sql` | column 계약 참고; Python repository API로 재작성 | `src/aidast/attack/store.py` |
| `vendor/commands/*.md` | 출처 참고 자료로만 보존 | `docs/third-party/claude-bughunter/commands/` |
| `__pycache__`, docstring뿐인 package marker | 병합하지 않음 | 없음 |

원본 playbook Markdown을 모델에게 한꺼번에 넣지 않는다. 먼저 각 skill에서 아래 manifest만 추출하고 사람이 검토한 뒤 활성화한다.

```json
{
  "catalog_id": "hunt-example",
  "version": "source-commit+local-review",
  "signals": ["typed-signal-id"],
  "required_evidence": ["endpoint", "parameter"],
  "required_identities": ["anonymous"],
  "activity_class": "bounded-observation",
  "adapter_id": "reviewed-adapter-id",
  "default_budget": {"requests": 2, "seconds": 20},
  "enabled": false
}
```

`enabled=false`가 기본이다. reviewed adapter가 없는 skill은 설명·수동 검토 자료로는 사용해도 자동 실행하지 않는다.

## 4. Attack Agent 구성

### 4.1 `AttackCoordinator`

파일: `src/aidast/attack/agent.py`

역할:

- Recon handoff와 실행 승인 검증
- writable `Attack.db` 생성 또는 resume
- dispatcher로 후보 test family 생성
- task 상태 전이와 lease 관리
- planner 호출, 결과 검증, adapter dispatch
- attempt/fact/finding candidate 저장
- 예산 소진, 취소, 승인 만료 시 즉시 중단

상태는 다음과 같이 관리한다.

```text
created → verifying_handoff → planning → awaiting_approval
        → ready → running → completed

blocked   : Scope/policy/handoff/catalog 불일치
paused    : 승인 만료·취소, 세션 만료, 예산 소진, 결과 불확실
failed    : DB commit, broker 또는 필수 adapter 실패
cancelled : 운영자가 실행을 거부하거나 중단
```

### 4.2 `AttackPlanner`

파일: `src/aidast/attack/planner.py`

모델은 임의 shell 명령이나 payload를 반환하지 않는다. 다음 구조만 반환한다.

- 기존 endpoint/task/catalog ID
- 선택 이유와 근거 observation ID
- 필요한 identity reference
- 예상되는 증거와 종료 조건
- catalog가 허용한 parameter slot

Python은 ID가 현재 scan에 속하는지, catalog와 prerequisite가 맞는지, 중복·예산 여부를 다시 검증한다. endpoint 경로나 캡처 문자열은 신뢰할 수 없는 데이터로 표시하며 instruction으로 취급하지 않는다.

### 4.3 `AttackDispatcher`

파일: `src/aidast/attack/catalog.py`

Recon annotation과 실제 저장 증거를 이용해 우선순위를 계산한다.

1. 명시적 protocol/framework signal
2. 인증/tenant/object identifier가 있는 endpoint
3. 동일 기능의 method/version 차이
4. 일반적인 낮은 위험의 관찰 검사

annotation confidence만으로 실행하지 않는다. 필요한 parameter, session, response baseline이 없으면 `blocked_missing_prerequisite`로 기록한다. 한 wave에는 최대 8개 catalog family만 활성화한다.

### 4.4 `PolicyBroker`

파일: `src/aidast/core/policy_service.py`, `src/aidast/core/request_broker.py`

모든 HTTP client, Playwright, ffuf, API secondary adapter가 같은 결정을 사용한다.

매 요청 전에 다음을 확인한다.

- authorization 진위·만료·revocation generation
- plan revision/task/adapter ID 일치
- Scope와 TargetPolicy digest 일치
- 실제 destination의 scheme/host/port/path와 resolved address
- identity reference의 origin/audience/tenant 일치
- activity class와 예상 effect
- run/target/identity별 전역 request·RPS·concurrency·byte·시간 예산
- redirect마다 동일한 재검증과 credential 제거

현재 `RequestBroker.request_count`는 instance-local이므로 durable budget ledger로 바꿔야 한다. timeout은 caller가 늘릴 수 없고 정책값 이하로 cap한다. broker DB나 감사 기록이 불가능하면 요청도 보내지 않는다.

## 5. 승인 계약

Scope 승인은 “어디를 검사할 수 있는가”만 증명하며 Attack 실행을 승인하지 않는다. Attack plan이 완성된 뒤 별도 `RunAuthorization.json`을 만든다.

필수 필드:

- authorization/run/scan ID
- 인증된 발급자와 승인자 identity
- 발급·시작·만료 시각
- Scope, TargetPolicy, handoff, plan revision, catalog digest
- 승인된 task ID 목록
- 허용 activity class와 adapter ID
- 사용할 credential reference 목록
- target/identity별 예산
- 제외 동작과 evidence 보존 정책
- revocation generation

다음 변경은 재승인을 요구한다.

- target, path, method/effect 또는 identity 확대
- 새 adapter나 새 test family 추가
- 요청·시간·byte 예산 증가
- plan 본문 또는 catalog version 변경

단순히 예산을 낮추거나 task를 취소하는 변경은 기존 승인을 좁히므로 재승인 없이 허용한다.

## 6. DB 전략과 thin schema v6

### 6.1 immutable Recon과 writable Attack 분리

`Runs/<scan_id>/Recon.db`는 handoff hash가 확정된 원본이므로 수정하지 않는다. Attack 시작 시 빈 `AttackRuns/<attack_run_id>/Attack.db`를 만들고 Attack 소유 테이블만 생성한다. Recon 자료는 생성·재개 때 Handoff와 SHA-256을 재검증한 뒤 별도 read-only SQLite 연결로 조회한다.

이 방식은 두 요구를 동시에 만족한다.

- Recon→Attack 입력의 byte-level 무결성 유지
- Recon 데이터 중복 없이 Attack 상태만 별도 저장

`Attack.db`는 `source_manifest_id`, `source_manifest_sha256`, `source_database_sha256`와 상대 locator로 원본을 가리킨다. SQLite가 서로 다른 DB 사이의 foreign key를 강제하지 못하므로 endpoint의 scan 귀속은 Python 저장 API가 `endpoints → origins → assets`를 조회해 검증한다. Attack 내부 run/task/attempt 관계는 로컬 FK와 trigger를 유지한다.

### 6.2 현재 v4와 원본 SQL

원본 SQL이 사용하는 `attack_attempts`, `attack_facts`, `findings`, `attack_requests`, `finding_chains`, `finding_chain_nodes` column은 현재 v4에 이미 존재한다. 단, 원본 SQL은 SQLite CLI의 `.bail`, parameter, `readfile()`에 의존하므로 Python sqlite3에서 직접 실행하지 않는다.

thin schema v6에서 관리할 항목:

- `attack_runs`: source digests, plan revision, authorization, 상태, cursor
- `attack_plans`와 `attack_plan_tasks`: immutable revision과 task digest
- `run_authorizations`: exact plan/policy/catalog binding, expiry/revocation
- `broker_reservations`: dispatch 전 예산 예약과 fencing token
- `broker_receipts`: 실제 전송 여부, redirect, byte/timing 요약
- `worker_leases`: 중복 worker 실행 방지
- `model_iterations`: context hash, prompt/schema/catalog version, raw result, 검증 결과
- `attack_evidence`: finding 유무와 관계없이 모든 attempt의 정제된 증거

기존 table 보강:

- `attack_attempts`: logical check ID와 execution ID 분리, `outcome_unknown` 지원
- `attack_facts`: source attempt/run, expiry, superseded fact 지원
- `findings`: attack run/task/reviewer 귀속; 기본 상태는 `unreviewed`
- `attack_requests`: finding 필수 관계 제거 또는 일반 evidence table로 이동
- chain은 confirmed finding만 `demonstrated`가 되도록 검증

원본의 `INSERT OR IGNORE`는 사용하지 않는다. 결과를 `inserted`, `duplicate`, `invalid`, `failed`로 구분하고 audit event와 같은 transaction에 기록한다. header/body는 공통 redactor를 통과시키고 원문 대신 digest, 길이, 제한된 정제본 또는 외부 evidence reference를 저장한다.

## 7. 동적 분석 loop

```text
1. VERIFY
   handoff, completed scan, Scope/Policy/catalog digest 확인

2. MATERIALIZE
   immutable Recon.db 검증 → 빈 writable Attack.db 생성

3. DISPATCH
   저장된 signal로 catalog 후보와 누락 prerequisite 생성

4. PLAN
   모델이 기존 ID와 catalog 범위 안에서 task를 제안

5. APPROVE
   운영자가 정확한 plan revision/task/budget/identity를 승인

6. RESERVE
   broker가 durable budget과 worker lease를 먼저 예약

7. EXECUTE
   고정 adapter가 승인된 request intent만 전송

8. OBSERVE
   응답을 redaction·size cap 후 evidence로 저장

9. DECIDE
   모델/validator가 negative, inconclusive, candidate로 분류

10. VALIDATE
   candidate는 독립 검토 전까지 finding으로 확정하지 않음

11. REPLAN
   새 fact가 생기면 남은 task 우선순위만 조정; 확대는 재승인

12. COMPLETE
   completed/skipped/blocked/inconclusive/failed 수를 각각 보고
```

요청을 보내기 전에 reservation과 attempt ID를 먼저 commit한다. 전송 후 receipt 저장 전에 process가 죽으면 `outcome_unknown`으로 두고 자동 재전송하지 않는다.

## 8. 먼저 해결해야 하는 기존 egress 구멍

Attack을 연결하기 전에 Recon을 포함한 모든 transport가 하나의 broker를 사용해야 한다.

1. `api_secondary_discovery._http_request()`가 별도 urllib opener를 사용하며 redirect를 broker에서 검사하지 않는다.
2. `discover_with_ffuf()`는 `proxy_url`을 받지만 ffuf command에 전달하지 않는다.
3. Playwright는 launch proxy에 의존하며 Python 수준의 TargetPolicy route hook이 없다.
4. proxy와 `RequestBroker`가 별도 request counter를 사용해 전체 예산이 분리된다.
5. 기본 browser session 파일명이 host/port 기준이라 account/tenant/run이 섞일 수 있다.
6. full URL의 query와 선택적 body에 개인정보·token이 들어갈 수 있어 evidence redaction 규칙을 확장해야 한다.

이 항목이 끝나기 전에는 “모든 Attack 요청이 Scope와 예산으로 강제된다”고 볼 수 없다.

## 9. 구현 순서

### Phase 0: 기준 고정

- 현재 handoff v1, DB v4, offline review 동작을 fixture로 고정
- 기존 `prepare_review()`의 network/process 거부 동작 유지

완료 조건: 기존 141개 테스트와 package resource 테스트 통과.

### Phase 1: source catalog 보존

- 라이선스와 provenance 복사
- 59개 skill inventory와 content hash 생성
- 각 skill을 disabled catalog entry로 등록

완료 조건: wheel 설치 후에도 catalog hash 검증, 어떤 skill도 실행 capability를 갖지 않음.

### Phase 2: thin schema v6와 writable run store

- 빈 Attack DB 생성, Recon 상대 locator와 source digest 저장
- plan/authorization/broker/evidence/lease table 추가
- Python repository API 구현

완료 조건: 원본 Recon.db hash 불변, migration 재실행 안전, cross-scan/run 쓰기 차단.

### Phase 3: planner와 dispatcher

- deterministic signal routing
- stateless structured model call
- strict ID/catalog/prerequisite/budget validator

완료 조건: prompt injection 문자열, forged ID, duplicate, oversized context가 실행 task가 되지 않음.

### Phase 4: 승인과 공용 broker

- plan-bound `RunAuthorization`
- durable hierarchical budget, lease, revocation
- 모든 transport adapter 통합

완료 조건: 정책 밖 host/redirect/address/identity 요청은 전송 전 차단되고 restart로 예산이 초기화되지 않음.

### Phase 5: local dynamic harness

- loopback mock target과 fixed low-impact adapters
- 정상 응답, redirect, timeout, 큰 응답, 오류, secret marker 테스트
- crash/resume 및 `outcome_unknown` 검증

완료 조건: 외부 네트워크 없이 정확한 request ledger, redaction, 취소, 복구가 재현됨.

### Phase 6: 제한적 운영 활성화

- 사람이 검토한 test family부터 adapter별 opt-in
- 실제 버그바운티 프로그램의 policy와 승인 artifact 사용
- candidate→confirmed 독립 검토 gate 적용

완료 조건: 미승인 task, 만료 승인, credential audience 불일치, 감사 저장 실패 시 fail-closed.

## 10. 테스트 필수 항목

- 변조·누락·다른 scan의 handoff 거부
- 원본 Recon.db byte hash 불변
- schema migration과 legacy DB 보존
- plan revision/digest가 다른 승인 거부
- 미승인 task/adapter/identity 거부
- redirect·DNS/address 변경 재검증
- 모든 adapter의 공용 global budget 사용
- process restart 후 budget·cursor·lease 복원
- dispatch 직후 crash의 `outcome_unknown` 처리
- 두 account/tenant session 완전 분리
- header/query/body redaction과 body cap
- 모델이 반환한 forged ID·명령·임의 URL 거부
- zero findings와 incomplete/failed run 구분
- installed wheel에서 catalog/provenance resource 로딩

## 11. 최종 목표 인터페이스

```bash
# 1. Scope + Recon + immutable handoff
aidast run "<PROGRAM_URL>" --target "<CANONICAL_ASSET>"

# 2. Attack plan 생성. 네트워크 요청 없음
aidast attack plan Runs/<scan_id>/Handoff.json \
  --output-dir AttackRuns/<attack_run_id>

# 3. 정확한 plan revision을 사람이 승인
aidast attack approve AttackRuns/<attack_run_id>/Plan.json \
  --by "<REVIEWER>" --expires-in 2h

# 4. 승인된 task만 실행하고 중단/재개 가능
aidast attack execute AttackRuns/<attack_run_id>/RunAuthorization.json
aidast attack status <attack_run_id>
aidast attack resume <attack_run_id>
aidast attack revoke <attack_run_id> --by "<REVIEWER>"
```

현재 구현된 `aidast attack <Handoff.json>`은 Phase 0의 offline evidence-review 기능으로 유지한다. 새 동적 분석 기능은 기존 명령의 의미를 바꾸지 않고 별도 subcommand와 schema version으로 추가한다.

## 12. 2026-09-09 구현 상태

- Phase 1 완료: 외부 library 59개와 controller의 출처·해시를 보존했고, 전부 실행 연결 없는 `metadata_only` 카탈로그로 등록했다.
- Phase 2 완료: Recon 테이블을 복제하지 않는 thin schema v6와 run-bound plan/evidence/audit/revocation/lease 저장소를 추가했다. 생성·재개 때 원본 Handoff/Recon을 다시 검증한다.
- Phase 3 완료(제한형): 새 컨텍스트를 쓰는 구조화 planner와 forged ID를 거부하는 dispatcher, 고정 응답 메타데이터 adapter를 구현했다.
- Phase 4 부분 완료: 서명 승인, 정확한 intent binding, SQLite 전역 예산과 매 요청 철회 확인을 구현했다. Recon subprocess 전체와 Attack ledger를 하나의 원장으로 합치는 작업은 아직 남아 있다.
- Phase 5 부분 완료: redirect, timeout, 큰 응답, 동시 worker, crash/resume를 외부 네트워크 없는 fixture로 검증했다. 운영 환경 loopback harness는 아직 없다.
- Phase 6 미활성: 기본 CLI는 `approve/execute`를 스스로 신뢰하지 않으며, 검증 workflow가 주입되지 않으면 거부한다. 59개 playbook용 능동 취약점 adapter도 아직 비활성이다.

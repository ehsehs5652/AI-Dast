# VulnBank·OWASP Juice Shop 기능 및 탐지 평가 계획

## 1. 목적

현재 AI DAST 구현을 로컬에서 실행 중인 다음 두 교육용 취약 애플리케이션에 적용한다.

| 대상 | URL | 고정 기준 |
| --- | --- | --- |
| OWASP Juice Shop | `http://127.0.0.1:3001/` | `lab/compose.yaml`에 고정한 Docker image digest |
| Commando-X VulnBank | `http://127.0.0.1:5001/` | source commit `5e5ea5425fcf309373a0655dd111ecfb45037cbf` |

이번 평가는 다음 질문에 답하는 것을 목표로 한다.

1. 승인 Scope부터 Recon, Attack, Chaining, Validation까지 통합 pipeline이 완료되는가?
2. Recon이 공개·인증 영역의 endpoint, method와 API 표면을 얼마나 수집하는가?
3. Attack 후보가 실제 evidence와 reproduction spec에 연결되는가?
4. Validation이 알려진 취약점은 확인하고 정상 동작은 취약점으로 오인하지 않는가?
5. 동일 조건에서 실행 시간, 요청 수, 실패와 결과 변동이 어느 정도인가?
6. `CONFIRMED` case를 근거로 Report 초안을 생성할 수 있는가?

단순 홈페이지 응답 시간이나 컨테이너 기동 성공은 AI DAST의 탐지 성능으로 해석하지 않는다. 이는 실행 전제조건 확인에만 사용한다.

## 2. 평가 범위

### 포함

- 승인된 loopback 대상의 Recon
- 브라우저 기반 공개·인증 영역 수집
- GET, HEAD, OPTIONS와 제한된 POST 기반 테스트
- SQL injection, 인증·인가, session/JWT, XSS, API·GraphQL, 정보 노출과 비즈니스 로직 후보
- Attack finding과 evidence 관계
- Chaining의 완료 또는 정당한 `SKIPPED`
- Shared Validation의 case, control, evidence와 decision
- `CONFIRMED` case의 로컬 Report 생성
- 중단·실패 상태와 재개 가능성 확인

### 초기 평가에서 제외

- 외부 도메인, webhook, Collaborator와 인터넷 OOB 서비스
- 외부 DeepSeek API 호출
- 실제 cloud metadata와 사설망 대상
- DoS, 대량 brute force, 고동시성 race condition
- 관리자 계정 삭제, 계정 정지, 데이터 대량 삭제
- 악성 실행 파일 업로드와 서버 명령 실행
- Docker host 또는 다른 컨테이너 공격
- 자동 보고서 제출

VulnBank의 동일 애플리케이션 내부에 구현된 SSRF 교육 endpoint는 별도로 구분한다. 평가에 포함할 경우 VulnBank 컨테이너 자신의 `127.0.0.1:5000`에 구현된 `/internal/*` 및 모의 `/latest/meta-data/*`만 허용한다. 외부 URL은 사용하지 않는다.

## 3. 현재 구현상 선행 제약

### 승인 Scope artifact

`aidast run`은 승인된 Scope artifact를 필요로 하고, 프로그램 식별 URL은 절대 HTTPS URL이어야 한다. 실제 테스트 대상은 HTTP loopback URL이다.

테스트 전에 기존 Scope 모델과 승인·해시 계약을 사용하는 로컬 전용 fixture를 준비한다.

| 구분 | 프로그램 식별 URL | 승인할 canonical asset |
| --- | --- | --- |
| Juice Shop | `https://lab.aidast.invalid/juice-shop` | `http://127.0.0.1:3001/` |
| VulnBank | `https://lab.aidast.invalid/vuln-bank` | `http://127.0.0.1:5001/` |

`.invalid` URL은 네트워크 접근에 사용하지 않는다. Scope artifact 경로를 결정하는 식별자 역할만 한다. fixture는 다음 내용을 명시해야 한다.

- 해당 loopback URL만 in-scope
- HTTP scheme과 정확한 port 허용
- 로컬 교육용 앱의 취약점 테스트 명시적 허용
- GET, HEAD, OPTIONS와 POST 명시
- PUT, PATCH, DELETE 금지
- 외부 egress와 외부 OOB 금지
- DoS, 대량 brute force, race test 금지
- 요청 제한과 timeout
- VulnBank `/graphql`에 대한 harmless introspection 허용 여부

예상 실행 상한은 다음과 같다.

| 항목 | 초기값 |
| --- | ---: |
| RPS | 0.5 |
| concurrency | 2 |
| timeout | 15초 |
| max depth | 2 |
| target별 max HTTP requests | 500 |

fixture 생성기는 `Scope.json`, `Scope.md`, `Manifest.json`, `Approval.json`을 기존 `ScopeCoordinator` 검증이 통과하는 형태로 생성해야 한다. 제품의 정책 검증을 우회하는 별도 플래그는 추가하지 않는다.

### 인증 identity

인증이 필요한 평가에는 최소 두 개의 일반 사용자 identity가 필요하다.

- `primary`: 자신의 객체와 정상 흐름 확인
- `secondary`: 객체 간 authorization 차이 확인

현재 CLI가 한 실행에서 여러 identity credential reference를 Attack·Validation에 전달할 수 있는지 실행 전 확인한다. 지원되지 않는 경우:

1. 공개·단일 identity 범위로 baseline을 먼저 수행한다.
2. 다중 사용자 BOLA/IDOR 항목은 `FN`이 아니라 `NOT_EVALUATED`로 기록한다.
3. 테스트 전용 credential backend 추가는 별도 변경으로 분리한다.

### 도구 의존성

다음을 실행 전 확인한다.

- Codex CLI 로그인
- Playwright Chromium
- `mitmdump`
- `katana`
- `ffuf`
- 프로젝트 Python 환경과 package import
- Docker의 Juice Shop, VulnBank, PostgreSQL health

URL asset을 대상으로 하므로 공개 도메인용 `subfinder`는 이번 평가의 필수 항목이 아니다.

## 4. 테스트 데이터와 초기 상태

두 대상은 각각 별도 scan으로 실행한다. 하나의 Scope와 scan에 두 대상을 섞지 않는다.

### VulnBank

- 기본 admin 계정은 앱 초기화 확인용으로만 기록한다.
- 일반 사용자 두 개를 테스트 전용 이름으로 생성한다.
- 두 사용자의 account number와 초기 balance를 기록한다.
- 사용자 간 식별 가능한 최소 거래 1건을 준비한다.
- 외부 LLM API key는 비워 두고 mock AI 모드를 유지한다.
- 반복 실행 전 PostgreSQL baseline을 복원한다.

DB 초기화는 named volume 전체를 바로 삭제하는 방식보다 다음 순서를 우선한다.

1. 초기 계정과 fixture 데이터를 구성한다.
2. PostgreSQL dump 또는 동등한 baseline을 만든다.
3. 각 반복 실행 전에 baseline을 복원한다.
4. 복원이 검증되지 않으면 반복 결과를 서로 직접 비교하지 않는다.

### Juice Shop

- 테스트 전용 일반 계정을 사용한다.
- 인증 실행 전에 필요한 최소 상태만 준비한다.
- 반복 실행 사이에는 동일한 container/image와 초기 데이터 상태로 되돌린다.
- challenge 해결 상태가 다음 반복에 누적되지 않도록 container 재생성 또는 검증된 초기화 절차를 사용한다.

실제 개인정보, 개인 계정과 재사용 중인 비밀번호는 사용하지 않는다.

## 5. 정답 데이터셋

탐지 정확도를 평가하려면 실행 전에 version별 ground truth를 고정한다.

### finding 단위

하나의 정답 항목은 최소 다음 조합으로 정의한다.

```text
target
+ endpoint template
+ HTTP method
+ vulnerability class
+ injection/object location
+ required identity roles
+ observable security impact
```

같은 원인과 endpoint에서 나온 중복 보고는 하나의 finding으로 정규화한다. 취약점 이름만 같고 endpoint 또는 영향이 다르면 별도 항목으로 본다.

### 상태

각 ground-truth 항목은 다음 중 하나로 분류한다.

- `ELIGIBLE`: 현재 Scope, 계정과 Runtime이 평가할 수 있음
- `NOT_EVALUATED_AUTH`: 필요한 identity/credential이 준비되지 않음
- `NOT_EVALUATED_RUNTIME`: browser/OOB/race 등 필요한 runtime 미지원
- `OUT_OF_TEST_SCOPE`: 초기 안전 범위에서 명시적으로 제외
- `MANUAL_ONLY`: 자동 DAST 결과로 직접 판정하기 어려움

Precision과 recall의 분모에는 `ELIGIBLE`만 사용한다.

### 초기 대표 항목

첫 실행은 전체 취약점 수를 목표로 하지 않고, 현재 pipeline의 주요 경로를 확인할 대표 항목을 선정한다.

VulnBank 후보군:

- `/login` 인증 SQL injection
- `/debug/users` 정보 노출
- `/check_balance/<account_number>` 및 `/transactions/<account_number>` authorization
- `/graphql` introspection과 오류 노출
- `/api/v3/user/<user_id>` 객체 접근 제어
- JWT/session 관련 약점
- `/upload_profile_picture_url`의 동일 앱 내부 SSRF
- merchant/API 또는 AI mock endpoint의 정보 노출

Juice Shop 후보군:

- 로그인 관련 injection과 인증 우회
- 공개된 민감 endpoint 또는 파일
- API 객체 접근 제어
- 입력 반사·저장 위치의 XSS
- JWT/session 관련 약점
- 관리자·사용자 기능의 authorization
- 오류·디버그·메타데이터 노출

정확한 challenge ID와 endpoint는 고정된 Juice Shop image에서 별도 ground-truth 표로 확정한다. 앱의 모든 challenge를 자동으로 `ELIGIBLE`로 간주하지 않는다.

## 6. 단계별 실행 계획

### Phase A — 정적 사전 점검

목표: 네트워크 테스트 전에 구성 오류를 찾는다.

1. Docker 서비스와 `/healthz` 확인
2. 이미지 digest와 VulnBank source commit 기록
3. Codex와 외부 도구 설치 확인
4. 로컬 Scope fixture 생성 및 `aidast scope status` 검증
5. `aidast recon ... --policy-only` 실행
6. 생성된 `TargetPolicy.json` 수동 확인

정책 확인 항목:

- 대상 host가 `127.0.0.1` 하나인지
- port가 각각 3001 또는 5001인지
- scheme이 HTTP 하나인지
- path가 `/` 아래로만 제한되는지
- Recon method가 GET/HEAD/OPTIONS인지
- Attack에서 허용된 mutation method가 POST만인지
- RPS, concurrency, depth와 요청 한도가 예상과 일치하는지
- 외부 host 또는 wildcard가 없는지

정책이 예상보다 넓으면 실행하지 않는다.

### Phase B — Recon-only shakedown

목표: 후속 Attack 없이 수집 기능과 정책 경계를 확인한다.

대상별로 다음 형태의 명령을 사용한다.

```bash
aidast recon "https://lab.aidast.invalid/juice-shop" \
  --target "http://127.0.0.1:3001/" \
  --start-url "http://127.0.0.1:3001/" \
  --max-rps 0.5 \
  --max-requests 500 \
  --max-depth 2 \
  --max-concurrency 2 \
  --timeout-seconds 15 \
  --ffuf-wordlist resources/wordlists/common.txt \
  --tag-batch-size 25 \
  --codex-timeout 600 \
  --execute \
  --tag-after
```

VulnBank는 식별 URL과 target/start URL을 5001 대상으로 변경한다.

2026-09-23 로컬 재검증에서는 50건 태깅 배치가 기본 Codex 제한 300초에 도달했다. 관측치당 입력이 늘어난 현재 구현에는 25건 배치와 600초 상한을 적용한다.

검사 항목:

- Recon stage 종료 상태
- DNS/HTTP/origin/endpoint 단계 결과
- `Recon.db`, `Surface.json`, `ReconReview.json` 생성
- 관측 endpoint와 method 수
- 중복 관측과 annotation 실패 수
- Scope 밖 요청 차단 기록
- endpoint 기준 목록 대비 수집률
- 로그에 외부 host 요청이 없는지

Recon에서 실패가 발생하면 통합 실행으로 넘어가지 않는다.

### Phase C — 인증 흐름 점검

목표: runtime browser 로그인과 session 전달을 검증한다.

1. 대상별 `primary` 테스트 계정으로 로그인한다.
2. 로그인 이후 dashboard와 인증 API가 Surface에 포함되는지 확인한다.
3. 쿠키·token 값 자체가 artifact나 로그에 평문 노출되지 않는지 확인한다.
4. VulnBank의 `secondary` identity 제공 가능 여부를 확인한다.
5. 인증 실패 시 공개 영역 결과와 구분해 기록한다.

인증 준비가 안 된 항목은 탐지 실패로 세지 않는다.

### Phase D — 통합 pipeline 1회 shakedown

목표: 대상별로 Recon → Attack → Chaining → Validation 전체 경로를 한 번 완료한다.

```bash
aidast run "https://lab.aidast.invalid/juice-shop" \
  --target "http://127.0.0.1:3001/" \
  --start-url "http://127.0.0.1:3001/" \
  --max-rps 0.5 \
  --max-requests 500 \
  --max-depth 2 \
  --max-concurrency 2 \
  --timeout-seconds 15 \
  --tag-batch-size 25 \
  --codex-timeout 600
```

VulnBank는 식별 URL과 target/start URL을 5001 대상으로 변경한다.

확인할 산출물:

```text
result/Runs/<scan_id>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Scope.json
├── Approval.json
├── TargetPolicy.json
└── Handoff.json

result/AttackRuns/<scan_id>/
└── Pipeline.db
```

DB 확인 항목:

- `scans` 상태
- `stage_runs`의 Recon, Attack, Chaining, Validation 상태와 시간
- `attack_tasks`의 terminal 상태
- `attack_attempts`와 request ledger
- `findings`와 reproduction spec
- `finding_chains`와 chain evidence
- `validation_cases`, attempts, evidence와 decision
- `audit_events`
- `reserved`, `running`, `outcome_unknown`으로 남은 요청

### Phase E — 판정 및 Report

1. 각 finding을 ground truth와 사람이 대조한다.
2. TP, FP, duplicate, unsupported와 unresolved로 분류한다.
3. 각 `CONFIRMED` case의 evidence가 실제 attempt/request를 가리키는지 확인한다.
4. 대표 `CONFIRMED` case에 대해 Report 초안을 생성한다.
5. Report의 재현 절차와 evidence 인용을 원본 case와 비교한다.
6. report status에서 stale 여부를 확인한다.

Report는 외부 플랫폼에 제출하지 않는다.

### Phase F — 반복 평가

대상별 shakedown이 성공한 뒤 초기 상태를 복원하고 동일 조건으로 총 3회 실행한다.

- 동일 Docker image/source commit
- 동일 AI DAST code/worktree
- 동일 Scope와 Policy
- 동일 계정과 데이터 baseline
- 동일 모델 식별자
- 동일 요청 상한

3회의 중앙값과 최소·최대 또는 변동 범위를 비교한다. 모델 또는 Skill이 변경되면 같은 baseline으로 새 평가 세트를 시작한다.

## 7. 평가 지표

### 환경과 기능

- 대상 앱과 DB health
- Stage별 `completed`, `failed`, `skipped`
- 필수 artifact 생성 여부
- Recon 원본 hash 보존 여부
- 중단 후 재개 성공 여부
- 미종결 task/request 존재 여부

### Recon 품질

```text
endpoint recall = 발견한 eligible endpoint / 전체 eligible endpoint
method recall   = 발견한 eligible endpoint-method / 전체 eligible endpoint-method
duplicate ratio = 중복 정규화 전 관측 수 중 중복 관측 비율
```

공개 영역과 인증 영역을 분리해서 기록한다.

### 탐지 정확도

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 × precision × recall / (precision + recall)
```

- TP: endpoint, 취약점 유형, 공격 위치·객체와 보안 영향이 ground truth와 일치
- FP: 취약점으로 확정했으나 독립 재현 또는 ground truth에서 성립하지 않음
- FN: `ELIGIBLE` 취약점을 찾지 못함
- duplicate: 같은 root cause를 여러 건으로 보고했으며 FP와 별도 집계
- `INCONCLUSIVE`, `BLOCKED`, `UNDERPOWERED`는 FP로 즉시 세지 않고 원인을 별도 분석

### 실행 비용

- 전체 및 Stage별 소요 시간
- Recon/Attack/Validation 요청 수
- 모델 호출과 확인 가능한 모델 사용량
- 생성된 task와 Agent 수
- 실패와 재시도 횟수
- `CONFIRMED` finding당 요청 수와 실행 시간

측정하지 못한 항목은 0이 아니라 `NOT_MEASURED`로 기록한다.

## 8. 중단 조건

다음 상황에서는 해당 실행을 중단하고 원인을 기록한다.

- TargetPolicy가 loopback 이외 host를 허용함
- 예상하지 않은 외부 네트워크 요청이 관측됨
- 요청 한도 또는 method 제한이 적용되지 않음
- 테스트 대상이 비정상 종료하거나 DB health가 실패함
- 실제 데이터 삭제 또는 테스트 계정 밖의 상태 변경이 발생함
- credential, cookie, token 또는 비밀값이 artifact에 평문 노출됨
- Recon 원본 DB hash가 후속 단계에서 변경됨
- Agent 결과와 DB에 기록된 finding/evidence ID가 일치하지 않음
- 진행 중 요청의 outcome을 알 수 없는 상태에서 자동 재실행을 시도함

중단 후 동일 상태를 임의로 이어서 성능 결과에 포함하지 않는다. 환경을 baseline으로 복원하고 새 scan으로 다시 시작한다.

## 9. 결과 정리 형식

실행 원본은 기존 `result/Runs`와 `result/AttackRuns`에 보존한다. 별도의 smoke-test JSON은 만들지 않는다.

최종 평가는 대상별로 다음 내용을 하나의 Markdown 보고서에 정리한다.

```text
환경·버전
Scope·Policy 요약
실행별 Stage 결과
Recon coverage
TP·FP·FN 및 제외 항목
Validation 상태 분포
실행 비용
실패·재시도·제약
대표 evidence와 Report 검토
개선 우선순위
```

자동 생성 수치만으로 TP/FP를 확정하지 않는다. ground truth와 evidence를 사람이 대조한 결과를 기록한다.

## 10. 실행 전 준비 체크리스트

- [ ] 두 Docker 대상과 VulnBank DB가 healthy다.
- [ ] 대상 image digest와 source commit을 기록했다.
- [ ] Codex CLI 로그인이 유효하다.
- [ ] Playwright Chromium, mitmdump, katana와 ffuf가 준비됐다.
- [ ] 두 로컬 Scope fixture가 승인·무결성 검사를 통과한다.
- [ ] `policy-only` 결과를 사람이 검토했다.
- [ ] loopback 외부 요청이 허용되지 않는다.
- [ ] 테스트 계정과 데이터 baseline이 준비됐다.
- [ ] 다중 identity 지원 여부를 확인했다.
- [ ] ground truth에서 `ELIGIBLE` 항목을 확정했다.
- [ ] 각 대상의 Recon-only shakedown이 성공했다.
- [ ] 실행 중단 및 데이터 복원 절차를 확인했다.

이 체크리스트가 완료된 뒤 통합 `aidast run`을 시작한다.

# AI DAST 운영 상세

이 문서는 AI DAST의 Recon 실행 경계, 인증 브라우저, 요청 예산, 진단,
관측 태깅, 통합 파이프라인과 Legacy 호환 경로를 설명합니다.
처음 설치하거나 일반적인 실행 흐름만 확인하려면 먼저
[README](../README.md)를 읽으세요.

## 목차

- [Scope 수집과 정책](#scope-수집과-정책)
- [운영 안전 원칙](#운영-안전-원칙)
- [Recon 실행 제어](#recon-실행-제어)
- [로그인과 브라우저 모드](#로그인과-브라우저-모드)
- [요청 예산과 프록시 경계](#요청-예산과-프록시-경계)
- [진단 로그](#진단-로그)
- [로컬 웹 대시보드](#로컬-웹-대시보드)
- [관측과 태깅](#관측과-태깅)
- [통합 파이프라인과 데이터 무결성](#통합-파이프라인과-데이터-무결성)
- [Legacy Attack 경로](#legacy-attack-경로)
- [Shared Validation](#shared-validation)
- [Case 기반 Report](#case-기반-report)
- [Legacy Validation과 Report](#legacy-validation과-report)
- [Skill 실행](#skill-실행)
- [결과 및 프로젝트 폴더](#결과-및-프로젝트-폴더)
- [Katana와 ffuf 증거 메타데이터](#katana와-ffuf-증거-메타데이터)

## 운영 안전 원칙

- 페이지 내용은 신뢰할 수 없는 입력으로 처리합니다.
- Recon의 자동 form submission은 항상 비활성화됩니다.
- Codex 로그인 정보는 저장소에 포함하지 않습니다.
- `result/`와 `.venv/`는 Git에서 제외합니다. `.env` 같은 비밀정보 파일도
  커밋하지 않습니다.
- 로그인 세션과 브라우저 프로필에는 쿠키, 스토리지, 토큰이 포함될 수 있으므로
  공유하거나 커밋하지 않습니다.
- 브라우저 세션 전달은 서비스별 로그인 성공이나 프록시 전환 후 유효성을
  범용적으로 보장하지 않습니다.
- Report는 로컬 초안만 생성하며 플랫폼에 자동 제출하지 않습니다.

모든 기본 결과를 하나의 저장소 밖 디렉터리에 모으려면 실행 셸에서 다음 환경변수를
설정합니다.

```bash
export AIDAST_RESULT_ROOT="/path/to/dast_result"
```

설정하지 않으면 clone한 저장소의 `result/`를 사용합니다. 따라서 어느 작업
디렉터리에서 `aidast`를 실행해도 CLI와 WebUI가 같은 결과를 읽습니다.
`--output-dir`, `--db-path`, `--surface-path`, `--run-root` 등 명시적 CLI 경로는
환경변수 기반 기본값보다 우선합니다.

## 로컬 웹 대시보드

`aidast dashboard --ui-dir <WebUI-dist>`는 clone한 저장소의 `result/`에 있는 persisted run을
읽기 전용으로 투영합니다. `/api/v1/scans`와 scan snapshot REST API, scan별
WebSocket replay stream을 제공하고 선택한 정적 WebUI도 같은 origin에서 제공합니다.

- `Recon.db`와 `Pipeline.db`는 SQLite read-only URI와 `query_only`로 엽니다.
- 로그에는 audit event type만 사용하며 `details_json`, HTTP body, cookie, token은
  전달하지 않습니다.
- durable WebSocket cursor는 파생 데이터인 `result/.webui/events.db`에 저장합니다.
- `Scope.json`과 `Approval.json`의 SHA-256이 일치해야 승인 상태가 표시됩니다.
- 인증이 구현되기 전까지 `127.0.0.1`, `::1`, `localhost` 이외의 bind는 거부합니다.
- UI에는 실행/변경 endpoint가 없으며 스캔 제어는 계속 CLI를 사용합니다.

## Scope 수집과 정책

### 수집과 승인

```bash
aidast scope "<PROGRAM_URL>"
```

임시 `Scope.md`가 만들어지면 원본 프로그램 페이지와 대조한 뒤 터미널에서
승인합니다.

```text
이 Scope를 승인하고 저장할까요? [y/N]:
```

- `y`: 프로그램별 공식 경로에 Scope 산출물을 저장합니다.
- `n` 또는 Enter: 임시 산출물을 모두 폐기합니다.

검토자 이름을 남기거나 저장된 Scope의 무결성을 확인할 수 있습니다.

```bash
aidast scope "<PROGRAM_URL>" \
  --by "<REVIEWER>"
aidast scope status "<PROGRAM_URL>"
```

승인 후 `Scope.md` 또는 `Scope.json`이 변경되면 무결성 검사가 실패합니다.
기존 프로그램 산출물은 자동으로 덮어쓰지 않습니다.

### 인증이 필요한 프로그램 페이지

Intigriti researcher URL처럼 플랫폼 로그인이 필요한 프로그램 페이지는
Scope 전용 runtime browser로 수집합니다.

```bash
aidast scope "<PROGRAM_URL>" \
  --login-mode runtime-browser \
  --identity "<ACCOUNT_LABEL>"
```

`aidast`가 저장소 밖의 격리된 persistent Chromium 프로필을 엽니다. 로그인과
MFA를 직접 완료하고, 명령에 입력한 정확한 프로그램 페이지로 돌아와 Scope
화면을 연 뒤 터미널에서 Enter를 누르세요. 다른 origin 또는 다른 path에 있는
탭은 캡처 대상으로 인정하지 않습니다.

프로필은 기본적으로
`~/.local/share/aidast/scope-sessions/<binding-hash>/browser-profile/`에
저장되어 같은 platform origin과 identity 조합에서 재사용됩니다. 실제 쿠키와
토큰이 포함되므로 공유·백업·커밋하지 마세요. Scope 캡처는 완전성 검사를 통과한
뒤에만 Codex가 해석하며, partial 또는 blocked 캡처는 승인 단계로 넘어가지
않습니다.

```text
result/Scope/<platform>/<program>/
├── Scope.md
├── Scope.json
├── Manifest.json
└── Approval.json
```

### Recon 계획과 정책 확인

```bash
aidast recon "<PROGRAM_URL>"
```

1. 승인된 Scope가 있으면 무결성을 확인하고 재사용합니다.
2. Scope가 없으면 수집과 대화형 승인을 먼저 수행합니다.
3. Main Agent가 승인된 자산을 바탕으로 downstream 호환 정책을 생성합니다.
4. AIDAST 소스에 vendoring된 Strix-derived Recon engine이 도구와 순서를 선택합니다.
5. AIDAST MITM addon이 Scope 경계를 강제하고 허용 캡처를 Recon DB와 Surface에 적재합니다.

내장 엔진은 `src/aidast/recon/strix_engine/`에 있으며 내부 namespace는
`aidast.recon.strix_engine`입니다. 실행 시 `reference/strix`를 import하지 않으므로 그 폴더는
개발 참고용입니다. Recon extras, LLM provider/login, sandbox image는 별도 준비해야 합니다.
`--policy-only`는 계획과 TargetPolicy를 확인하며 실제 타깃 네트워크 요청은 하지 않습니다.

```bash
aidast recon "<PROGRAM_URL>" --policy-only
```

Recon은 승인 Scope에서 생성한 TargetPolicy와 AIDAST MITM addon으로 요청을 검사합니다.
TargetPolicy는 Recon tool 설정과 Attack 호환 정책 모두에 사용됩니다. 정책 검증이나 필수
프록시 준비가 실패하면 fail-closed로 중단합니다.

## Recon 실행 제어

실제 실행에는 승인된 `Scope.json`의 canonical 자산을 `--target`으로 지정하거나
`--all-targets`를 명시해야 합니다. `--target`은 반복해서 사용할 수 있으며 부분
문자열이나 유사 도메인은 허용하지 않습니다.

```bash
aidast recon "<PROGRAM_URL>" \
  --all-targets \
  --start-url "<START_URL>" \
  --execute \
  --tag-after
```

`--target`은 승인된 canonical 자산만 선택할 수 있습니다. `--start-url`은 시작 URL일
뿐이며 허용범위를 넓히지 않습니다. AIDAST MITM addon은 승인된 host/scheme/port/path/method를
요청 시점에 강제하며 wildcard 발견도 승인 wildcard 경계 안에서만 허용합니다.
Recon 로그인과 세션은 내장 Strix-derived browser 흐름이 관리합니다. 이전 CLI의
`--session-bundle` 옵션은 현재 Recon 명령에서 지원하지 않습니다.

Intigriti/HackerOne 요청 식별값은 MITM addon에서 승인 host 규칙을 통과한 뒤에만
타깃 요청에 추가됩니다. 로그인 제공자 등 out-of-scope host로는 전달하지 않습니다.

```bash
aidast recon "<PROGRAM_URL>" \
  --all-targets \
  --intigriti-username "<INTIGRITI_USERNAME>" \
  --execute
```

이 옵션은 `X-Intigriti-Username`과 식별 User-Agent를 지정합니다. 승인된 Scope가
헤더를 요구하는 경우 누락 시 실행을 거부합니다.

`--all-targets`는 선택된 승인 Scope 자산 전체를 내장 Strix-derived Recon agent에 제공합니다.
agent가 도구와 순서를 선택하고, Scope 경계는 MITM addon에서 최종 강제됩니다.
Downstream TargetPolicy는 Attack 호환 계약으로 유지됩니다.

기본 Recon은 비로그인 읽기 전용 탐색으로 시작합니다. `--allow-authorized-account-registration`
은 승인된 정확한 canonical host에서 root agent가 가치와 self-service 가입 경로를 확인해
일회용 저권한 계정 등록을 고려하게 합니다. `--allow-lab-account-creation`은 승인된 로컬
테스트 타깃에서만 사용합니다. Scope 금지는 항상 우선하며, 계정 등록 허가는 거래·삭제 등
업무 상태 변경을 허용하지 않습니다.

격리된 로컬 랩에서 상태변경 endpoint 후보까지 검증하려는 경우에만
`--allow-lab-state-changing-discovery`를 추가합니다. 이 옵션은 `127.0.0.1`/`localhost`/
loopback IP의 명시적 단일 타깃으로 제한되고 wildcard는 거부됩니다. first-party JS/UI/API
명세에 공개된 각 operation에 대해 관측된 method/schema와 synthetic 데이터로 한 번만
요청하며, 외부 결제/provider 호출·다른 identity 변경·계정 및 기존 데이터 삭제는 하지 않습니다.
Scope에서 금지한 method/path는 여전히 MITM addon이 차단합니다. 이 옵션은 공개/실제
버그바운티 대상에 적용되지 않습니다.

### 시작 URL과 인증 경계

`--start-url`은 시작점일 뿐 권한을 부여하지 않습니다. AIDAST MITM addon은 요청마다
scheme, host pattern, port, path, method를 검사합니다. 기존 CLI의 `--session-bundle`
단일 타깃 세션 재사용 옵션은 제거되었습니다. 두 계정 IDOR 세션 비교는 Attack 쪽에서 처리합니다.

### 종료 처리

일반 오류나 `Ctrl-C` 같은 제어 종료가 발생하면 현재 scan과 stage를 `failed`로
마감하고 DB 연결을 닫은 뒤 종료 신호를 다시 전달합니다. 프로세스 강제 종료나
전원 손실처럼 정리 코드를 실행할 수 없는 경우에는 마지막 상태가 남을 수 있습니다.

## Recon 실행기와 도구 준비

Strix-derived engine source는 AIDAST 패키지에 포함되어 있지만, agent runtime dependency는
`uv sync --extra recon-engine`으로 설치해야 합니다. 실행 시 sandbox image와 LLM 설정도
필요합니다. `reference/strix` checkout은 runtime dependency가 아닙니다. MITM addon은 승인된
Scope 경계를 강제하며 `mitmdump`를 시작할 수 없으면 실행을 중단합니다. 개별 탐색 도구의
사용 가능 여부와 실행 결과는 Recon 진단에 기록됩니다.

## MITM proxy 경계와 실행 로그

허용된 요청은 MITM capture에 기록합니다. 차단된 요청은 AIDAST DB에 endpoint 관측으로
적재하지 않습니다. 로그인 ID header는 타깃별 정책 확인 뒤 추가합니다. 이 addon은 HTTP(S)
프록시 경계이지 OS/network-namespace 수준의 우회 불가능 egress firewall은 아닙니다.

`--diagnostic-logs`는 AIDAST Recon coordinator/executor의 단계별 진단 JSONL을 생성합니다.
MITM raw capture에는 URL·헤더·본문이 있을 수 있으니 로컬 민감자료로 취급하고 공유 전에
검토해야 합니다.

## 진단 로그

Recon 진단은 `result/logs/<scan_id>/recon.jsonl`에 저장되며, 통합 `run`의 산출물은
해당 scan의 `Runs/.../<scan_id>/` 아래에 생성됩니다.

```bash
aidast run "<PROGRAM_URL>" \
  --target "<CANONICAL_ASSET>" \
  --diagnostic-logs
```

MITM journal에는 URL, request/response headers, 그리고 body가 기록될 수 있습니다.
이는 AIDAST가 관측을 적재하는 원본 근거입니다. 인증·개인정보가 포함될 수 있으므로
`result/logs/<scan_id>/` 전체를 로컬 민감자료로 취급하고, 공유 전에는 반드시 검토·마스킹하세요.

## 관측과 태깅

AIDAST Main Agent가 Recon 계획과 제한된 adaptive follow-up을 제안하고, Python coordinator가
승인 Scope·정책과 기존 수행 task를 검증한 뒤 실행합니다. `--tag-after`이면 별도 worker가
저장 관측을 기존 Codex 기반 기능 태깅에 전달합니다. 계획 및 `--policy-only`는 태깅하지 않습니다.

```bash
aidast tag result/Recon.db
```

같은 Recon 명령에서 태깅까지 이어가려면 `--tag-after`를 추가합니다.
이미 태깅된 관측은 건너뜁니다.

- `discovery_contexts`: 페이지, 자동 클릭, 당시 인증 상태와 세션 연결
- `endpoint_observations`: 병합 전 발견 기록, 출처, HTTP 트랜잭션 근거
- `annotation_runs`: 모델 선택, 프롬프트/태그 버전, 성공 및 실패 이력
- `endpoint_annotations`: 기능, 페이지, 데이터 역할 태그와 판단 근거

기존 Recon DB는 additive SQLite schema `user_version=3`으로 마이그레이션됩니다.
기존 행은 보존하며 알 수 없는 과거 맥락을 추측해 채우지 않습니다.

LLM에는 요청/응답 본문, 쿠키, 인증 헤더, form 입력값을 전달하지 않습니다.
URL의 사용자정보, query, fragment를 제거합니다. 인증이 확인되지 않은 상태는
`unknown`으로 저장하고 모델 confidence를 검증된 확률로 취급하지 않습니다.
태깅 실패 시 수집 결과와 실패 상태를 보존하며 다음 `tag` 실행에서 재시도할 수 있습니다.
태깅 worker는 실제 타깃에 접근하지 않습니다.

## 통합 파이프라인과 데이터 무결성

```bash
aidast run "<PROGRAM_URL>" --all-targets
```

일부 자산만 실행하려면 `--target`을 반복해서 지정합니다.

```text
Scope → AI-Dast Recon → 태깅
      → Handoff → Pipeline.db
      → Native Attack → Chaining
      → Shared Validation
      → case 기반 Report
```

`Handoff.json`에는 `Recon.db`, Scope, 정책과 관련 artifact의 SHA-256, 크기,
역할과 scan ID가 들어갑니다. 원본 `Recon.db`는 query-only로 열고 SQLite backup으로
`Pipeline.db`를 만듭니다. Attack, Chaining, Validation schema는 복제본에만
추가합니다. 복제 전후 원본 해시가 달라지면 파이프라인을 중단합니다.

```text
result/Runs/<platform>/<program>/<scan_id>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Scope.json
├── Approval.json
├── TargetPolicy.json
└── Handoff.json

result/AttackRuns/<platform>/<program>/<scan_id>/
└── Pipeline.db
```

통합 `aidast run`은 Shared Validation 이후 현재 확정된 `CONFIRMED` case마다
Report 로컬 초안을 자동 생성합니다. 확정된 case가 없거나 지원하지 않는 플랫폼이면
Report 단계를 건너뜁니다. `CodexMainAgent`는 단계별 adapter 이름이며
전체 순서와 gate를 결정하는 상위 Agent가 아닙니다.

## Legacy Attack 경로

다음 경로는 persisted-data 호환을 위한 기존 오프라인 `Attack.db` 흐름입니다.
통합 `aidast run`의 Native Attack과 구분해야 합니다.

```bash
aidast attack review \
  result/Runs/<platform>/<program>/<scan_id>/Handoff.json \
  --output-dir result/AttackRuns/<platform>/<program>/<scan_id>

aidast attack plan \
  result/Runs/<platform>/<program>/<scan_id>/Handoff.json \
  --output-dir result/AttackRuns/<platform>/<program>/<scan_id>

aidast attack status \
  result/AttackRuns/<platform>/<program>/<scan_id>/Attack.db

aidast attack revoke \
  result/AttackRuns/<platform>/<program>/<scan_id>/Attack.db \
  --reason "검토 중단"
```

기본 CLI는 오프라인 증거 검토와 계획까지만 수행합니다. 동적 코어는 검토된 고정
adapter의 HEAD/GET/OPTIONS 응답 메타데이터만 관찰합니다. 신뢰된 승인 workflow와
`TargetPolicy` broker가 주입되지 않으면 fail-closed됩니다. 외부 Attack playbook
59개는 비활성 참고 카탈로그이며 payload나 shell 명령을 실행하지 않습니다.

Recon handoff와 원본 파일 SHA-256은 DB를 열 때마다 다시 확인합니다.
SQLite `-wal`, `-journal`, `-shm` 파일이 없는 완결된 Recon snapshot이 필요합니다.
Review config와 계획은 상대 경로를 사용합니다. 통합 `Pipeline.db`의 원본 경로는
무결성 보호 대상이므로 완료된 평면 경로의 스캔을 직접 옮기지 마세요. 새 스캔은
처음부터 프로그램별 경로에 저장하며, 기존 평면 경로도 조회·재개할 수 있습니다.

`approve`와 `execute`는 신뢰된 애플리케이션이
`main(argv, attack_workflow=...)`로 검증 경계를 주입한 경우에만 사용할 수 있습니다.
두 명령 모두 `--authorization FILE`이 필요하고 `approve`는 `--by REVIEWER`도
필요합니다. 파일 경로나 검토자 이름만으로 승인이 성립하지 않습니다.

기본 `revoke`는 로컬 AttackStore를 갱신합니다. 별도 broker 예산 ledger의 폐기와는
다르므로 연결된 실행기는 매 요청마다 저장된 실행 상태와 폐기 세대도 검증해야 합니다.

## Shared Validation

기본 Validation은 별도 `Validation.db`를 만들지 않고 `Pipeline.db`에 case, attempt,
evidence, decision을 기록합니다. Chaining stage가 `completed` 또는 `skipped`일 때만
시작할 수 있습니다.

```bash
aidast validate run \
  <PIPELINE_DB> \
  --scan-id <scan_id> \
  --policy <TARGET_POLICY_JSON>

aidast validate run \
  <PIPELINE_DB> \
  --scan-id <scan_id> \
  --finding-id <finding_id> \
  --policy <TARGET_POLICY_JSON>

aidast validate resume \
  <PIPELINE_DB> \
  --stage-run-id <stage_run_id> \
  --policy <TARGET_POLICY_JSON>

aidast validate status \
  <PIPELINE_DB> \
  --scan-id <scan_id>
```

Validation은 HTTP, browser, OOB, chain adapter 뒤에서 positive/negative control과
반복 관측을 수행합니다. 최종 상태는 `CONFIRMED`, `DISPROVEN`, `OUT_OF_SCOPE`,
`KNOWN`, `UNDERPOWERED`, `BLOCKED`, `INCONCLUSIVE`, `CONTESTED` 중 하나입니다.
모델이 최종 상태를 직접 정하지 않습니다. 중단된 case는 같은 stage run과 audit
history를 유지해 재개합니다.

## Case 기반 Report

Report는 `Pipeline.db`의 Validation `case_id`를 선택해 로컬 초안을 만듭니다.
통합 실행에서는 case별로 `result/ReportRun/<scan_id>/<case_id>/`에 자동 저장합니다.
`CONFIRMED`만 draft 대상이고, `KNOWN`은 원본 case를 가리키며 `CONTESTED`는
review-only로 남습니다. HackerOne, Intigriti, Bugcrowd를 지원하며 자동 제출하지 않습니다.

```bash
aidast report run \
  <PIPELINE_DB> \
  --case-id <case_id> \
  --platform hackerone \
  --output-dir result/ReportRun/<scan_id>/<case_id>

aidast report status \
  result/ReportRun/<scan_id>/<case_id>/Report.db
```

`Report.db`, `Report.json`, `Report.md`는 Validation decision과 인용 evidence에
연결됩니다. Decision hash가 바뀌면 기존 Report는 stale로 판정됩니다.

## Legacy Validation과 Report

기존 `Attack.db → Validation.db → Report.db` 데이터는 삭제하거나 자동 변환하지
않습니다. `--run-id`와 `--validation-id`를 명시한 기존 명령을 계속 지원합니다.

```bash
aidast validate run \
  <LEGACY_ATTACK_DB> \
  --run-id <run_id> \
  --finding-id <finding_id> \
  --output-dir <VALIDATION_OUTPUT_DIR>

aidast report run \
  <LEGACY_VALIDATION_DB> \
  --validation-id <validation_id> \
  --platform hackerone \
  --output-dir result/ReportRun/<scan_id>
```

## Skill 실행

Scope 수집과 의미 해석은 제한된 Codex planning 호출과 네이티브 Skill로 관리됩니다.

```text
src/aidast/skills/scope/SKILL.md
```

실행 시 Skill은 Codex 표준 경로
`.agents/skills/aidast-scope/SKILL.md`에 임시 배치되고 `$aidast-scope`로
호출됩니다. Codex 네이티브 브라우저가 JavaScript 페이지를 충분히 렌더링하지
못하면 제한된 Playwright 브라우저로 같은 URL을 수집하고 Codex가 캡처를 해석합니다.
사용자 승인, 원문 근거, 무결성 검사와 공식 저장은 Python 코드가 담당합니다.

## 결과 및 프로젝트 폴더

기본 실행 산출물은 Git에서 제외되는 `result/` 아래에 저장됩니다.

```text
result/
├── Scope/<platform>/<program>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Runs/<platform>/<program>/<scan_id>/
├── AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db
├── AttackRun/                     # legacy
├── ValidationRun/                 # legacy
├── ReportRun/<scan_id>/<case_id>/
└── .aidast_sessions/
```

`--run-root`와 `--attack-output-root`는 프로그램별 폴더를 만들 기준 경로입니다.
`--output-dir`, `--db-path`, `--surface-path`는 해당 명령의 출력 경로입니다.

핵심 코드는 `src/aidast/recon`, `pipeline`, `attack`, `chaining`, `validation`,
`reporting`으로 나뉩니다. Stage orchestration은 `src/aidast/orchestration`,
Codex adapter는 `src/aidast/agents`, 로컬 Skill은 `src/aidast/skills`에 있습니다.

설계와 변경 이력은 `docs/design`, `docs/changes`, 외부 출처 자료는
`docs/third-party`, 공용 wordlist는 `resources/wordlists`에 둡니다.

## Recon 도구 결과와 관측

Katana, Gospider, httpx, ffuf, Subfinder 및 browser adapter를 AIDAST의 executor가
호출하고 각 결과를 parser·정책 검사·DB 저장 단계로 전달합니다. 도구 후보 수, 실제 HTTP
exchange 수, AIDAST canonical endpoint 수는 서로 다른 집계입니다. 진단 JSONL에서 단계별
실행·실패·파싱·정책 제거 건수를 함께 확인하세요.

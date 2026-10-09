# AI DAST

AI DAST는 **승인된 버그바운티 범위 안에서만 동작하는 웹 취약점 분석 도구**입니다.
웹 대시보드와 CLI를 제공하며, Scope 수집부터 정찰·공격 후보 분석·검증·보고서 초안까지
하나의 흐름으로 연결합니다.

> **주의:** 반드시 참여 권한이 있고 테스트가 명시적으로 허용된 프로그램과 자산에서만
> 사용하세요.

## 동작 흐름

```text
Scope 수집 및 사용자 승인
    ↓
Recon(자산·endpoint 탐색)
    ↓
Attack 후보 분석
    ↓
Chaining(취약점 연결)
    ↓
Validation(재현·검증)
    ↓
버그바운티 플랫폼별 보고서 초안
```

단계 순서, 실행 조건, 데이터베이스 상태와 재개 처리는 Python 오케스트레이터가
결정론적으로 관리합니다. 실제 네트워크 요청은 Scope, 정책, 승인과 요청 예산 검사를
모두 통과한 경우에만 실행됩니다.

## 바로가기

- [설치](#설치)
- [웹 대시보드](#웹-대시보드)
- [빠른 시작](#빠른-시작)
- [핵심 워크플로](#핵심-워크플로)
- [주요 명령](#주요-명령)
- [결과 폴더](#결과-폴더)
- [운영 상세](docs/OPERATIONS.md)

## 처음 사용하는 경우

```bash
git clone https://github.com/ehsehs5652/AI-Dast.git
cd AI-Dast
uv sync --extra recon-engine
uv tool install --editable '.[recon-engine]'
uvx --from playwright playwright install chromium  # Scope/Attack 전용; Recon 브라우저는 agent-browser

cd WebUI
npm ci
npm run build
cd ..

aidast login
aidast dashboard --ui-dir WebUI/dist
```

브라우저에서 <http://127.0.0.1:8000>을 열고 다음 순서로 진행합니다.

1. **Scope / Programs**에서 프로그램 URL과 Public/Private 여부를 등록합니다.
2. Scope를 수집하고 인스코프·아웃오브스코프 항목을 검토합니다.
3. **Yes**로 승인한 Scope만 **New Scan**에서 실행합니다.
4. 스캔 진행 상태와 로그를 대시보드에서 확인합니다.

자세한 화면 설명은 [WebUI 사용 설명서](WebUI/README.md)를 참고하세요.

## 주요 기능

| 단계 | 역할 | 주요 결과 |
| --- | --- | --- |
| Scope | 프로그램 Scope 수집, 사용자 승인, 무결성 검증 | `Scope.json`, `Approval.json` |
| Recon | 자산·서비스·endpoint 수집과 관측 태깅 | `Recon.db`, `Surface.json` |
| Handoff | Recon 산출물의 해시와 역할 검증 | `Handoff.json`, `Pipeline.db` |
| Attack | 정책과 승인 경계 안에서 후보 조사 | finding, attempt, evidence |
| Chaining | 검증 가능한 finding 간 연결 분석 | chain candidate |
| Validation | 재현·대조군·증거 기반 최종 판정 | validation case |
| Report | 검증된 case의 플랫폼별 로컬 초안 생성 | `Report.md`, `Report.json` |

Recon은 `src/aidast/recon/strix_engine/`에 통합된 AI-DAST 내장 엔진으로 실행됩니다.
실행 시 개발 참고용 `reference/` 디렉터리를 동적으로 불러오지 않습니다. AI-DAST가 Scope
승인과 MITM 경계를 제공하고, 내장 에이전트가 탐색 도구와 순서를 선택합니다. 허용된 MITM
캡처는 AI-DAST의 DB/Surface에 적재되고 기존 태깅 경로를 거칩니다. Attack·Chaining·Validation은
기존 AI-DAST 파이프라인을 사용합니다. 내장 코드의 제3자 출처와 라이선스는
[`docs/third-party/STRIX-ENGINE-VENDORING.md`](docs/third-party/STRIX-ENGINE-VENDORING.md)에 공개합니다.

Recon Python 의존성은 `uv sync --extra recon-engine`에 포함됩니다. Sandbox를 사용하는
실행은 Docker 이미지와 LLM provider/login 설정도 필요합니다. 소스 checkout에서 이미지를
빌드할 때는 저장소 루트에서 다음처럼 실행합니다.

```bash
docker build -t aidast-strix-mitm:local \
  -f src/aidast/recon/strix_engine/containers/Dockerfile .
export AIDAST_STRIX_IMAGE=aidast-strix-mitm:local
```

Recon LLM 인증은 AIDAST의 `aidast login`과 별도로 설정합니다. 내장 인증 명령은 다음처럼
실행할 수 있습니다.

```bash
python -m aidast.recon.strix_engine.interface.main auth login chatgpt
export STRIX_LLM="chatgpt/<지원되는-모델>"
```

이 구독 로그인 정보는 사용자 설정의 `~/.strix/`에 저장되며 저장소나 Recon DB에는
기록되지 않습니다.

Vendoring 및 Apache-2.0 출처·수정 내역은
[`docs/third-party/STRIX-ENGINE-VENDORING.md`](docs/third-party/STRIX-ENGINE-VENDORING.md)에
기록했습니다. `reference/strix`는 개발 시 비교용으로만 남으며, 삭제해도 Python 실행
코드의 import는 깨지지 않습니다.

Attack은 Recon 신호로 선택된 Hunt Skill을 사용합니다. 템플릿이 지원되는
프로브는 Agent가 payload를 직접 생성하지 않고, 버전과 해시가 고정된 YAML
템플릿과 Python Runner가 요청 변형·matcher·evidence를 결정론적으로
처리합니다. matcher 적중은 finding 확정이 아니라 Validation 후보입니다.

Recon과 Attack의 메서드 상한은 Scope에서 메서드나 관련 활동을 명시적으로
금지한 경우에만 좁힙니다. 그 외에는 두 단계 모두 POST/PUT/PATCH/DELETE를
포함합니다. 이는 임의의 부작용을 허용한다는 뜻은 아닙니다. 브라우저의 자동 폼
제출은 별도 설정이며 기본 비활성화 상태입니다. 요청별 위험 등급, 테스트 자원
소유 증명, 요청 예산, 고위험·외부 부작용 승인 절차와 Scope의 데이터·서비스
영향 제한은 그대로 적용됩니다.

IDOR Hunt는 Recon에서 성공적으로 관측한 인증된 읽기 요청과 식별자 후보가
있을 때만 별도의 계정 B 로그인을 요청합니다. B 세션은 origin별로 격리하고,
관측된 계정 A 요청의 메서드·객체 ID·경로를 바꾸지 않은 채 GET/HEAD/OPTIONS로
재생해 응답 내용을 비교합니다. 이 IDOR 전용 재생 경로는 쓰기 요청을 허용하지
않으며, 상태 코드 차이만으로 취약점을 확정하지 않습니다. B 로그인이 불가능하거나
적합한 관측 요청이 없으면 IDOR 검사를 건너뛰고 다른 Attack 검사는 계속합니다.

## 실행 전 확인

- 실제 요청은 승인된 Scope, `TargetPolicy`, 요청 예산을 모두 통과해야 합니다.
- 로그인 세션에는 쿠키·스토리지·토큰이 포함될 수 있으므로
  `result/.aidast_sessions/`와 브라우저 프로필을 공유하거나 커밋하지 않습니다.
- 정책 강제에 필요한 `mitmdump`를 시작하지 못하면 실행을 중단합니다.
- Report는 로컬 초안만 생성하며 플랫폼에 자동 제출하지 않습니다.

세부 정책, 요청 예산, 로그인 모드와 fail-closed 동작은
[안전 경계와 운영 원칙](docs/OPERATIONS.md)을 참고하세요.

## 설치

### 필수 환경

- Python 3.13 이상
- [uv](https://docs.astral.sh/uv/)
- [Codex CLI](https://github.com/openai/codex)
- Chromium (Recon uses `agent-browser`; Playwright is retained only for the Scope
  reader fallback and Attack browser/session transport)

### GitHub에서 설치

```bash
git clone https://github.com/ehsehs5652/AI-Dast.git
cd AI-Dast
uv sync --extra recon-engine
uv tool install --editable '.[recon-engine]'

uvx --from playwright \
  playwright install chromium  # Scope/Attack compatibility only; Recon uses agent-browser
```

이후 어느 폴더에서든 `aidast`를 실행할 수 있습니다. 기본 산출물은 명령을
실행한 폴더가 아니라 위에서 clone한 저장소의 `result/`에 모입니다.

### 팀 개발용 의존성 설치

코드를 수정하고 PR을 만드는 팀원은 clone한 저장소에서 개발 의존성도 설치합니다.

```bash
cd AI-Dast
uv sync --group dev --extra recon-engine
```

editable tool로 연결되어 있으므로 clone 폴더의 코드 수정은 재설치 없이 바로
반영됩니다.

### 설치 확인과 로그인

설치를 확인하고 Codex에 로그인합니다.

```bash
aidast --help
aidast login
```

`aidast login`은 Codex CLI 로그인 화면을 열고 완료 후 상태를 확인합니다.
인증 정보는 저장소나 AI DAST DB가 아니라 Codex CLI 사용자 설정에 저장됩니다.

### 업데이트

일반 사용자와 팀 개발자 모두 현재 설치를 삭제하지 않고 업데이트할 수 있습니다.

```bash
aidast update
```

clone한 저장소에 연결된 editable 설치에서는 저장소가 깨끗한지 확인한 뒤 현재 브랜치를
`git pull --ff-only`로 업데이트하고 tool 의존성을 새로 맞춥니다. 로컬 변경사항이
있으면 작업을 덮어쓰지 않고 중단하므로 먼저 commit하거나 stash해야 합니다.

### Recon 도구 준비

내장 Recon 엔진을 위한 Python 의존성은 설치 단계의 `recon-engine` extra에 포함됩니다.
실제 실행에는 sandbox image, LLM provider/login, 정책 프록시 `mitmdump`도 필요합니다.
이미지의 외부 탐색 도구들은 vendored Dockerfile에서 준비합니다.

## 웹 대시보드

WebUI를 live 모드로 빌드한 뒤 로컬 운영자 대시보드를 실행합니다.

```bash
cd WebUI
npm ci
npm run build

cd ..
aidast dashboard --ui-dir WebUI/dist
```

기본 저장 경로는 명령을 실행한 위치와 관계없이 clone한 저장소의 `result/`입니다.
브라우저에서 `http://127.0.0.1:8000`을 엽니다. 서버는 `Recon.db` 또는
`Pipeline.db`를 read-only로 읽고, 승인 파일의 SHA-256 무결성을 다시 확인한 후
스캔 상태와 비밀정보가 제거된 활동 로그를 REST/WebSocket으로 전달합니다.
재연결용 이벤트 커서는 `result/.webui/events.db`에 별도로 저장되며 원본 실행 DB는
수정하지 않습니다.

현재 서버에는 원격 인증이 없으므로 loopback 주소에만 바인딩할 수 있습니다.
`Scopes / Programs`에서 프로그램 URL과 Public/Private 구분을 먼저 등록합니다.
등록 항목은 Scope 수집 대기열일 뿐 실행 권한이 아닙니다. 대시보드에서 Public
headless 수집 또는 로그인/MFA용 interactive browser 수집을 시작하고, 진행 로그와
추출된 인/아웃 스코프 및 정책을 검토한 뒤 반드시 **Yes(승인)** 또는 **No(거절)** 를
선택합니다. Yes만 해시로 묶인 승인 파일을 게시하며 No는 초안을 삭제합니다.
`New scan`은 무결성이 확인된 승인 Scope만 선택할 수 있고,
그 Scope의 정확한 타깃과 그 안에 포함되는 시작 URL만 기존 `aidast run`으로
전달합니다. 승인되지 않은 프로그램·Scope 밖 URL·임의 명령은 거부하며 CLI의
정책·승인·예산 게이트를 그대로 통과합니다. 프론트엔드 빌드 변수와 전체 이벤트 계약은
[`WebUI/README.md`](WebUI/README.md)를 참고하세요.

## 빠른 시작

### 1. Scope 수집 및 승인

```bash
aidast scope "<PROGRAM_URL>"
```

생성된 임시 `Scope.md`를 원본 프로그램 페이지와 대조한 뒤 승인합니다.

로그인이 필요한 Intigriti researcher 페이지는 격리된 persistent Chromium을
열어 플랫폼 로그인과 MFA를 완료한 뒤 수집합니다.

```bash
aidast scope "<INTIGRITI_RESEARCHER_PROGRAM_URL>" \
  --login-mode runtime-browser \
  --identity "<ACCOUNT_LABEL>"
```

브라우저에서 정확한 프로그램 상세 페이지로 돌아와 Scope 화면을 연 다음
터미널에서 Enter를 누릅니다. 브라우저 프로필에는 인증정보가 포함되므로
공유하거나 Git에 추가하면 안 됩니다.

Adobe Public 프로그램을 `aidast`로만 운영하는 명령 허용 목록과 단계별 게이트는
[Intigriti Adobe Public aidast-only 가이드](docs/guides/INTIGRITI_ADOBE_PUBLIC_AIDAST_ONLY.md)를
참고하세요.

모든 기본 산출물을 저장소 밖의 한 디렉터리에 모으려면
`AIDAST_RESULT_ROOT`를 지정합니다.

Intigriti 프로그램에서 요청 식별 헤더를 요구하면 Recon 또는 통합 실행에
사용자명을 전달합니다.

```bash
aidast recon "<INTIGRITI_RESEARCHER_PROGRAM_URL>" \
  --all-targets \
  --intigriti-username "<INTIGRITI_USERNAME>" \
  --execute
```

```bash
export AIDAST_RESULT_ROOT="/path/to/dast_result"
```

이 설정은 기본 Scope, Recon DB/Surface, Runs, Attack, Validation, Report 경로에
적용됩니다. 명령에서 개별 출력 경로를 지정하면 해당 명령의 명시적 값이 우선합니다.

```text
이 Scope를 승인하고 저장할까요? [y/N]:
```

`y`만 승인으로 처리합니다. `n` 또는 Enter를 입력하면 임시 산출물을 폐기합니다.

```bash
aidast scope status "<PROGRAM_URL>"
```

### 2. 네트워크 요청 없이 정책 확인

```bash
aidast recon "<PROGRAM_URL>" --policy-only
```

Scope 해석, `TargetPolicy.json`, 도구 제어값만 확인하며 실제 타깃에는 요청하지 않습니다.

Recon 에이전트는 승인된 Scope를 입력으로 받아 비로그인 발견부터 시작합니다. 일회용 계정
등록은 해당 옵션을 명시한 경우에만 고려됩니다. 세션은 격리된 Recon sandbox의 agent-browser에서
관리되며 허용된 HTTP(S) 트래픽은 AI-DAST MITM 경계를 통과합니다.

### 3. 승인된 전체 자산 실행

```bash
aidast run "<PROGRAM_URL>" --all-targets
```

일부 canonical 자산만 실행하려면 `--target`을 반복해서 지정합니다.

```bash
aidast run "<PROGRAM_URL>" \
  --target "example.com" \
  --target "api.example.com"
```

HackerOne 프로그램이 자동화 요청 식별을 요구하거나 권장하면 사용자명을
`X-HackerOne` 헤더로 전달합니다.

```bash
aidast run "<HACKERONE_PROGRAM_URL>" \
  --target "example.com" \
  --hackerone-username "<HACKERONE_USERNAME>"
```

`aidast run`은 Recon, 태깅, Handoff, Native Attack, Chaining,
Shared Validation 순서로 실행한 뒤 현재 확정된 `CONFIRMED` case마다 Report 로컬 초안을 자동 생성합니다.
지원 플랫폼은 HackerOne, Intigriti, Bugcrowd입니다. 확정된 case가 없거나 다른 플랫폼이면
Report를 생성하지 않습니다. 플랫폼에 자동 제출하지 않습니다.

### 4. 검증된 case의 Report 초안 수동 생성·재실행

```bash
aidast report run \
  result/AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db \
  --case-id <case_id> \
  --platform hackerone \
  --output-dir result/ReportRun/<scan_id>/<case_id>
```

지원 플랫폼은 `hackerone`, `intigriti`, `bugcrowd`입니다.
`CONFIRMED` case만 초안을 만들 수 있습니다.

## 핵심 워크플로

### Scope

Scope 산출물은 `result/Scope/<platform>/<program>/` 아래에 프로그램별로
분리합니다. 사용자 승인 뒤에는 `Scope.md`와 `Scope.json`의 무결성을 검사하며
기존 산출물을 자동으로 덮어쓰지 않습니다. 전체 파일 구성은
[Scope 수집과 정책](docs/OPERATIONS.md#scope-수집과-정책)을 참고하세요.

### Recon

팀원 `AI-DAST-ALL`의 Recon/Attack 기능 병합 내용과 검증 범위는 [병합 기록](docs/changes/AI_DAST_ALL_RECON_ATTACK_PARITY.md)에 정리했습니다.

```bash
aidast recon "<PROGRAM_URL>"
```

기본 호출은 승인된 Scope에서 계획 미리보기만 만듭니다. 실제 실행은 아래처럼
`--execute`와 `--target` 또는 `--all-targets`를 지정해야 합니다. AI-DAST 내장 Recon
에이전트가 탐색 도구와 실행 순서를 선택하고, Scope 경계는 AI-DAST MITM addon이 강제합니다.

```bash
aidast recon "<PROGRAM_URL>" \
  --target "example.com" \
  --start-url "https://example.com/app" \
  --execute
```

`--start-url`은 시작 탐색 URL이며 승인된 TargetPolicy와 Scope가 요청을 제한합니다.
Wildcard 자산 발견 결과도 승인 Scope 정책 안에서만 후속 작업으로 등록됩니다.
`--policy-only`는 실제 네트워크 요청 없이 계획과 정책만 확인합니다.

내장 Recon root agent는 승인된 host와 허용된 MITM 경계 안에서 탐색하며,
일회용 계정 등록은 `--allow-authorized-account-registration` 또는 로컬 테스트용
`--allow-lab-account-creation`을 명시한 경우에만 고려합니다. Scope의 금지가 우선합니다.
해당 옵션 없이 폼 제출·상태 변경을 하지 않습니다.

격리된 로컬 랩에서 JS/UI/API 명세에 드러난 쓰기 경로까지 확인하려면
`--allow-lab-state-changing-discovery`를 추가합니다. 이 옵션은 exact loopback 타깃만
허용하며, 후보별 1회 요청과 synthetic 데이터만 사용합니다. wildcard, 다른 사용자,
외부 결제 서비스, 기존 데이터나 일회용 계정 삭제는 허용하지 않습니다. 이 옵션은
실제 버그바운티 타깃에 사용하면 안 됩니다. 예:

```bash
aidast recon "https://lab.aidast.invalid/juice-shop-open" \
  --output-dir result/Scope \
  --target "http://127.0.0.1:3001/" \
  --execute \
  --diagnostic-logs \
  --allow-lab-state-changing-discovery
```

### 관측 태깅

미태깅 Recon 관측은 별도로 재개할 수 있습니다.

```bash
aidast tag result/Recon.db
```

같은 Recon 명령에서 태깅까지 이어가려면 `--tag-after`를 사용합니다. 내장 Recon agent가
MITM에서 남긴 승인 관측을 기존 DB/Surface와 태깅 경로에 전달합니다.
태깅 worker는 실제 타깃에 접근하지 않으며 요청/응답 본문, 쿠키, 인증 헤더,
form 입력값을 LLM에 전달하지 않습니다.

### Handoff와 통합 DB

Recon 묶음은 `result/Runs/<platform>/<program>/<scan_id>/`, 후속 단계가 공유하는 DB는
`result/AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db`에 저장합니다.
기존 평면 경로의 스캔도 대시보드와 재개 명령에서 계속 조회합니다. 기존 DB의
원본 경로는 무결성 보호 대상이므로 과거 폴더를 직접 옮기지 마세요.

`Handoff.json`은 관련 artifact의 SHA-256, 크기, 역할과 scan ID를 기록합니다.
원본 `Recon.db`는 SQLite query-only 모드로 검증하고 backup으로 `Pipeline.db`를
만듭니다. 복제 전후 원본 해시가 달라지면 파이프라인을 중단합니다.
전체 산출물 구성은
[Handoff와 데이터 무결성](docs/OPERATIONS.md#통합-파이프라인과-데이터-무결성)을
참고하세요.

### Attack 실행 경계

`aidast.attack`에는 AI-DAST-ALL을 기준으로 병합한 로컬 승인 워크플로,
Ed25519 승인 검증, 요청 intent, 세션 바인딩, 정책 실행기와 내구성 있는 요청 예산
구현이 포함됩니다. 이 경로는 애플리케이션이 신뢰할 수 있는
`SkillAttackWorkflow` 또는 `SessionAttackLauncher`를 명시적으로 구성해 주입할
때만 네트워크 실행이 가능합니다.

일반 CLI의 `aidast attack approve`와 `aidast attack execute`는 명령행 입력만으로
신뢰 경계를 만들지 않습니다. 주입된 워크플로가 없으면 파일을 열거나 요청을
보내기 전에 실패합니다. 실행하려면 다음 항목이 모두 일치해야 합니다.

- 애플리케이션이 미리 고정한 Ed25519 공개키로 검증된 실행 승인과 현재
  revocation generation
- 실행 계획에 결합된 정확한 요청 intent digest
- 승인된 Scope에서 파생된 `TargetPolicy`와 영속 요청 예산
- run ID, scheme, host, port, path prefix와 identity에 정확히 결합된 일반 파일
  형태의 세션 상태

통합 `aidast run`의 Native Attack은 후속 Validation·Report와 같은
`Pipeline.db`를 사용합니다. 병합된 로컬 승인 워크플로의 thin Attack DB는 별도
호환 경로이며 Recon 원본을 읽기 전용으로 유지합니다.

### Validation

```bash
aidast validate status \
  result/AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db \
  --scan-id <scan_id>
```

최종 상태는 `CONFIRMED`, `DISPROVEN`, `OUT_OF_SCOPE`, `KNOWN`,
`UNDERPOWERED`, `BLOCKED`, `INCONCLUSIVE`, `CONTESTED` 중 하나입니다.
모델이 최종 상태를 직접 정하지 않습니다.

Shared Validation과 case 기반 Report는 현재 `Pipeline.db` schema v10 계약을
그대로 사용합니다. Attack finding의 runtime, development,
impact-development 재현 계약은 정규화된 해시와 함께 원자적으로 저장되며,
Report는 해당 Validation case가 허용한 evidence만 인용합니다. 생성 결과는 항상
로컬 초안이고 플랫폼에 자동 제출되지 않습니다.

## 주요 명령

| 명령 | 설명 |
| --- | --- |
| `aidast login` | Codex CLI 로그인 및 상태 확인 |
| `aidast update` | 설치 방식에 맞춰 AI DAST를 제자리에서 업데이트 |
| `aidast scope` | 프로그램 Scope 수집 또는 상태 확인 |
| `aidast recon` | Recon 계획, 정책 확인, 선택적 실행 |
| `aidast tag` | 저장된 Recon 관측 태깅 재개 |
| `aidast run` | Recon부터 Validation 및 확정 case의 로컬 Report 초안까지 통합 실행 |
| `aidast attack` | 오프라인 계획·상태 관리와 주입된 신뢰 워크플로 실행 경계 |
| `aidast validate` | Shared 또는 Legacy Validation 실행·재개·조회 |
| `aidast report` | 로컬 Report 초안 생성 및 상태 확인 |

각 명령의 전체 옵션은 `aidast <command> --help`로 확인할 수 있습니다.
`Legacy`는 통합 `aidast run` 이전에 저장된 DB를 계속 사용할 수 있게 남겨 둔
호환 경로입니다. 자세한 차이는
[Legacy Attack 경로](docs/OPERATIONS.md#legacy-attack-경로)를 참고하세요.

## 결과 폴더

기본 산출물은 Git에서 제외되는 `result/` 아래에 저장됩니다.

- `Scope/<platform>/<program>/`: 프로그램별 Scope와 승인 정보
- `Runs/<platform>/<program>/<scan_id>/`: Recon, Surface, Handoff 산출물
- `AttackRuns/<platform>/<program>/<scan_id>/`: 통합 `Pipeline.db`
- `ReportRun/`: case 기반 Report 초안
- `AttackRun/`, `ValidationRun/`: Legacy 호환 데이터
- `.aidast_sessions/`: 로컬 로그인 세션

`--run-root`와 `--attack-output-root`는 각각 프로그램별 하위 폴더를 만들
기준 경로를 지정합니다. `--output-dir`, `--db-path`, `--surface-path`는
해당 명령의 출력 경로를 지정합니다.

## 프로젝트 구조

- `agents/`: 제한된 Codex 호출 adapter
- `orchestration/`: 단계 순서와 gate
- `scope/`, `recon/`: Scope 모델, Recon 실행과 관측
- `pipeline/`: Handoff와 `Pipeline.db`
- `attack/`, `chaining/`: 후보 조사와 finding 연결
- `validation/`, `reporting/`: 검증과 Report
- `skills/`: 단계별 로컬 Skill

## 개발

```bash
uv sync --group dev --extra recon-engine
uv run pytest -q
```

배포 의존성만 설치하려면 `uv sync --no-dev --extra recon-engine`을 사용합니다.
테스트 탐색 경로는 루트 `tests/`로 고정되어 있습니다.

## 상세 문서

- [운영 상세](docs/OPERATIONS.md): Recon 경계, 인증, 예산, 진단, Legacy 경로
- [병합 변경 이력](docs/changes/MERGE_CHANGES.md): 통합 전후 차이와 변경 이유
- [Attack Agent 병합 설계](docs/design/ATTACK_AGENT_MERGE_DESIGN.md)
- [외부 Claude-BugHunter 출처와 라이선스](docs/third-party/claude-bughunter/README.md)

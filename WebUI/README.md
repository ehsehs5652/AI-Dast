# AI DAST 웹 대시보드

AI DAST의 Scope 승인, 스캔 실행, 진행 상태, 취약점 후보, 검증 결과와 보고서 초안을
브라우저에서 확인하는 로컬 운영 화면입니다.

대시보드는 실행 상태를 보여주고 승인된 스캔을 시작하는 역할을 담당합니다. 실제 요청,
정책 검사, 요청 예산, 승인 검증과 상태 전이는 Python 백엔드가 처리합니다.

> 현재 대시보드는 한 명의 로컬 운영자를 위한 구성입니다. 원격 서버에 공개하지 마세요.

## 한눈에 보기

| 항목 | 내용 |
| --- | --- |
| 프론트엔드 | React + TypeScript + Vite |
| 백엔드 | FastAPI |
| 실시간 상태 | WebSocket 재연결 및 이벤트 재생 |
| 지원 언어 | 한국어, English |
| 화면 모드 | 시스템 설정, 라이트, 다크 |
| 기본 주소 | `http://127.0.0.1:8000` |
| 데이터 위치 | clone한 저장소의 `result/` |

## 가장 빠른 실행

### Windows + WSL

저장소의 `WebUI/start-dashboard.cmd`를 실행하면 빌드된 WebUI와 Python 백엔드를
시작하고 브라우저를 엽니다.

### 터미널에서 실행

저장소 루트에서 다음 명령을 실행합니다.

```bash
cd WebUI
npm ci
npm run build

cd ..
aidast dashboard --ui-dir WebUI/dist
```

브라우저에서 <http://127.0.0.1:8000>을 엽니다.

`dist/index.html`을 더블 클릭해 `file://`로 여는 방식은 지원하지 않습니다. REST와
WebSocket이 같은 출처에서 연결되어야 하므로 반드시 대시보드 서버를 실행해야 합니다.

## 사용자 흐름

1. 오른쪽 위에서 언어와 화면 모드를 선택합니다.
2. **Scope / Programs**에서 버그바운티 프로그램 URL과 Public/Private 여부를 등록합니다.
3. **Collect Scope**를 누르면 AI DAST 전용 Playwright 브라우저가 열립니다.
   버그바운티 플랫폼 로그인과 MFA를 완료하고 정확한 Scope 페이지를 연 뒤
   대시보드에서 **로그인 완료 · 계속**을 선택합니다.
4. 추출된 인스코프·아웃오브스코프 자산과 정책을 검토하고 **Yes** 또는 **No**를
   선택합니다.
   승인 후에는 프로그램 행의 **Scope 내용 보기**에서 항목별 요약을 확인하고,
   필요한 항목을 펼쳐 수집 내용과 승인 정보를 다시 볼 수 있습니다.
   **수집 활동**은 기록 건수만 표시하며, 클릭하면 시간과 메시지 기록을 펼칩니다.
   **출처 증거**는 자산과 규칙을 뒷받침하는 프로그램 원문의 직접 인용이고,
   **세이프하버**는 프로그램이 밝힌 정책 준수 보안 연구의 보호 조건입니다.
   세이프하버 문구만으로 테스트 허용 범위가 넓어지지는 않습니다.
5. 승인된 Scope만 **New Scan**에서 선택할 수 있습니다.
6. 스캔을 시작한 뒤 **Scans**, **Findings**, **Validation**, **Reports**와 오른쪽
   활동 로그에서 진행 상태를 확인합니다.

프로그램을 등록하거나 Scope를 수집하는 것만으로는 실행 권한이 생기지 않습니다.
사용자가 **Yes**로 승인하고 무결성 검증까지 통과한 Scope만 스캔할 수 있습니다.

## 화면 구성

| 화면 | 기능 |
| --- | --- |
| Overview | 현재 스캔 상태, 단계별 진행률, 취약점 분포와 최근 활동 |
| Scope / Programs | 프로그램 등록, Scope 수집, 초안 검토와 Yes/No 승인, 승인된 Scope 내용 재조회 |
| Scans | 승인된 Scope 기반 새 스캔 시작과 저장된 스캔 선택 |
| Findings | 심각도·검색 필터와 취약점 후보 상세 정보 |
| Validation | 검증 후보와 필요한 증거 확인 |
| Reports | 무결성이 확인된 로컬 보고서 초안 조회·다운로드 |
| Audit log | 민감정보를 제거한 상태 변경 이력 |
| Settings | 연결 상태, 결과 저장 위치, 언어와 화면 설정 |

화면 폭이 900px 이하이면 활동 로그가 본문 아래로 이동하고, 660px 이하이면 내비게이션이
하단 바로 전환됩니다. 스캔 상태와 로그는 페이지를 이동해도 유지됩니다. 로그 보기를
일시정지해도 수신 자체는 멈추지 않으며 최근 500개 항목을 메모리에 유지합니다.

## 개발 모드

Node.js **22.18 이상**이 필요하며 Node.js 24 사용을 권장합니다.

```bash
cd WebUI
npm ci
npm run dev
```

개발 서버 주소는 <http://localhost:4173>입니다.

```bash
npm test
npm run build
npm run preview -- --port 4173
```

의존성 버전은 `package.json`과 `package-lock.json`에 고정되어 있습니다. 테스트는
Node.js 기본 `node:test`를 사용합니다.

### 한국어 문구 추가

화면의 고정 문구는 `src/lib/i18n.ts`의 `ko` 목록에 등록하고 `tr(...)`로 표시합니다.
`npm run build`는 `scripts/check-i18n.mjs`를 실행해 고정 문구의 번역 누락을
오류로 처리합니다.

Scope 수집 및 스캔 활동은 서버가 `message_code`와 필요한 `message_params`를
전달합니다. 새 활동 종류를 만들 때 `src/lib/activityMessages.ts`에 한국어 문구를
함께 등록하세요. 빌드 검사는 백엔드에 추가된 메시지 코드의 번역 등록 여부도
확인합니다. 기존 저장 이벤트의 `message`는 호환용으로 유지됩니다.

## 데모 모드와 라이브 모드

### 데모 모드

기본값은 데모 모드입니다. `demo_local_042`라는 합성 데이터만 사용하며 실제 타깃에
접속하거나 명령을 실행하지 않습니다. 데모 프로그램 목록은 실제 등록 프로그램과 관계가
없고 데모 모드에서는 스캔을 시작할 수 없습니다.

### 라이브 모드

`.env.example`을 `.env.local`로 복사한 뒤 다음 값을 설정합니다.

```dotenv
VITE_TRANSPORT=live
VITE_SCAN_ID=your_scan_id
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_BASE_URL=ws://127.0.0.1:8000
```

백엔드와 WebUI를 같은 주소에서 제공할 때는 API와 WebSocket 주소를 생략하는 것이
좋습니다. 이 경우 브라우저의 현재 주소를 자동으로 사용합니다.

`VITE_*` 값은 브라우저 번들에 공개됩니다. API 키, 쿠키, 토큰이나 비공개 endpoint를
절대 넣지 마세요. 라이브 모드는 백엔드 오류가 발생해도 데모 데이터로 바뀌지 않으며
오프라인·재연결 상태를 명확히 표시합니다.

## 백엔드 연결 규약

### REST 스냅샷

```text
GET /api/v1/scans/{scan_id}
```

응답에는 다음 이벤트를 이어 받을 수 있도록 `last_event_id`가 포함됩니다.

```json
{
  "version": 1,
  "scan_id": "scan_...",
  "last_event_id": 7,
  "status": "running",
  "stage": "Attack",
  "progress": 62,
  "activity": null,
  "requests": 391,
  "budget": 2000,
  "endpoints": 218,
  "scope_approved": true,
  "findings": [],
  "logs": []
}
```

스캔 단계는 `Scope`, `Recon`, `Attack`, `Chaining`, `Validation`, `Report` 순서입니다.
Recon 실행 중에는 진행률 아래에 현재 작업 종류(자산 탐색, DNS 확인, HTTP 응답 확인 등)를 표시합니다.
작업명은 서버가 고정된 목록에서 선택하며 대상 URL이나 요청 내용은 포함하지 않습니다.
확정된 Validation case가 있으면 지원 플랫폼의 Report 초안이 자동 생성됩니다.
초안이 없으면 Report 단계는 완료로 표시되지 않습니다.
스캔 상태는 `pending`, `running`, `completed`, `failed`, `cancelled` 중 하나입니다.

### WebSocket 실시간 이벤트

스냅샷을 받은 뒤 다음 주소로 연결합니다.

```text
/ws/scans/{scan_id}?after={last_event_id}
```

```json
{
  "version": 1,
  "event_id": 8,
  "scan_id": "scan_...",
  "occurred_at": "2026-09-20T06:00:00Z",
  "type": "log.appended",
  "payload": {
    "stage": "Attack",
    "level": "info",
    "message": "민감정보가 제거된 이벤트"
  }
}
```

| 이벤트 | 주요 payload |
| --- | --- |
| `log.appended` | `stage`, `level`, `message` |
| `task.progress.updated` | `progress`, `requests` |
| `stage.status.changed` | `stage` |
| `scan.status.changed` | `status` |
| `finding.updated` | 전체 finding 객체 |
| `heartbeat` | 빈 객체이며 이벤트 번호를 소비하지 않음 |

이벤트 번호는 스캔 안에서 빠짐없이 증가해야 합니다. 클라이언트는 중복 이벤트를 무시하고
순서가 뒤바뀐 이벤트를 최대 128개까지 임시 보관합니다. 연결이 끊기면 마지막으로 정상
처리한 이벤트 이후부터 1~30초 지수 백오프로 재연결합니다. 45초 동안 정상 프레임이
없으면 연결을 새로 만듭니다.

## 보안 경계

- 서버는 원격 인증이 구현되기 전까지 loopback 주소에만 bind합니다.
- 상태 변경 API는 같은 출처의 브라우저 요청만 허용합니다.
- 승인 파일의 해시와 Scope 무결성을 서버에서 다시 검증합니다.
- Scope 밖 URL, 임의 명령과 승인되지 않은 프로그램은 실행하지 않습니다.
- 로그와 감사 API는 요청 본문, 헤더, 쿠키, 토큰과 `details_json`을 전송하지 않습니다.
- 원본 `Recon.db`, `Pipeline.db`, `Report.db`는 읽기 전용으로 조회합니다.
- 보고서는 로컬 초안만 만들며 버그바운티 플랫폼에 자동 제출하지 않습니다.

UI에서 버튼을 숨기거나 비활성화하는 것은 보안 경계가 아닙니다. 최종 Scope, 정책,
요청 예산과 권한 검사는 항상 Python 백엔드에서 수행해야 합니다.

## 아직 지원하지 않는 기능

- 인터넷에 공개된 대시보드를 위한 사용자 인증·권한 관리
- 실행 중인 스캔의 pause/cancel
- Validation 판정과 증거 편집
- 보고서 생성·플랫폼 제출
- 대용량 Audit log 페이지네이션

## 코드 구조

| 경로 | 역할 |
| --- | --- |
| `src/App.tsx` | 전체 화면과 사용자 작업 흐름 |
| `src/styles.css` | 테마와 반응형 레이아웃 |
| `src/data/demo.ts` | 실제 타깃과 분리된 데모 데이터 |
| `src/lib/events.ts` | REST/WebSocket 데이터 검증과 이벤트 적용 |
| `src/hooks/useScanSocket.ts` | 연결, 재연결, 이벤트 재생과 로그 보관 |
| `tests/events.test.mjs` | 이벤트 계약 테스트 |

테마와 표시 언어만 브라우저 `localStorage`에 저장합니다. 비공개 프로그램 표시 여부,
운영 데이터, 인증정보와 비밀정보는 브라우저 저장소에 보관하지 않습니다.

## 검증

```bash
npm test
npm run build
```

현재 이벤트 계약 테스트 14개와 TypeScript production build를 기준으로 검증합니다.
브라우저·반응형 검증 기록은 `verification/README.md`에서 확인할 수 있습니다.

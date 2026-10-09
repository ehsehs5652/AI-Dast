# Strix와 AI-DAST 비교

> 현재 `recon --execute`와 통합 `run`은 AIDAST에 포함된 Strix-derived Recon 엔진을
> 사용합니다. `reference/strix` 체크아웃을 실행 시 import하지 않습니다. AIDAST의
> Scope 경계/MITM 캡처와 데이터 적재, 그리고 기존 Attack·Validation 계약은 유지됩니다.

작성 기준일: 2026-10-06  
비교 대상: 이 프로젝트의 `reference/strix` 소스(패키지 버전 `1.6.2`)와 AI-DAST의 현재 Strix Recon 통합 코드.  
주의: 이는 현재 체크아웃된 코드 기준 비교이며, Strix 원본 저장소 최신판 전체와의 기능 동등성 인증은 아니다.

## 핵심 요약

AI-DAST는 Strix를 단순히 호출하는 얇은 래퍼가 아니다. Recon의 에이전트 런타임, 도구 호출, 하위 에이전트, agent-browser, 탐색 기술은 Strix 코드를 사용한다. 그 앞뒤에는 AI-DAST의 프로그램 Scope 추출·대상 정규화·mitmproxy 경계·관측 DB 적재가 연결돼 있다.

따라서 현재 구성을 간단히 나타내면 다음과 같다.

```text
HackerOne/기타 프로그램
        │
        ▼
AI-DAST Scope 수집·검토·canonical target 선택
        │
        ├── Strix agent runtime: 도구와 하위 에이전트를 선택해 Recon
        │       └── httpx / Katana / agent-browser 및 필요 시 로드하는 Strix skills
        │
        ├── AI-DAST mitmproxy addon: Scope 검사, 허용/차단, HTTP(S) 캡처
        │
        ▼
AI-DAST DB 적재·endpoint/parameter 정규화·Surface 내보내기
        │
        └── 선택적으로 AI-DAST 태깅; Attack/Chaining/Validation은 별도 후속 파이프라인
```

## 세부 비교

| 영역 | Strix 기본 설계 | 현재 AI-DAST 통합 | 의미 |
|---|---|---|---|
| 에이전트와 Recon 순서 | Strix runtime이 root/child agent를 운영하고, 각 agent가 증거에 따라 도구와 순서를 고른다. | 동일한 Strix runtime을 `recon_only=True`로 실행한다. AI-DAST는 승인된 target 목록과 Recon 지침을 넘긴다. 지침에는 Katana, httpx, agent-browser 등의 사용 안내가 있어 완전히 무지시적인 실행은 아니다. | 도구 실행 엔진은 Strix지만, 입력·목표·가드와 일부 탐색 지침은 AI-DAST가 제공한다. |
| Scope 입력 | Strix는 scan config와 system-verified authorized targets를 사용한다. Strix 자체가 HackerOne 정책을 AI-DAST처럼 완전한 승인 Scope 문서/정책으로 변환하는 것은 아니다. | AI-DAST가 프로그램 페이지에서 Scope 문서와 canonical 자산을 만들고, 실행할 target을 선택한다. | 자산의 출처와 범위 판단을 AIDAST 쪽에서 유지한다. 모델이 임의로 제안한 호스트는 승인 목록에 추가되지 않아야 한다. |
| 네트워크 경계 | 기본 런타임은 Caido proxy를 통합한다. Strix의 에이전트와 proxy 도구는 Caido 요청·사이트맵·scope 정보를 활용할 수 있다. | `proxy_backend="mitmproxy"`로 기본 Caido sidecar 대신 AIDAST addon을 표준 proxy 포트에 띄운다. Recon 모드에서는 Caido 도구를 agent tool 목록에서 제외한다. | 현재 MITM addon은 Scope 게이트와 캡처 역할이다. Caido의 GUI, 프로젝트 데이터베이스, 요청 replay/수정 등 모든 기능을 똑같이 제공하는 것은 아니다. |
| HTTP 범위 적용 | Strix 기본 Caido 설정은 Strix runtime의 proxy 통합에 의존한다. | Scope에서 만든 host/path/method/scheme/port 규칙을 mitmproxy가 요청마다 검사한다. 규칙을 읽지 못하면 fail-closed로 차단한다. 명시적으로 금지된 항목만 좁히는 정책을 반영하며, host는 승인 자산에 묶인다. | “명시적 금지만 제한”은 범위 밖으로 무제한 허용한다는 뜻이 아니다. HTTP(S) 요청은 여전히 승인 호스트/경로의 경계 안에 있어야 한다. 임의 TCP 스캔을 허용하는 것도 아니다. |
| 포트와 프로토콜 | Strix 도구의 기능은 실행 환경과 도구 옵션에 따라 다르다. | AIDAST proxy 규칙은 Scope가 포트를 명시적으로 제한하지 않으면 승인 호스트의 HTTP(S) 포트를 허용할 수 있다. 이는 해당 포트 스캔을 자동 수행한다는 뜻은 아니다. HTTP/HTTPS도 Scope에 명시 금지가 있는지에 따라 결정한다. | 허용 정책과 실제 탐색 도구의 실행 범위는 구별해야 한다. |
| 크롤링과 브라우저 | Strix에는 Katana 등 CLI 도구용 skill과 `agent-browser`가 있다. agent-browser는 CDP 기반 Chromium CLI이며 Playwright/Puppeteer를 사용하지 않는다고 skill에 명시돼 있다. | Strix sandbox의 같은 agent-browser를 사용한다. AI-DAST의 이전 Playwright Recon 경로를 Strix Recon 브라우저로 사용하지 않는다. | 현재 Strix Recon의 브라우저는 Playwright가 아니라 agent-browser다. 브라우저 관측 트래픽도 proxy/capture 경계를 따라야 한다. |
| 도구 선택 | Strix에는 `httpx`, `katana`, `ffuf`, `subfinder`, `naabu`, `nuclei` 등 다수 도구 skill이 있다. Skills는 playbook이지 모든 도구를 매 스캔에서 반드시 실행한다는 보장은 아니다. | Strix agent가 사용 가능한 도구 중 증거와 작업에 맞는 것을 고른다. 현재 AIDAST bridge는 기본 skill로 asset discovery, httpx, Katana, agent-browser를 지정하고 OpenAPI/GraphQL skill은 관측 근거가 있을 때 로드하도록 지시한다. | “Strix에 도구가 있다”와 “특정 scan에서 실제 실행됐다”는 다르다. 실행 여부는 Strix 로그와 sandbox 산출물로 확인해야 한다. |
| OpenAPI / GraphQL | Strix는 동적 skill 로딩 구조와 관련 skills를 제공한다. 발견 여부나 명세가 자동으로 모두 endpoint화된다고 단정할 수는 없다. | 현재 prompt는 관측된 OpenAPI/Swagger를 `api_spec_recon` skill로 해석하고 inventory JSON에 정리하도록 한다. GraphQL 근거가 있으면 `graphql` skill에서 endpoint/schema discovery만 사용하도록 지시한다. AIDAST는 OpenAPI inventory를 Scope와 대조해 DB에 반영한다. | 문서에 적힌 operation을 무조건 요청하는 동작이 아니다. API 스펙 발견·파싱과 그 API 호출은 별개다. |
| 로그인·세션 | agent-browser가 browser session을 유지·저장하는 Strix 방식이 있다. 저장 기간과 사용 방식은 sandbox/session 설정에 의존한다. | Strix Recon은 AI-DAST의 `--session-bundle`을 지원하지 않는다. agent-browser 자체 흐름을 사용한다. 계정 등록은 별도 opt-in이며, exact canonical host에 한 계정만 허용하고 가입 성공 후 즉시 로그인·보호 경로 확인을 지시한다. | 기존 AIDAST Playwright 세션 파일을 그대로 넘길 수 있다고 가정하면 안 된다. 로그인 필요 여부와 로그인 성공은 캡처 로그에서 확인해야 한다. |
| LLM 인증 | Strix 기본 문서는 지원 provider의 API key 사용을 안내한다. | 현재 reference 코드에는 Codex 구독 인증 경로가 추가돼 있어 `STRIX_LLM=chatgpt/<model>`과 Strix/Codex 로그인 상태를 사용할 수 있다. | 이것은 OpenRouter API key 사용과 다르다. `reference/strix`는 로컬 수정본이므로 순정 Strix의 모델 인증 방식과 동일하다고 보면 안 된다. |
| 원시 캡처와 DB | Strix는 자체 scan state, agent 상태 및 보고서 산출물을 관리한다. | AIDAST addon이 HTTP exchange를 JSONL로 저장하고, AIDAST importer가 `scans → assets → origins → endpoints`, parameters, observations, HTTP transactions로 적재한다. | 최종 endpoint 개수는 캡처 요청 수와 같지 않다. Scope 필터·정적 자산/중복·정규화·import 실패에 따라 달라진다. |
| Endpoint 정규화 | Strix 자체 endpoint/sitemap 관점과 Strix 리포트가 기준이다. | AIDAST DB는 origin + method + normalized path를 canonical endpoint key로 사용하고 query signature 및 parameter를 별도 저장한다. redirect-loop/경로 fingerprint 후처리도 있다. | AIDAST DB 개수와 Strix UI/보고서의 수가 항상 1:1로 일치한다고 보장할 수 없다. 정규화 정책이 다른 만큼 비교 시 같은 입력·같은 필터 기준이 필요하다. |
| 태깅 | Strix는 finding/보고서 중심이며 AIDAST의 관측 URL 태깅 체계와 동일하지 않다. | Recon 관측을 AIDAST DB에 보존한 뒤 선택적으로 Codex Main Agent가 태깅한다. 태깅 실패는 Recon 저장 성공을 되돌리지 않고 unknown 상태로 남긴다. | 태깅은 Strix endpoint 탐색 엔진과 별도의 AIDAST 후처리다. |
| Attack / Validation | Strix의 본래 scan mode는 취약점 조사와 finding 생성을 포함할 수 있다. | AI-DAST Recon은 `recon_only`로 Strix의 공격 도구·취약점 검증 흐름을 제한한다. Attack, Chaining, Validation은 기존 AIDAST 파이프라인의 별도 단계다. | Strix Recon을 쓴다고 Attack/Validation까지 Strix로 바뀌는 것은 아니다. |

## Scope proxy의 실제 경계

현재 addon은 “관찰만 하는 무제한 프록시”가 아니라 요청을 실제로 허용/차단하는 경계다.

- AIDAST가 승인 Scope에서 proxy 규칙을 생성하고 Strix sandbox에 전달한다.
- Proxy는 규칙을 읽지 못하면 fail-closed 한다.
- 승인 host, 명시적 제외 host/path, HTTP(S) scheme, 포트, method를 요청마다 검사한다.
- method/scheme 제한은 Scope의 명시적 금지 문구를 근거로 적용한다. 단, 승인 host를 벗어나거나 명시적 out-of-scope인 요청은 허용되지 않는다.
- 요청 수 상한은 현재 이 addon에서 정책상 차단 한도로 사용되지 않는다. 이는 Strix 기본 Caido와 기능적으로 완전히 같다는 뜻이 아니라, AI-DAST proxy 경계의 설계가 다르다는 뜻이다.
- Replay/요청 변조/사이트맵 UI 같은 Caido 기능은 MITM addon이 자동으로 대체하지 않는다. 현재 Recon에서는 Caido 도구를 등록하지 않고 캡처 journal을 제공한다.

## 수정된 과거 통합 이슈

2026-10-05 Prism 실행(`scan_30f9563e8f014ffaba08844e2b7391fb`)은 proxy 진단 로그에 캡처 관측 3,275건이 기록됐지만, 해당 scan의 Recon DB에서 asset과 canonical endpoint 연결이 0건이었다. **이것은 이후 수정된 과거 이슈이지 현재 코드의 미해결 결함으로 분류하면 안 된다.** 해당 과거 실행의 DB 숫자가 0으로 남아 있는 것은 당시 기록이므로, 수정 이후 실행 결과와 혼동하지 않는다.

이 사례는 Strix의 도구 성능과 AIDAST importer/Scope 매핑을 별도로 진단해야 했던 이력을 보여준다. 수정 상태를 새 scan으로 검증할 때는 최소한 다음을 함께 기록하는 것이 좋다.

1. Strix agent가 종료 상태와 target별 완료/미완료 사유를 남겼는가.
2. mitmproxy가 캡처한 총 교환 수와 Scope 차단 수는 얼마인가.
3. target coverage의 host별 matched host/request/endpoint 집계가 캡처 내용과 일치하는가.
4. DB에서 scan_id에 연결된 asset, origin, endpoint, parameter, observation 수는 얼마인가.
5. capture-only endpoint 후보, import 후 canonical endpoint, 제외 처리 수의 차이는 무엇인가.

## 결론

AI-DAST에서 Strix가 맡는 핵심은 **Recon 에이전트 런타임과 도구 기반 탐색**이다. AIDAST가 유지하는 핵심은 **프로그램 Scope를 승인 가능한 자산/정책으로 바꾸고, MITM에서 강제하며, 캡처를 기존 DB·태깅·Attack/Validation 파이프라인에 연결하는 것**이다.

그래서 현재 도구는 “Strix와 완전히 동일한 제품”이 아니라 “Strix Recon 엔진 + AIDAST Scope enforcement/proxy capture/DB·후처리” 조합이다. 특히 Caido의 전체 기능을 mitmproxy addon이 대체한다고 말할 수 없고, 캡처 수를 곧바로 DB endpoint 수라고 말할 수도 없다. 성능 비교 시에는 agent 탐색량, proxy 허용량, canonical DB endpoint 수를 별도 지표로 봐야 한다. 2026-10-05의 Prism DB 0건은 수정 전 과거 실행의 상태이며, 이를 현재 상태 설명으로 인용하지 않는다.

## 코드에서 확인할 파일

- `src/aidast/recon/strix_bridge.py` — Strix scan config, Scope proxy rules, registration eligibility, Strix launcher.
- `reference/strix/strix/core/runner.py` — Strix scan/runtime orchestration 및 `recon_only`.
- `reference/strix/strix/runtime/session_manager.py` — sandbox, 기본 Caido와 MITM backend 선택.
- `reference/strix/strix/agents/factory.py` — Strix root/child agent의 Recon 전용 지침과 도구 surface.
- `reference/strix/strix/skills/tooling/agent_browser.md` — Strix agent-browser 사용법 및 Playwright 비의존 설명.
- `src/aidast/recon/tools/mitm_addon.py` — 요청별 Scope 검사 및 캡처 addon.
- `src/aidast/recon/tools/mitm_proxy.py` — mitmdump 실행 및 capture import.
- `src/aidast/recon/db.py` — endpoint/parameter/observation schema, upsert 및 정규화 연결.
- `src/aidast/recon/api_spec_ingestion.py` — LLM OpenAPI inventory의 Scope 검증 및 DB 적재.
- `src/aidast/cli.py` — Recon 실행, 캡처 적재, 진단 집계, Surface export, 선택 태깅.

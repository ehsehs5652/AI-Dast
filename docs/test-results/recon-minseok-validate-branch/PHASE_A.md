# Phase A — 정적 사전 점검

## 판정

**PASS**

최신 HEAD에서 두 로컬 대상의 가용성, 승인 Scope 무결성, 도구 준비 상태와
TargetPolicy 경계를 다시 확인했다.

## 환경

| 항목 | 결과 |
| --- | --- |
| Juice Shop container | running, HTTP 200 3/3, median 9.120 ms |
| VulnBank container | healthy, HTTP 200 3/3, median 9.132 ms |
| VulnBank `/healthz` | `status=ok`, `database=up` |
| VulnBank PostgreSQL | healthy |
| Codex CLI | 0.154.0, ChatGPT login valid |
| Python | 3.13.14 |
| Pydantic | 2.13.4 |
| Playwright | 1.62.0 |
| Katana | 1.7.0 |
| ffuf | 2.1.0-dev |
| mitmproxy | 12.2.3 |

Playwright 1.62.0이 요구하는 Chromium v1234가 최초에 없어서 Phase B 전
정확한 browser와 headless-shell build를 설치했다. 이 설치는 Phase A의 도구
준비 항목으로 기록한다.

## Scope와 Policy

두 기존 fixture는 production `ScopeCoordinator` 검증을 통과했다.

| 대상 | Scope | policy-only 결과 |
| --- | --- | --- |
| Juice Shop | `scope_local_lab_juice_shop` | 완료 |
| VulnBank | `scope_local_lab_vuln_bank` | 완료 |

확인한 공통 경계:

- scheme `http`, host `127.0.0.1`, exact port 3001 또는 5001
- allowed path `/` subtree, wildcard/external host 없음
- Recon method `GET`, `HEAD`, `OPTIONS`
- Attack method는 위 safe method와 명시적으로 승인된 `POST`만 허용
- active mode `active_non_destructive`
- 0.5 RPS, concurrency 1, timeout 15초, depth 2, 최대 500 requests
- form submission false
- Juice Shop GraphQL probe disabled
- VulnBank GraphQL probe는 `/graphql`만 허용

Phase A 실행 시점 TargetPolicy SHA-256:

- Juice Shop: `37ac51eabbe5e9f127c64df059dfa199dfd71f6fa03986ac355087bae0cc833a`
- VulnBank: `1fd957638a5e5a21c7666066e4838fbfa5336c4673eea027e77c45c06d9dde8b`

이 파일들은 후속 Phase에서 각 실행 cap/start URL에 맞게 다시 생성됐으므로 위 값은
Phase A policy-only 실행 시점의 값이다.

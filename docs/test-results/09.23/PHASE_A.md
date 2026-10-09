# Phase A — 로컬 정적 사전 점검 (2026-09-23 KST)

## 판정

**PASS.** 두 대상과 VulnBank DB가 응답했고, 승인 Scope 무결성 및 생성된 TargetPolicy의 경계를 확인했다. 이 단계에서는 Recon 네트워크 도구를 실행하지 않았다.

## 기준 환경

| 항목 | 확인 결과 |
| --- | --- |
| AI DAST | `a97d456156d1c7632b05bd800f61a561e9144ed8`, 브랜치 `refactor/project-organize` |
| Juice Shop | 이미지 digest `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`, 컨테이너 실행 중 |
| VulnBank | 소스 commit `5e5ea5425fcf309373a0655dd111ecfb45037cbf`, 컨테이너 healthy |
| PostgreSQL | 컨테이너 healthy, VulnBank `/healthz`가 `database=up`, `status=ok` 반환 |
| 도구 | Codex CLI `0.155.1` 로그인 유효; mitmdump, Katana, ffuf, Playwright `1.62.0` 및 Python package import 확인 |

`scripts/lab_smoke.py`의 홈페이지 GET은 두 대상 모두 **3/3회 HTTP 200**이었다. 중앙값은 Juice Shop **12.31 ms**, VulnBank **13.425 ms**였다. Playwright Chromium headless 렌더링도 두 대상에서 HTTP 200과 예상 페이지 제목을 확인했다. 이 수치는 가용성 확인이며 탐지 성능을 뜻하지 않는다.

## Scope와 정책

`aidast scope status`에서 두 fixture가 각각 `scope_local_lab_juice_shop`, `scope_local_lab_vuln_bank`로 승인 및 무결성 검사를 통과했다. 다음 명령 형식의 `--policy-only`를 대상별로 실행해 모두 exit 0을 확인했다.

```bash
.venv/bin/python -m aidast recon https://lab.aidast.invalid/<target> \
  --target http://127.0.0.1:<port>/ --start-url http://127.0.0.1:<port>/ \
  --max-rps 0.5 --max-requests 500 --max-depth 2 \
  --max-concurrency 2 --timeout-seconds 15 --login-mode none --policy-only
```

두 `TargetPolicy.json`의 실제 값은 HTTP, `127.0.0.1` 단일 host, 해당 대상의 정확한 port, `/` subtree로 제한됐다. Recon method는 GET/HEAD/OPTIONS, Attack method는 여기에 POST만 추가됐다. PUT/PATCH/DELETE, 외부 host와 wildcard는 허용되지 않았다. 요청 상한 500, RPS 0.5, timeout 15초, depth 2였고 실제 정책 concurrency는 승인 상한 2보다 좁은 **1**이었다. Form submission은 비활성화됐고 GraphQL probe는 Juice Shop에서 꺼졌으며 VulnBank `/graphql`에만 허용됐다.

| 대상 | TargetPolicy SHA-256 | policy-only 결과 |
| --- | --- | --- |
| Juice Shop | `b15e82a388d42bce49af030f3d5755c3284ed4bdb2a22140a0365027f68c64f3` | exit 0 |
| VulnBank | `24cc5c436977ad2737119c9c03251b485d4055199b346cdae4a8b3e9adf9f464` | exit 0 |

## 다음 단계 조건

정책은 계획의 loopback 경계보다 넓지 않다. Phase B의 익명 Recon-only 실행을 진행할 수 있다. 인증 계정 및 반복 평가용 데이터 복원 기준은 Phase C/F에서 별도 확인한다.

# VulnBank·OWASP Juice Shop Phase A 결과

## 결과

Phase A 정적 사전 점검을 2026-09-17 KST에 수행했다. 두 대상 모두 로컬에서 응답했고, 승인 Scope와 TargetPolicy가 무결성 및 경계 검사를 통과했다.

## 환경 식별

| 항목 | 값 |
| --- | --- |
| Phase A 최초 실행 Git HEAD | `15a8ee056f051394a08ac56c61f927e0f171d0a2` |
| 현재 기준 Git HEAD | `497473c983effd548ec845e13c9e7025992b1ed6` (`team/main`, 2026-09-17 재정렬) |
| AI DAST worktree | 로컬 랩·문서와 Scope 재검증 수정이 아직 미커밋 상태 |
| VulnBank source commit | `5e5ea5425fcf309373a0655dd111ecfb45037cbf` |
| Juice Shop image ID | `sha256:d160218b3cc2d7b2fb39c2ee6cb6f032fa62f3efbdb603df5892e67d575a168f` |
| VulnBank image ID | `sha256:3d0122c4433921e8942642ce6ed4d2f375a4d8c69b60e482f29e14c37857f2b2` |
| VulnBank DB image ID | `sha256:62823df8e8db27cab0b4c1333cc33876eeb84cded5229261e0727ee30726e347` |
| Python | 3.14.5 (`result/lab/.venv`) |
| Pydantic | 2.13.4 |
| Codex CLI | 0.154.0, ChatGPT login 유효 |
| 현재 Codex 사용자 설정 | `gpt-5.6-sol`, reasoning effort `medium` (`CODEX_HOME=/Users/lkhlkh0823/.codex1`) |
| 네이티브 Attack·Chaining·Validation 기본 모델 | `gpt-5.6-sol`로 코드에 명시 |
| Phase A Recon·Policy 실제 모델 | 식별자 미기록; CLI 내부 기본값 사용 |
| Playwright | 1.62.0 |
| Katana | 1.7.0 |
| ffuf | 2.1.0-dev |
| mitmproxy | 12.2.3 binary |

## 대상 가용성

| 대상 | Docker 상태 | HTTP 확인 | Browser 확인 |
| --- | --- | --- | --- |
| Juice Shop | running; 별도 container healthcheck 없음 | 홈페이지 3회 모두 200 | Chromium 200, title `OWASP Juice Shop` |
| VulnBank | healthy | 홈페이지 3회 모두 200 | Chromium 200, title `VulnBank - The Modern Banking Platform` |
| VulnBank PostgreSQL | healthy | `/healthz`: `status=ok`, `database=up` | 해당 없음 |

## 도구 준비 상태

- Codex CLI 로그인 확인
- project package import 확인
- Playwright Chromium 설치 및 두 대상 headless rendering 확인
- mitmdump 확인
- Katana 확인
- ffuf 확인
- URL asset을 사용하는 이번 평가에서 Subfinder는 필수 대상이 아님

## 로컬 승인 Scope

`scripts/prepare_local_lab_scopes.py`를 추가해 기존 `ScopeCoordinator`의 draft/publish 경로로 다음 artifact를 생성했다.

```text
result/Scope/lab-aidast-invalid/juice-shop/
├── Scope.json
├── Scope.md
├── Manifest.json
└── Approval.json

result/Scope/lab-aidast-invalid/vuln-bank/
├── Scope.json
├── Scope.md
├── Manifest.json
└── Approval.json
```

두 Scope 모두 `aidast scope status`에서 승인 및 hash 무결성 검사를 통과했다. Approval 파일 mode는 `0600`이다.

| Scope | 승인 canonical asset | 상태 |
| --- | --- | --- |
| `scope_local_lab_juice_shop` | `http://127.0.0.1:3001/` | valid |
| `scope_local_lab_vuln_bank` | `http://127.0.0.1:5001/` | valid |

프로그램 식별 URL인 `https://lab.aidast.invalid/...`는 artifact 경로 계산에만 사용하며 네트워크 접근 대상이 아니다.

## Policy-only 결과

두 대상 모두 `aidast recon ... --policy-only`를 완료했다. 실제 Recon 도구와 대상 네트워크 테스트는 실행하지 않았다.

### 공통 경계

| 필드 | 적용값 |
| --- | --- |
| host | `127.0.0.1`만 허용 |
| path | `/` subtree |
| Recon methods | GET, HEAD, OPTIONS |
| Attack methods | GET, HEAD, OPTIONS, POST |
| Attack mode | `active_non_destructive` |
| RPS | 0.5 |
| concurrency | 1 |
| timeout | 15초 |
| max depth | 2 |
| max requests | 500 |
| form submission | false |
| external/wildcard host | 없음 |

Scope와 CLI에서 지정한 concurrency 상한은 2였고 생성 정책은 더 보수적인 1을 적용했다. 범위를 넓히지 않으며 두 대상에 동일하게 적용됐으므로 Phase B에서는 1을 실제 baseline으로 사용한다.

### 대상별 경계

| 대상 | scheme | port | GraphQL probe |
| --- | --- | ---: | --- |
| Juice Shop | HTTP | 3001 | disabled |
| VulnBank | HTTP | 5001 | `/graphql`만 enabled |

정책 boundary assertion을 별도로 실행해 exact scheme, host, port, path, methods, limit, form submission과 GraphQL 경로를 확인했다.

TargetPolicy SHA-256:

- Juice Shop: `9ca59afecc05099a1c7bf937178004b4085c24f30d41ff536da297b0925e6fc9`
- VulnBank: `d4957998b81320205696b148631e3309df2cac509ee6563ad3c4a32c0349847c`

## 발견 및 수정한 blocker

첫 Juice Shop policy-only 실행에서 active POST 정책의 재검증이 실패했다.

원인은 `_apply_scope_host_exclusions()`가 host exclusion 적용 후 `validate_policy_for_target()`을 다시 호출하면서 `scope_markdown`을 전달하지 않은 것이었다. active authorization evidence는 Allowed activities 원문을 요구하므로, 근거가 존재해도 두 번째 검증에서 항상 거부됐다.

수정 내용:

- `_apply_scope_host_exclusions()`가 `scope_markdown`을 받도록 변경
- `_run_recon()`에서 승인된 Scope Markdown 전달
- active grant가 host exclusion 재검증을 통과하는 regression test 추가

검증 결과:

```text
tests/test_recon_policy.py: 24 passed
```

수정 후 두 대상의 policy-only가 완료됐다.

이후 저장소 기준을 `team/main`으로 재정렬하고 같은 수정을 다시 적용했다. 새 기준에서도 `tests/test_recon_policy.py` 24개가 모두 통과했고, 기존 로컬 Scope 두 개의 무결성 검증도 다시 통과했다.

## 남은 사전 조건

Phase B Recon-only 진행을 막는 항목은 없다. 다음 항목은 Phase C 또는 반복 평가 전에 처리한다.

1. Git 기준은 `team/main`으로 맞췄지만 랩·문서·재검증 수정은 미커밋이므로 benchmark 반복 전에 별도 commit으로 평가 상태를 고정한다.
2. 현재 사용자 설정과 네이티브 파이프라인 기본값은 `gpt-5.6-sol`이다. 다만 Recon 계획·정책 생성 경로는 `codex exec --ignore-user-config`를 사용하면서 `--model`을 전달하지 않는다. 따라서 Phase A 당시 실제 모델은 사후 확인할 수 없으며, 반복 비교 전에 이 경로도 `gpt-5.6-sol`을 명시적으로 전달하고 실행 산출물에 기록해야 한다.
3. VulnBank 다중 identity credential 전달 가능 여부는 Phase C에서 확인한다.
4. 대상별 ground truth의 `ELIGIBLE` 목록은 통합 탐지 정확도 계산 전에 확정한다.

## Phase A 체크리스트

- [x] 두 Docker 대상과 VulnBank DB가 healthy 또는 HTTP 정상이다.
- [x] 대상 image ID와 source commit을 기록했다.
- [x] Codex CLI 로그인이 유효하다.
- [x] Playwright Chromium, mitmdump, Katana와 ffuf가 준비됐다.
- [x] 두 로컬 Scope fixture가 승인·무결성 검사를 통과했다.
- [x] 두 대상의 policy-only가 완료됐다.
- [x] loopback, exact port와 method 경계를 검사했다.
- [x] 실제 대상 Recon/Attack 요청은 아직 실행하지 않았다.
- [ ] 반복 평가용 AI DAST source baseline 고정
- [ ] 반복 평가용 Codex model 식별자 고정

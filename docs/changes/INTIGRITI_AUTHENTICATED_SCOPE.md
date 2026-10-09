# Intigriti authenticated Scope collection

## 목적

인증이 필요한 Intigriti researcher 프로그램 페이지를 다른 수집 도구로
우회하지 않고 `aidast scope` 안에서 수집할 수 있게 한다. Scope가 완전하게
수집되고 운영자가 승인되기 전에는 Recon 또는 대상 자산 요청을 허용하지 않는다.

## 변경 기록

### 1. Runtime browser 기반 프로그램 로그인 추가

- `aidast scope`에 `--login-mode native|runtime-browser`를 추가했다.
- `--login-mode runtime-browser`는 Playwright persistent Chromium을 화면에 열고,
  운영자가 프로그램 플랫폼 로그인과 MFA를 직접 완료하도록 한다.
- `--identity`로 플랫폼 계정별 브라우저 프로필을 분리한다.
- 로그인 후 정확히 요청한 프로그램 URL로 돌아오지 않으면 캡처를 거부한다.

### 2. 세션 저장 경계

- 프로필은 저장소 밖의
  `~/.local/share/aidast/scope-sessions/<binding-hash>/`에 저장한다.
- binding hash는 프로그램 플랫폼 origin과 identity로 계산한다.
- 세션 디렉터리는 `0700`, 메타데이터는 `0600`을 시도한다.
- 심볼릭 링크 세션 디렉터리는 거부한다.
- `Session.json`에는 origin과 identity 결합 정보만 저장한다. 실제 쿠키와 토큰은
  브라우저 프로필 내부에 남으므로 절대 공유하거나 Git에 추가하면 안 된다.

### 3. 캡처와 해석 분리

- 인증 브라우저는 프로그램 페이지의 화면 텍스트만 캡처한다.
- Codex는 브라우저 권한 없이 캡처된 텍스트를 구조화된 Scope로 해석한다.
- 기존 source quote grounding과 완전성 검증은 그대로 유지한다.

### 4. 차단 진단 개선

- 기존의 일반적인 `program page access was blocked` 오류에
  `AUTHENTICATION_REQUIRED`, `ACCESS_DENIED`, `BOT_CHALLENGE`,
  `CONTENT_INCOMPLETE` 등의 실제 capture reason을 포함하도록 변경했다.
- `log in to continue`와 `sign in to continue` 화면을
  `AUTHENTICATION_REQUIRED`로 분류한다.

### 5. 로그인 흐름 안정성

- 최초 자동 이동이 타임아웃되어도 브라우저를 닫지 않고 운영자가 열린 창에서
  정확한 프로그램 URL로 직접 이동할 수 있게 했다.
- Enter 이후에는 동일 origin만이 아니라 정확한 program path까지 확인한다.

### 6. Adobe Public aidast-only 운영 가이드

- `docs/guides/INTIGRITI_ADOBE_PUBLIC_AIDAST_ONLY.md`를 추가했다.
- 프로그램 URL, 출력 경로, identity, 허용 명령, 직접 사용 금지 도구,
  단계별 실행 게이트, 실패 시 중단 조건, GitHub 비밀정보 제외 규칙을 기록했다.

### 7. Intigriti Sign in 무한 로딩 수정

- 증상: runtime browser에서 `Sign in`을 누르면 인증 페이지가 계속 로딩됐다.
- 원인: 로그인 단계부터 Playwright route handler가 모든 인증·정적 리소스 요청을
  동기 검사했다. 외부 IdP와 SPA 리소스가 많은 Intigriti 로그인 흐름에 이 정책을
  적용한 것이 병목 또는 차단 조건이 됐다.
- 수정: 운영자가 직접 제어하는 로그인/MFA 구간에는 자동 request route를 설치하지
  않는다.
- Enter 이후에는 자동 탭 클릭이나 추가 navigation을 하지 않고, 운영자가 연 정확한
  program origin/path의 현재 DOM만 읽는다.
- 보안 경계: URL exact-match, 완전성 판정, source quote grounding, 사람의 Scope 승인
  요구는 그대로 유지한다.

### 8. Intigriti canonical program path 처리

- 로그인 성공 후 Intigriti가
  `/researcher/programs/<company>/<program>/detail`을
  `/programs/<company>/<program>/detail`로 canonicalize하는 흐름을 허용했다.
- company, program slug, `detail` suffix는 정확히 일치해야 한다.
- 동일 프로그램의 nested view만 허용하며 다른 프로그램 slug는 계속 거부한다.
- URL 불일치 오류에는 query와 fragment를 제외한 same-origin path만 표시해 진단성을
  높였다.

### 9. SPA body 준비 지연 처리

- 증상: canonical URL 검증 후 `Locator.inner_text`가 5초 timeout으로 실패했다.
- 원인: Intigriti SPA URL은 준비됐지만 body DOM이 아직 읽을 수 없는 짧은 구간이
  있었다. 재실행 직후 너무 일찍 캡처를 시작하면 이 구간과 겹쳤다.
- 수정: 개별 body 읽기 timeout은 일시적인 상태로 처리하고 전체
  `--page-timeout` 안에서 다시 시도한다.
- 전체 시간 동안 읽을 수 있는 본문이 없으면 기존처럼 캡처 실패로 종료한다.

### 10. 중앙 결과 루트 지원

- `AIDAST_RESULT_ROOT` 환경변수로 기본 Scope, Recon DB/Surface, Runs, Attack,
  Validation, Report 산출물 루트를 지정할 수 있게 했다.
- 환경변수가 없으면 기존 `result/` 기본값을 유지한다.
- Adobe Public 가이드의 실행 경로 예시는 특정 사용자의 홈 디렉터리를 노출하지
  않도록 `$HOME/aidast-results`를 사용한다.
- 기존 승인 Scope는 새 결과 루트의 `Scope/` 아래로 이동한다.

### 11. Intigriti Recon 요청 식별

- `recon`과 통합 `run`에 `--intigriti-username`을 추가했다.
- HTTP Probe, Playwright, Katana, ffuf, API 2차 탐색의 승인된 타깃 요청에
  `X-Intigriti-Username`과 Intigriti User-Agent 접미사를 주입한다.
- 외부 정적 리소스에는 연구자 식별 헤더를 전달하지 않는다.
- Scope가 `X-Intigriti-Username`을 요구하면 사용자명 없는 능동 Recon을
  fail-closed한다.
- 저장 증거에서는 사용자명과 User-Agent의 Intigriti 접미사를 가린다.

### 12. 스킴 없는 URL 자산의 HTTPS 정규화

- 증상: Intigriti가 `stock.adobe.com`처럼 스킴 없는 값을 `URL` 타입으로 제공하면
  Recon 정책 검증이 `asset type cannot be executed as a web target: URL`로
  중단됐다.
- 원인: URL 정책 검증이 모든 `URL`/`API` 자산에 `https://` 또는 `http://`가 이미
  포함되어 있다고 가정했다.
- 수정: 스킴 없는 `URL`/`API` 자산만 `https://<asset>`으로 해석한다. 명시적인
  HTTP(S) URL은 기존 스킴, 포트, 경로 제한을 그대로 보존한다.
- 보안 경계: 기본값은 HTTPS/443이며 HTTP로의 완화, 다른 호스트, 다른 포트 또는
  승인 경로 밖으로의 확장은 계속 거부한다. 원본 `Scope.json`과 승인 무결성 파일은
  수정하지 않는다.

## 사용법

```bash
export AIDAST_RESULT_ROOT="${AIDAST_RESULT_ROOT:-$HOME/aidast-results}"

aidast scope \
  "https://app.intigriti.com/researcher/programs/adobe/adobepublic/detail" \
  --output-dir "$AIDAST_RESULT_ROOT/Scope/intigriti-adobe-public" \
  --by "<REVIEWER>" \
  --login-mode runtime-browser \
  --identity "<ACCOUNT_LABEL>" \
  --page-timeout 120 \
  --codex-timeout 300
```

1. 열린 Chromium에서 Intigriti 로그인과 MFA를 완료한다.
2. 명령에 입력한 정확한 프로그램 상세 URL로 돌아간다.
3. 가능하면 프로그램의 Scope/자산 화면을 연다.
4. 터미널에서 Enter를 누른다.
5. 임시 `Scope.md`를 원본 페이지와 대조한 뒤 승인한다.

## 보안 및 운영 제한

- 로그인 중 외부 IdP 페이지를 여는 것은 운영자 수동 동작으로만 허용한다.
- 자동 캡처는 Enter 이후 정확한 프로그램 URL과 일치하는 탭에서만 수행한다.
- 프로그램 페이지의 링크로 발견한 Adobe 자산은 Scope를 자동 확장하지 않는다.
- 캡처가 partial 또는 blocked이면 `Scope.md`를 생성하지 않는다.
- 세션 프로필, 쿠키, 토큰은 변경 문서나 진단 로그에 기록하지 않는다.

## GitHub 검토 체크리스트

- [ ] CLI 도움말에 새 옵션이 표시되는지 확인
- [ ] native 모드의 기존 공개 프로그램 수집이 유지되는지 확인
- [ ] runtime-browser가 identity별 프로필을 분리하는지 확인
- [ ] 다른 프로그램 URL 또는 로그인 페이지에서 Enter 시 실패하는지 확인
- [ ] blocked 오류에 capture reason이 포함되는지 확인
- [ ] Scope 승인 전 Recon이 시작되지 않는지 확인
- [ ] 세션 파일이 Git 변경 목록에 나타나지 않는지 확인
- [ ] 단위 테스트와 전체 테스트 결과 기록

## 테스트 결과

- `python -m compileall -q src/aidast`: 통과
- Scope/Auth 집중 테스트: `33 passed, 3 subtests passed`
- 전체 회귀 테스트를 macOS 기본 임시 경로에서 실행하면 `/var/folders`가
  `/private/var/folders`로 해석되는 기존 symlink 경계 때문에 61개가 실패한다.
  이번 변경 파일과 무관한 기존 테스트 환경 문제다.
- 실제 경로인 `TMPDIR=/private/tmp`에서 전체 회귀 테스트:
  `538 passed, 1 skipped, 170 subtests passed`, Unix socket이 금지된 샌드박스에서
  helper broker 관련 3개만 실패했다.
- 위 helper broker 3개를 정상 권한 환경에서 재실행: `3 passed`.
- 개발 venv와 설치된 `aidast` 환경 모두 Playwright Chromium 실행 파일 존재 확인.
- `git diff --check`: 통과.
- bare-host URL 정책 집중 테스트: `27 passed`.
- Recon 정책·워크플로 회귀 테스트: `74 passed, 16 subtests passed`.
- Adobe Scope의 스킴 없는 URL 자산 17개를 HTTPS 정책으로 검증: 모두 통과.
- `stock.adobe.com` 실제 `aidast recon --policy-only` 검증: HTTPS, 포트 443,
  경로 `/`로 정책 생성 완료. Recon 네트워크 도구는 실행하지 않음.

## 아직 필요한 수동 검증

- 실제 Intigriti 로그인/MFA 후 Adobe Public 프로그램 화면 캡처
- 생성된 임시 Scope의 source quote와 플랫폼 원문 대조
- 승인 후 `aidast scope status` 무결성 확인

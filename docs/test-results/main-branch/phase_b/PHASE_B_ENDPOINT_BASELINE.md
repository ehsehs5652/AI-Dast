# Phase B application endpoint 평가 기준 및 수집률

## 산정 기준

이 문서는 다음 고정 버전의 소스 route 선언을 Phase B 재실행 결과와 비교한다.

| 대상 | 기준 버전 | Recon DB |
| --- | --- | --- |
| OWASP Juice Shop | 20.2.0, image digest `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` | `result/test-runs/phase-b-rerun/attempt-2/juice-shop/Recon.db` |
| VulnBank | commit `5e5ea5425fcf309373a0655dd111ecfb45037cbf` | `result/test-runs/phase-b-rerun/attempt-2/vuln-bank/Recon.db` |

endpoint 식별자는 `HTTP method + path template`이다. 비교 전에 다음과 같이 정규화했다.

- trailing slash 제거 (`/` 자체는 유지)
- Flask converter 제거: `<int:user_id>` → `:user_id`
- Express parameter 유지: `:id`
- concrete path segment는 해당 template parameter 한 칸과 일치
- method는 대소문자를 정규화한 뒤 엄격히 일치

Phase B 정책은 GET/HEAD/OPTIONS를 허용한다. HEAD는 GET에서 자동 파생되고 OPTIONS는 global/wildcard 처리가 포함되어 별도 business resource 수로 보지 않았으므로, source-declared GET route만 수집률 분모로 사용했다.

정적 asset, Swagger UI 내부 모듈, Socket.IO transport, generic static/middleware mount와 ffuf candidate는 application route 기준 목록에서 제외했다.

Juice Shop은 `server.js`의 명시적 Express verb route, `finale.resource`가 생성하는 GET list/read route, `/dataerasure` router GET과 Angular 진입점 `/`을 포함했다.

VulnBank는 고정 commit의 Flask `@app.route` 선언을 사용했다.

## 정확성 및 범위

71개와 47개는 서버가 응답할 수 있는 모든 URL의 절대 개수가 아니라, 위 규칙으로 확정한 application GET route의 평가 기준 개수다. 다음 runtime 교차 검증을 수행했다.

- Juice Shop의 별도 in-memory app에서 Express route stack을 조회한 결과 unique top-level GET route는 69개였다. 여기에 mounted `/dataerasure` GET 1개와 Angular 진입점 `/` 1개를 포함해 71개로 확정했다.
- VulnBank 실행 컨테이너의 Flask `url_map`에는 GET rule 51개가 등록되어 있었다. `/static/<path:filename>`과 Swagger UI 지원 rule 3개를 제외하면 application GET route는 47개로 정적 추출 결과와 일치했다.

Juice Shop은 Angular catch-all과 static middleware가 임의의 path 또는 파일을 처리하고, VulnBank도 static path rule을 가진다.

따라서 지원 파일과 catch-all URL까지 포함한 “모든 응답 가능 URL 수”는 단일한 유한 endpoint 개수로 표현하지 않는다. 본 수집률은 명시적인 application route pattern만 비교한다.

### 전체 runtime route pattern 집계

실행 중 framework router에 명시적으로 등록된 유한 route pattern은 별도로 다음과 같이 집계했다.

| 대상 | unique path pattern | unique method + path pattern | method별 pattern |
| --- | ---: | ---: | --- |
| Juice Shop | 95 | 144 | GET 71, POST 36, PUT 21, PATCH 1, DELETE 14, OPTIONS 1 |
| VulnBank | 78 | 83 | GET 51, POST 32 |

Juice Shop 값은 별도 in-memory app의 Express top-level 및 nested router stack을 합쳐 중복 제거했다. VulnBank 값은 실행 컨테이너의 Flask `url_map`에서 자동 파생되는 HEAD와 OPTIONS를 제외하고 중복 제거했다.

이 표에도 static middleware가 제공하는 개별 파일, Angular catch-all이 받을 수 있는 임의 path, Socket.IO transport URL, query string 조합과 `:id` 같은 parameter의 concrete 값은 포함되지 않는다. 이들을 전부 펼친 concrete URL 총수는 고정된 유한 숫자가 아니므로, 평가에는 route pattern 개수를 사용한다.

### 공식 문서 교차 확인

공식 웹 문서와 저장소에는 애플리케이션 전체의 `method + path` 총계를 명시한 집계값이 없다.

- OWASP Juice Shop 공식 가이드는 generated API, hand-written middleware와 third-party middleware라는 route 구성 방식 및 자동 생성 대상 모델을 설명하지만 전체 operation 수는 제시하지 않는다.
- Juice Shop 20.2.0 이미지의 공식 `swagger.yml`은 `NextGen B2B API` 한 path·한 operation(`POST /orders`, 실제 mount는 `/b2b/v2`)만 기술하므로 전체 endpoint 명세가 아니다.
- VulnBank 공식 README는 `/api/docs`를 안내하지만 총계를 제시하지 않는다. 고정 commit의 `static/openapi.json`에는 39 path·39 operation(GET 19, POST 20)만 있으며, runtime의 83개 method/path pattern 전체를 포함하지 않는다.

따라서 공식 문서는 route 존재와 구조를 교차 확인하는 보조 근거로 사용하고, 이 평가의 전체 method/path pattern 총계는 고정 버전 runtime router dump를 기준으로 한다.

## 요약

| 대상 | 평가 기준 application GET route | 수집 route | 누락 route | 수집률 |
| --- | ---: | ---: | ---: | ---: |
| Juice Shop | 71 | 7 | 64 | 9.9% |
| VulnBank | 47 | 11 | 36 | 23.4% |
| 합계 | 118 | 18 | 100 | 15.3% |

전체 수집률은 대상별 비율의 단순 평균이 아니라 `18 / 118 × 100`으로 계산했다.

## Juice Shop

### 수집 7개

```text
GET /
GET /api/Challenges
GET /api/Quantitys
GET /rest/admin/application-configuration
GET /rest/admin/application-version
GET /rest/languages
GET /rest/products/search
```

### 누락 64개

```text
GET /.well-known/security.txt
GET /api/Addresss
GET /api/Addresss/:id
GET /api/BasketItems
GET /api/BasketItems/:id
GET /api/Cards
GET /api/Cards/:id
GET /api/Challenges/:id
GET /api/Complaints
GET /api/Complaints/:id
GET /api/Deliverys
GET /api/Deliverys/:id
GET /api/Feedbacks
GET /api/Feedbacks/:id
GET /api/Hints
GET /api/Hints/:id
GET /api/PrivacyRequests
GET /api/PrivacyRequests/:id
GET /api/Products
GET /api/Products/:id
GET /api/Quantitys/:id
GET /api/Recycles
GET /api/Recycles/:id
GET /api/SecurityAnswers
GET /api/SecurityAnswers/:id
GET /api/SecurityQuestions
GET /api/SecurityQuestions/:id
GET /api/Users
GET /api/Users/:id
GET /dataerasure
GET /metrics
GET /profile
GET /promotion
GET /redirect
GET /rest/2fa/status
GET /rest/basket/:id
GET /rest/captcha
GET /rest/continue-code
GET /rest/continue-code-findIt
GET /rest/continue-code-fixIt
GET /rest/country-mapping
GET /rest/deluxe-membership
GET /rest/image-captcha
GET /rest/memories
GET /rest/order-history
GET /rest/order-history/orders
GET /rest/products/:id/reviews
GET /rest/repeat-notification
GET /rest/saveLoginIp
GET /rest/track-order/:id
GET /rest/user/authentication-details
GET /rest/user/change-password
GET /rest/user/security-question
GET /rest/user/whoami
GET /rest/wallet/balance
GET /rest/web3/nftMintListen
GET /rest/web3/nftUnlocked
GET /security.txt
GET /snippets/:challenge
GET /snippets/fixes/:key
GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg
GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us
GET /video
GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility
```

## VulnBank

### 수집 11개

```text
GET /
GET /blog
GET /careers
GET /compliance
GET /forgot-password
GET /login
GET /merchant/login
GET /merchant/register
GET /privacy
GET /register
GET /terms
```

### 누락 36개

```text
GET /api/ai/rate-limit-status
GET /api/ai/system-info
GET /api/bill-categories
GET /api/bill-payments/history
GET /api/billers/by-category/:category_id
GET /api/check_balance
GET /api/transactions
GET /api/v1/merchants/me
GET /api/v1/payments
GET /api/v1/payments/:payment_id
GET /api/v1/payments/merchant_id/:merchant_id
GET /api/v3/user/:user_id
GET /api/virtual-cards
GET /api/virtual-cards/:card_id/transactions
GET /check_balance/:account_number
GET /dashboard
GET /debug/users
GET /graphql
GET /healthz
GET /internal/config.json
GET /internal/secret
GET /latest/meta-data
GET /latest/meta-data/ami-id
GET /latest/meta-data/hostname
GET /latest/meta-data/iam
GET /latest/meta-data/iam/security-credentials
GET /latest/meta-data/iam/security-credentials/vulnbank-role
GET /latest/meta-data/instance-id
GET /latest/meta-data/local-ipv4
GET /latest/meta-data/public-ipv4
GET /latest/meta-data/security-groups
GET /merchant
GET /merchant/dashboard
GET /reset-password
GET /sup3r_s3cr3t_admin
GET /transactions/:account_number
```

## 해석 제한

- 이 수집률은 취약점 탐지율이나 finding recall이 아니다.
- 인증 없이 실행된 Phase B이므로 인증 뒤에만 링크되는 route는 동적 crawler가 발견하기 어렵다.
- parameter route는 concrete URL이 한 번이라도 수집된 경우에만 hit가 된다.
- Juice Shop의 Angular frontend bundle을 정적으로 분석해 API 문자열을 추출하는 기능은 이번 Recon에 포함되지 않았다.
- VulnBank의 OpenAPI 문서는 schema 오류로 ZAP import에 실패했으므로 OpenAPI 기반 route 보강이 이루어지지 않았다.

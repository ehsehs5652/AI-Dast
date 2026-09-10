# Scope: Shopify Bug Bounty

> Source: https://www.shopify.com/bugbounty/criteria
> Captured at: 2026-09-09T09:00:02.900812+00:00
> Scope ID: `scope_259f7f38b03743e1bf7cdd52d3c8b6c6`

## Program summary

Shopify의 취약점 신고 프로그램으로, 해당 페이지는 자산 범위, 부적격 취약점 및 참여 규칙을 설명한다. 출처: \[Criteria \| Shopify Bug Bounty\](https://www.shopify.com/bugbounty/criteria). captured\_text에는 자산 표와 짧은 규칙 발췌를 수록했다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Authentication &amp; ATO | 범위에 포함되지만 구체적인 대상은 명시되지 않음 | 명시되지 않음 | Non-Core 인증 및 계정 탈취 범주 |
| WILDCARD | \*.pci.shopifyinc.com | 프로그램 규칙 적용 | 명시되지 않음 | Core |
| WILDCARD | \*.shopifycs.com | 프로그램 규칙 적용 | 명시되지 않음 | Non-Core |
| SOURCE\_CODE | https://github.com/Shopify/\* | 프로그램 규칙 적용 | 명시되지 않음 | Non-Core 소스 코드 범위 |
| DOMAIN | admin.shopify.com | 프로그램 규칙 적용 | 명시되지 않음 | Core |
| DOMAIN | arrive-server.shopifycloud.com | 프로그램 규칙 적용 | 명시되지 않음 | Core |
| DOMAIN | shopify.plus | 프로그램 규칙 적용 | 명시되지 않음 | Core |
| DOMAIN | shop.app | 프로그램 규칙 적용 | 명시되지 않음 | Core |
| DOMAIN | shopifyinbox.com | 프로그램 규칙 적용 | 명시되지 않음 | Non-Core |
| DOMAIN | linkpop.com | 프로그램 규칙 적용 | 명시되지 않음 | Non-Core |
| WILDCARD | \*.shopifycloud.com | 명시적인 제외 자산과 프로그램 규칙 적용 | 명시되지 않음 | Non-Core |
| WILDCARD | \*.shopifykloud.com | 프로그램 규칙 적용 | 명시되지 않음 | Non-Core |
| MOBILE\_APP | Shopify Mobile Applications | 모바일 관련 부적격 항목 적용 | 명시되지 않음 | Non-Core 모바일 애플리케이션 범주 |
| OTHER | Shopify Developed Apps | 프로그램 규칙 적용 | 명시되지 않음 | Non-Core Shopify 개발 애플리케이션 범주 |
| WILDCARD | \*.shopify.com | 명시적인 제외 자산과 프로그램 규칙 적용 | 명시되지 않음 | Non-Core |
| WILDCARD | \*.shopify.io | 프로그램 규칙 적용 | 명시되지 않음 | Non-Core |
| OTHER | Shopify Third Party Store | 표에는 포함되지만 자신이 만들지 않은 상점과의 상호작용 금지 규칙이 적용됨 | 명시되지 않음 | Non-Core 제삼자 상점 범주 |
| OTHER | Shopify Third Party Apps | 표에는 포함되지만 보상 대상이 아니며 Informative 처리 | 명시되지 않음 | Non-Core 제삼자 애플리케이션 범주 |
| DOMAIN | accounts.shopify.com | 프로그램 규칙 적용 | 명시되지 않음 | Core |
| DOMAIN | partners.shopify.com | 프로그램 규칙 적용 | 명시되지 않음 | Core |
| DOMAIN | your-store.myshopify.com | 지정된 HackerOne 이메일로 직접 생성한 상점만 테스트 | 명시되지 않음 | Core 테스트 상점 표기 |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| DOMAIN | community.shopify.dev | 명시적 제외 | 해당 없음 | Non-Core |
| DOMAIN | academy.shopify.com | 명시적 제외 | 해당 없음 | Non-Core |
| DOMAIN | supplier-portal.shopifycloud.com | 명시적 제외 | 해당 없음 | Non-Core |
| DOMAIN | community.shopify.com | 명시적 제외 | 해당 없음 | Non-Core |
| DOMAIN | livechat.shopify.com | 명시적 제외 | 해당 없음 | Non-Core |
| DOMAIN | cdn.shopify.com | 명시적 제외 | 해당 없음 | Non-Core |
| WILDCARD | \*.email.shopify.com | 명시적 제외 | 해당 없음 | Non-Core |
| DOMAIN | investors.shopify.com | 명시적 제외 | 해당 없음 | Non-Core |
| OTHER | Other | 명시적 제외 | 해당 없음 | Non-Core 기타 범주 |

## Allowed activities

- 지정된 HackerOne 이메일로 직접 만든 상점에서 프로그램 규칙에 따라 테스트한다.
- GraphQL introspection은 조사 자료로 활용할 수 있다.

## Prohibited activities

- 직접 만들지 않은 상점 접근·상호작용, Shopify Support 대상 테스트·사전 검증·진행 문의를 금지한다.
- 해결 전 또는 허락 없는 공개, 위법 행위, 타인 데이터의 중단·침해를 금지한다.

## Submission requirements

- 취약점을 검증하면 즉시 신고하고 모든 신고 규칙을 준수한다.
- 제삼자 앱은 개발자에게 먼저 신고한다. 일주일간 답변이 없으면 앱·개발자 이름, URL, 취약점, 재현 단계, 영향과 심각도를 포함해 Shopify에 신고할 수 있으나 보상은 없다.
- 제출물은 권리를 보유한 원본이어야 하며, 저작인격권 포기와 MIT License 조건이 적용된다.

## Operational constraints

- 보상 참여자는 Shopify 직원이 아니어야 한다. Shopify는 규칙 변경, 제출 무효화, 프로그램 취소 및 보상 여부를 결정할 수 있다.
- DDoS, 사회공학, 단순 HTTP/DNS SSRF, GraphQL introspection, 비밀번호 강도 및 CVV 검증 신고는 부적격이다.
- 일부 XSS·CSRF, 의도된 CDN 동작, 상점의 알려진 오탐 및 모바일 관련 항목은 제외된다. 리디렉션·이메일 HTML 삽입은 영향 있는 취약점 연계가 필요하다.
- 직원 권한 문제는 민감 권한 상승, 직접적인 재정 영향 또는 미승인 구매자 개인정보 영향을 평가한다. 경쟁 조건은 악용 가능성과 민감정보 접근을 요구한다.

## Safe harbor

열람한 페이지에는 명시적인 법적 면책 약속이 없다.

## Ambiguities requiring review

- 제삼자 상점의 범위 포함 표기와 본인 생성 상점만 테스트하라는 규칙의 관계가 불명확하다.
- 제삼자 앱은 범위 표에 포함되지만 보상 제외이다.
- 범주형 자산의 구체적인 식별자, 최대 심각도 및 요청 속도 제한은 명시되지 않았다.
- 외부 HackerOne 부적격 지침은 참조되지만 열람하지 않았다.
- 저작권상 발췌 제한으로 captured\_text에는 전체 규칙과 세부 예외를 재현하지 않았다. COMPLETE는 페이지 접근과 필수 섹션 가용성을 의미한다.

## Source evidence

- **Eligibility for Rewards:** “Only test against stores you created using your HackerOne YOURHANDLE @ wearehackerone.com registered email.”
- **Domains in scope:** “Shopify Third Party Apps \| In Scope \| Non-Core”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.

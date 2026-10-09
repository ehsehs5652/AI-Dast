# Deterministic Attack Template Runner

## 목적

Attack Agent가 동일 endpoint에 대해 매번 payload와 요청을 새로 작성하는
경로를 점진적으로 줄인다. Hunt Skill은 적용 여부와 결과 해석을 담당하고,
YAML 템플릿과 Python Runner가 payload, 요청 변형, matcher, evidence 규칙을
소유한다.

## 첫 수직 기능

- Skill: `hunt-xss`
- Template: `reflected-xss-basic`
- 지원 입력: `GET` query parameter
- payload: 고정된 2개 variant와 실행 context에서 파생된 결정론적 marker
- matcher: response body marker 반사 및 HTML Content-Type
- 결과: `candidate` 또는 `negative`; 템플릿은 finding을 직접 확정하지 않음
- transport: 기존 `guarded_request` 경계를 그대로 사용하여 Scope,
  TargetPolicy, 요청 예산, 속도, 동시성, 승인 규칙을 우회하지 않음

## 기존 경로와의 비교

| 항목 | 기존 direct probe | Template probe |
| --- | --- | --- |
| payload 선택 | Attack Agent | 버전된 YAML |
| 요청 변형 | Attack Agent | Python Runner |
| endpoint/parameter 선택 | Attack Agent | Attack Agent |
| Scope/Policy 강제 | `guarded_request` | 같은 `guarded_request` |
| matcher | Attack Agent | Python Runner |
| 최종 판정 | Attack/Validation | Attack/Validation |
| 동일 입력 재현성 | 모델 출력에 의존 | 동일 request plan 보장 |

Direct probe는 아직 템플릿으로 표현하지 못한 workflow의 fallback으로 유지한다.

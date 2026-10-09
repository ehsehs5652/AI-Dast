# Current branch Phase A~E evaluation

## 기준

| 항목 | 값 |
| --- | --- |
| 실행일 | 2026-09-18 KST |
| 브랜치 | `feat/recon_minseok_validate` |
| Git HEAD | `f54af467909b751d2424330a38f1ff819b670e89` |
| Juice Shop | `http://127.0.0.1:3001/`, image digest `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` |
| VulnBank | `http://127.0.0.1:5001/`, source `5e5ea5425fcf309373a0655dd111ecfb45037cbf` |
| 공통 실행 경계 | loopback only, 0.5 RPS, concurrency 1, timeout 15초, max depth 2, 최대 500 requests |

이 결과 세트는 기존 2026-09-17~18 평가와 섞지 않고
`docs/test-results/current-branch-f54af46/` 및
`result/test-runs/current-branch-f54af46/` 아래에 분리했다.

## 요약

| Phase | 판정 | 핵심 결과 |
| --- | --- | --- |
| A | PASS | 서비스 health, 도구, Scope 무결성, exact TargetPolicy 경계를 확인했다. |
| B | PASS | 최종 attempt에서 두 anonymous Recon이 `completed`, tagging 실패 0으로 끝났다. |
| C | PASS | Juice Shop primary와 VulnBank primary/secondary 인증 Surface를 현재 브랜치에서 재수집했다. |
| D | PASS | 두 대상 모두 Recon, Attack, Chaining, Validation stage가 `completed`였다. |
| E | PARTIAL | finding ground-truth 판정은 완료했지만 Validation 3건이 모두 `INCONCLUSIVE`여서 Report gate가 초안을 거부했다. |

전체 pipeline 실행 경로는 동작했다. 다만 Phase E의 로컬 Report 생성까지 통과했다고
판정할 수는 없다. 현재 blocker는 Juice Shop 및 VulnBank OpenAPI case의
`http_runtime_contract_missing`, VulnBank 인증 우회 case의 `candidate_integrity`다.

## 회귀 검증

Phase A~E 실행과 문서 작성 후 최신 작업 트리에서 전체 suite를 다시 실행했다.

```text
805 passed, 4 skipped, 508 subtests passed in 107.38s
```

최초 sandbox 실행에서는 loopback bind가 차단되어 32개 runtime test가
`PermissionError`로 실패했다. 동일 suite를 로컬 loopback 권한으로 재실행한 위
결과를 최종 회귀 판정으로 사용한다.

## 문서

- [Phase A](PHASE_A.md)
- [Phase B](PHASE_B.md)
- [Phase C](PHASE_C.md)
- [Phase D](PHASE_D.md)
- [Phase E](PHASE_E.md)

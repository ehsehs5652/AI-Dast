# 2026-09-23 로컬 대상 테스트 결과

`docs/test-plans/LOCAL_FUNCTIONAL_LAB.md`와 `VULNBANK_JUICESHOP_EVALUATION_PLAN.md`에 따라 Juice Shop과 VulnBank를 점검했다. 기준 코드 commit은 `a97d456156d1c7632b05bd800f61a561e9144ed8`이며, Phase B 직전 CLI 회귀 수정으로 작업 트리에 `src/aidast/cli.py`와 해당 테스트 변경이 추가됐다. 따라서 이 실행은 코드가 완전히 고정된 3회 비교 실험이 아니다.

| 단계 | 판정 | 근거 |
| --- | --- | --- |
| [A](PHASE_A.md) | PASS | 서비스·DB health, 브라우저, Scope 무결성 및 exact loopback 정책 확인 |
| [B](PHASE_B.md) | FAIL | VulnBank 외부 font 요청 34건 허용; Juice Shop 관측 태깅 50건 `MainAgentError` |
| [C](PHASE_C.md) | NOT RUN | B 실패로 인증 Surface 평가 미진행 |
| [D](PHASE_D.md) | NOT RUN | 계획의 Recon 실패 중단 조건 적용 |
| [E](PHASE_E.md) | NOT RUN | 통합 finding 및 Validation case 없음 |
| [F](PHASE_F.md) | NOT RUN | shakedown 미통과, 초기 상태 복원 미검증 |

## 로컬 회귀 테스트

- CLI 수정 회귀 테스트: 먼저 예상한 `AttributeError` 실패를 확인하고 수정 후 `ReconCliTests` 13개 통과.
- 관련 Recon suite: `69 passed, 14 subtests passed`.
- 전체 suite 최초 실행: `32 failed, 1013 passed, 6 skipped`; macOS `TMPDIR`의 `/var` → `/private/var` symlink로 인한 경로 비교·검사 실패가 중심이었다.
- `TMPDIR=/private/tmp`에서 같은 전체 suite를 재실행한 로그: `1043 passed, 6 skipped, 642 subtests passed in 110.13s`. 로그 원본은 `result/test-runs/09.23/pytest-full.log`에 있다. 로그 출력 뒤 사용한 셸 래퍼가 zsh 예약 변수 `status` 할당 오류를 냈으므로 래퍼 exit code는 테스트 결과로 사용하지 않는다.

## 재개 조건

1. 로컬 평가에서 브라우저 `passive` 지원 요청이 외부 host로 나가지 않도록 경계를 고정한다.
2. Juice Shop 태깅의 `MainAgentError` 원인을 확인하고 실패 배치를 재시도한다.
3. 두 대상의 Recon stage와 필수 산출물 생성이 완료된 후 Phase C~F를 새 결과 세트로 실행한다.

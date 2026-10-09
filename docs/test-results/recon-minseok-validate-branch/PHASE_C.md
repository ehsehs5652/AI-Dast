# Phase C — 인증 흐름 점검

## 판정

**PASS**

기존 로컬 테스트 계정의 integrity-protected Session bundle을 현재 브랜치에서
다시 검증하고, primary/secondary 인증 Surface를 새 Recon DB에 수집했다.

## 실행 결과

| 실행 | Scan ID | 상태 | endpoints | observations | transactions |
| --- | --- | --- | ---: | ---: | ---: |
| Juice Shop primary | `scan_52cdd9ffe8e94d71bba803f426873f25` | completed | 25 | 186 | 147 |
| VulnBank primary | `scan_627334d9b5c64dacb13bfcb86657de93` | completed | 5 | 23 | 21 |
| VulnBank secondary | `scan_4c83e460fd214894893165707db9241d` | completed | 5 | 23 | 21 |

Juice Shop primary Surface에서 `GET /rest/user/whoami`를 확인했다. VulnBank의
두 identity는 각각 dashboard와 동일한 인증 API 집합을 수집했고 서로 다른 사용자
객체를 참조했다. 두 storage snapshot의 SHA-256도 달라 identity가 분리돼 있음을
확인했다. 해시와 account identifier는 결과 문서에 기록하지 않았다.

Session.json과 storage snapshot의 mode는 모두 `0600`이었다. credential, cookie,
JWT 원문은 이 문서에 저장하지 않았다.

산출물:

- `result/test-runs/current-branch-f54af46/phase-c/juice-shop-primary/`
- `result/test-runs/current-branch-f54af46/phase-c/vuln-bank-primary/`
- `result/test-runs/current-branch-f54af46/phase-c/vuln-bank-secondary/`

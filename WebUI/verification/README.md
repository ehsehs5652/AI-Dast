# WebUI 검증 기록

2026-09-20 기준 Node.js 24.18.1과 Chromium/Playwright 환경에서 검증했습니다.

## 자동 검증

- `npm test`: **14개 통과, 실패 0개**
- `npm run build`: TypeScript 검사와 Vite production build 통과
- gzip 기준 대략적인 번들 크기: JavaScript 95kB, CSS 11kB

테스트는 스냅샷 검증, 잘못된 WebSocket frame 거부, 이벤트 순서 복구, 중복 제거,
heartbeat 처리, 로그 500개 보관 제한과 스캔 상태 변경을 확인합니다.

## 브라우저 검증

- 8개 메뉴와 hash 기반 앞/뒤 탐색
- 비어 있는 초기 프로그램 목록과 사용자 등록 항목만 표시되는지 확인
- Private 프로그램 이름의 기본 마스킹과 일시적 표시
- Scope 수집 진행 로그, 초안 검토와 명시적인 Yes/No 승인
- 승인된 Scope만 New Scan에서 선택 가능한지 확인
- 1440px, 1024px, 768px, 390px 반응형 레이아웃
- 라이트·다크·시스템 테마와 한국어·영어 전환
- 활동 로그 일시정지 중에도 이벤트 수신이 계속되는지 확인

## 실시간 연결 검증

- REST 스냅샷 cursor 이후의 WebSocket 이벤트 재생
- 순서가 바뀐 이벤트의 정렬, 중복 frame 무시와 재연결
- REST 503 발생 시 데모 데이터로 바뀌지 않고 오류 상태 표시
- Audit API에서 요청 본문, 헤더, 쿠키, 토큰과 `details_json`이 제외되는지 확인
- 해시가 일치하는 `Report.db` 초안만 표시하고 경로 탐색 형태의 ID는 거부

실제 외부 타깃 스캔은 실행하지 않았습니다. 브라우저 검증 스크린샷은 생성 파일이므로
Git에 포함하지 않습니다.

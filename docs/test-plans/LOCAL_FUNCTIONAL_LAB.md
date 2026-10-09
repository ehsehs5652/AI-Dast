# 로컬 기능 테스트 환경

## 현재 구성

- Juice Shop: <http://127.0.0.1:3001/>. [Compose 설정](../lab/compose.yaml)은 로컬 loopback에만 포트를 열고 이미지 digest를 고정합니다.
- VulnBank: <http://127.0.0.1:5001/>. 원본은 [Commando-X/vuln-bank](https://github.com/Commando-X/vuln-bank).
- VulnBank의 PostgreSQL은 내부 네트워크에서만 연결되며 호스트에 DB 포트를 게시하지 않습니다. 웹의 AI 채팅은 빈 `DEEPSEEK_API_KEY`로 mock 모드를 사용합니다.

## 실행·확인·종료

```bash
# 테스트 앱 시작: 소스 준비는 아래 최초 설치 항목 참고
docker compose -f lab/compose.yaml up -d --build

# 상태와 시작 로그
docker compose -f lab/compose.yaml ps
docker compose -f lab/compose.yaml logs --tail 50 juice-shop vuln-bank

# 홈페이지 가용성 측정: 1초 간격으로 총 3회 GET
python scripts/lab_smoke.py \
  --url http://127.0.0.1:3001/ \
  --url http://127.0.0.1:5001/

# 중지 후 같은 컨테이너 재사용
docker compose -f lab/compose.yaml stop
docker compose -f lab/compose.yaml start
```

`lab_smoke.py`는 `http://127.0.0.1:<port>/`만 허용하며 리다이렉트를 따라가지 않습니다. 요청당 응답 본문을 최대 64 KiB까지 읽고 결과를 콘솔에만 출력합니다. 이는 접속 확인 도구입니다.

`docker compose -f lab/compose.yaml down`은 이 Compose의 컨테이너를 제거합니다. Juice Shop의 컨테이너 내부 데이터는 사라지지만, VulnBank의 DB와 업로드 파일은 named volume에 남습니다. 

`down --volumes`는 이 구성의 볼륨까지 삭제하므로 테스트 데이터를 모두 폐기할 때만 사용하세요. 

### 최초 설치

```bash
git clone https://github.com/Commando-X/vuln-bank.git result/lab/vuln-bank

git -C result/lab/vuln-bank checkout --detach 5e5ea5425fcf309373a0655dd111ecfb45037cbf

docker compose -f lab/compose.yaml up -d --build
```

소스는 Git에서 제외되는 `result/`에 두고 Compose만 프로젝트에 보관합니다. 

웹 컨테이너는 호스트 포트 게시를 위한 `bank-web` 네트워크와 DB 연결용 내부 `bank` 네트워크에 연결됩니다. DB는 `bank`에만 연결됩니다. 웹 컨테이너의 외부 통신 전체를 차단하는 구성은 아닙니다.

VulnBank의 DB 연결 상태는 `http://127.0.0.1:5001/healthz`, API 문서는 `http://127.0.0.1:5001/api/docs`에서 확인할 수 있습니다. 테스트 계정은 브라우저에서 일반 회원가입으로 생성하면 됩니다. 실제 외부 LLM 호출은 이 구성의 평가 범위에 포함하지 않습니다.

## 평가 지표

| 구분 | 기록할 지표 | 해석 |
| --- | --- | --- |
| 환경 가용성 | 기동 성공, HTTP 응답, 로그인 성공 | 테스트 환경이 정상인지 확인 |
| 기능 정확성 | 단계 완료·실패, 산출물 생성, 원본 보존, 재개 결과 | 프로그램이 계약대로 동작하는지 확인 |
| 수집 품질 | 기준 목록 대비 관측 엔드포인트·메서드, 중복, 누락 | 수집 범위와 품질 평가 |
| 실행 비용 | 단계별 소요 시간, 요청 수, 모델 사용량, 실패·재시도 | 동일 조건에서 비용 비교 |
| 탐지 정확도 | 검토된 정답 대비 TP·FP·FN | precision·recall 평가; 이번 구성에서는 미측정 |

비교 시 앱 이미지/커밋, 프로젝트 커밋과 작업 트리 변경, 로그인 상태, 데이터 초기 상태, 정책·예산, 모델 식별자를 함께 기록하세요. 동일 조건을 최소 3회 반복하고 중앙값과 변동 범위를 비교합니다. 모델 사용량을 수집하지 못했다면 0으로 쓰지 말고 미측정으로 남깁니다.

탐지 정확도는 `precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`로 계산합니다. 분모가 0이면 N/A로 기록합니다. 정답 목록은 해당 버전·계정·범위에서 평가 가능한 항목으로 확정해야 합니다. Juice Shop의 모든 챌린지를 그대로 분모로 쓰거나 후보 개수만으로 탐지 성능을 판단하면 안 됩니다. 인증 실패 등으로 평가하지 못한 항목은 따로 기록합니다.

현재 구성은 환경 기동·가용성 확인과 오프라인 기능 테스트까지 제공합니다. 자동 취약점 공격 실행이나 재현 절차는 포함하지 않습니다.

## 참고

- 프로젝트 구조: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)
- Juice Shop 공식 Docker 이미지 안내: [OWASP Developer Guide](https://devguide.owasp.org/en/07-training-education/01-vulnerable-apps/01-juice-shop/)
- VulnBank 원본 구성: [docker-compose.yml](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/docker-compose.yml)

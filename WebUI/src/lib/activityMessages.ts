import type { Language } from './i18n';

export type ActivityMessage = {
  message: string;
  message_code?: string | null;
  message_params?: Record<string, string | number>;
};

const auditLabels: Record<string, string> = {
  'stage.started': '단계 시작',
  'stage.resumed': '단계 재개',
  'stage.completed': '단계 완료',
  'stage.failed': '단계 실패',
  'task.created': '작업 생성',
  'task.cancelled': '작업 취소',
  'credential_reference.created': '인증정보 참조 생성',
  'scope.verified': '스코프 검증',
  'pipeline.materialized': '파이프라인 생성',
  'request.authorized': '요청 승인',
  'finding.created': '취약점 후보 생성',
  'recon.activity': '정찰 도구 활동',
};

const reconPhaseLabels: Record<string, string> = {
  subfinder: 'Subfinder 하위 도메인 탐색', dnsx: 'dnsx DNS 확인',
  naabu: 'naabu 포트 탐색', nmap: 'nmap 포트 확인',
  asset_discovery: '자산 탐색', dns_resolution: 'DNS 확인', host_port_discovery: '호스트·포트 탐색',
  http_probe: 'HTTP 확인', origin_discovery: '웹 원점 확인', endpoint_discovery: '엔드포인트 수집',
  playwright_bootstrap: 'Playwright 브라우저·세션 준비', playwright_priority: 'Playwright 우선 페이지/API 관측',
  katana_standard: 'Katana 일반 크롤링', katana_headless: 'Katana 브라우저 크롤링',
  playwright_interaction: 'Playwright 화면 상호작용', ffuf: 'ffuf 경로 탐색',
  api_secondary: 'API 명세·GraphQL 추가 탐색', openapi_detection: 'OpenAPI 명세 확인',
  graphql_detection: 'GraphQL 엔드포인트 확인', zap_openapi: 'ZAP OpenAPI 탐색',
  zap_graphql: 'ZAP GraphQL 탐색', mitm_capture: 'mitmproxy 요청 캡처',
};
const reconStateLabels: Record<string, string> = {
  started: '시작', finished: '종료', skipped: '건너뜀', failed: '실패', planned: '작업 범위 결정',
};

export function reconActivityLabel(params: Record<string, string | number>): string {
  if (params.phase === 'endpoint_discovery' && params.state === 'found') {
    const status = typeof params.response_status === 'number' ? params.response_status : null;
    const evidence = status === null ? 'HTTP 응답 미확인 · 후보'
      : status === 404 ? 'HTTP 404 응답 · 유효 경로 미확인'
      : status === 401 || status === 403 ? `HTTP ${status} 접근 제한 응답 관측`
      : status >= 500 ? `HTTP ${status} 서버 오류 응답 관측`
      : `HTTP ${status} 응답 관측`;
    return `URL 발견 · ${params.method} ${params.url} · ${evidence}${params.source ? ` · 출처 ${params.source}` : ''}`;
  }
  const phase = reconPhaseLabels[String(params.phase)] ?? '정찰 작업';
  const state = reconStateLabels[String(params.state)] ?? '상태 변경';
  const root = typeof params.index === 'number' && typeof params.total === 'number'
    ? ` · 대상 ${params.index}/${params.total}` : '';
  const count = typeof params.count === 'number' ? ` · 결과 ${params.count}건` : '';
  const roots = typeof params.root_count === 'number' ? ` · 탐색 경로 ${params.root_count}개` : '';
  const captured = typeof params.allowed_count === 'number'
    ? ` · 허용 ${params.allowed_count}건, 차단 ${Number(params.blocked_count) || 0}건` : '';
  const duplicates = typeof params.duplicate_count === 'number' && params.duplicate_count > 0
    ? ` · 이미 본 화면 ${params.duplicate_count}개 건너뜀` : '';
  const reason = { time_limit: '시간 상한 도달', action_limit: '동작 상한 도달', page_limit: '페이지 상한 도달' }[String(params.reason)] ?? '';
  return `${phase} ${state}${root}${count}${roots}${captured}${duplicates}${reason ? ` · ${reason}` : ''}`;
}

const koreanMessages: Record<string, (params: Record<string, string | number>) => string> = {
  'pipeline.accepted': () => '승인 확인 후 스캔 요청을 접수했습니다.',
  'pipeline.start_failed': () => '스캔 프로세스를 시작하지 못했습니다.',
  'pipeline.started': () => 'AI DAST 파이프라인을 시작했습니다.',
  'pipeline.completed': () => 'AI DAST 파이프라인이 완료되었습니다.',
  'pipeline.failed': () => 'AI DAST 파이프라인이 오류로 종료되었습니다.',
  'pipeline.resumed': () => '실패한 단계부터 스캔을 다시 시작했습니다.',
  'pipeline.resume_completed': () => '재실행한 스캔이 완료되었습니다.',
  'pipeline.resume_failed': () => '재실행한 스캔이 오류로 종료되었습니다.',
  'pipeline.stop_requested': () => '운영자가 스캔 중단을 요청했습니다.',
  'pipeline.stopped': () => '운영자가 스캔을 중단했습니다.',
  'pipeline.stop_persist_failed': () => '프로세스는 종료됐지만 저장된 스캔 상태를 갱신하지 못했습니다.',
  'pipeline.cancel_requested': () => '운영자가 스캔 취소를 요청했습니다.',
  'pipeline.cancelled': () => '스캔이 취소됐습니다.',
  'pipeline.cancel_persist_failed': () => '프로세스는 종료됐지만 저장된 스캔 상태를 취소됨으로 갱신하지 못했습니다.',
  'pipeline.paused': () => '스캔 실행이 일시정지됐습니다.',
  'pipeline.continued': () => '일시정지한 스캔 실행을 계속합니다.',
  'pipeline.audit_event': params => `파이프라인 이벤트 · ${auditLabels[String(params.event_type)] ?? '상태 변경'}`,
  'recon.activity': params => reconActivityLabel(params),
  'scope.started': () => '스코프 수집을 시작했습니다.',
  'scope.interrupted': () => '대시보드 재시작으로 스코프 수집이 중단되었습니다.',
  'scope.already_approved': () => '검증된 승인 스코프가 이미 있습니다.',
  'scope.browser_ready': () => '프로그램 페이지에 자동 접근하지 못했습니다. 열린 브라우저에서 로그인이나 접근 확인을 마친 뒤 계속을 누르세요.',
  'scope.browser_confirmed': () => '브라우저 접근 확인을 받았습니다. 등록된 프로그램 페이지로 이동해 캡처합니다.',
  'scope.browser_progress': () => '브라우저에서 프로그램 정책 화면을 수집하고 있습니다.',
  'scope.page_read_started': () => '프로그램 정책 화면 읽기를 시작합니다.',
  'scope.page_read_completed': params => `프로그램 정책 화면 읽기를 완료했습니다. 텍스트 ${Number(params.characters) || 0}자를 수집했습니다.`,
  'scope.analysis_started': () => 'Scope Agent가 In-Scope, Out-of-Scope와 정책 제약을 읽고 분석합니다.',
  'scope.analysis_completed': params => `In-Scope ${Number(params.in_scope) || 0}개와 Out-of-Scope ${Number(params.out_of_scope) || 0}개를 읽고 분류했습니다.`,
  'scope.collection_started': () => 'Scope Agent가 프로그램 화면 수집과 정책 분석을 시작합니다.',
  'scope.collection_completed': params => `프로그램 화면 수집과 정책 분석을 마쳤습니다. 텍스트 ${Number(params.characters) || 0}자, In-Scope ${Number(params.in_scope) || 0}개, Out-of-Scope ${Number(params.out_of_scope) || 0}개를 추출했습니다.`,
  'scope.verification_started': () => '수집한 범위와 원문 근거가 일치하는지 검증합니다.',
  'scope.verification_completed': () => '수집한 범위와 원문 근거 검증을 완료했습니다.',
  'scope.draft_started': () => '검증된 내용으로 스코프 초안 저장을 시작합니다.',
  'scope.draft_completed': () => '스코프 초안 저장을 완료했습니다.',
  'scope.paused': () => '스코프 수집을 일시정지했습니다.',
  'scope.continued': () => '일시정지한 스코프 수집을 계속합니다.',
  'scope.cancel_requested': () => '스코프 수집 취소를 요청했습니다.',
  'scope.cancelled': () => '스코프 수집이 취소됐습니다.',
  'scope.review_required': params => `스코프 초안이 검토를 기다립니다. 허용 범위 ${Number(params.in_scope) || 0}개, 제외 범위 ${Number(params.out_of_scope) || 0}개입니다.`,
  'scope.approved': () => '스코프 초안을 승인하고 무결성이 결합된 산출물을 게시했습니다.',
  'scope.rejected': () => '운영자가 스코프 초안을 거절했습니다. 승인 산출물은 생성하지 않았습니다.',
  'scope.failed': params => {
    const reason = String(params.reason || '');
    if (reason === 'Scope navigation reached its three-step limit before capture' || reason === 'Scope navigation exhausted its reviewed views before capture') {
      return '스코프 수집 실패: 프로그램 화면을 이동했지만 자산 목록과 정책을 함께 확인하지 못했습니다.';
    }
    return reason ? `스코프 수집 실패: ${reason}` : '스코프 수집에 실패했습니다. 자세한 원인은 서버 로그를 확인하세요.';
  },
};

const auditLabelsEn: Record<string, string> = {
  'stage.started': 'Stage started', 'stage.resumed': 'Stage resumed',
  'stage.completed': 'Stage completed', 'stage.failed': 'Stage failed',
  'task.created': 'Task created', 'task.cancelled': 'Task cancelled',
  'credential_reference.created': 'Credential reference created',
  'scope.verified': 'Scope verified', 'pipeline.materialized': 'Pipeline created',
  'request.authorized': 'Request authorized', 'finding.created': 'Finding candidate created',
  'recon.activity': 'Recon tool activity',
};
const reconPhaseLabelsEn: Record<string, string> = {
  subfinder: 'Subfinder subdomain discovery', dnsx: 'dnsx DNS resolution',
  naabu: 'naabu port discovery', nmap: 'nmap port verification',
  asset_discovery: 'Asset discovery', dns_resolution: 'DNS resolution', host_port_discovery: 'Host and port discovery',
  http_probe: 'HTTP probing', origin_discovery: 'Web origin discovery', endpoint_discovery: 'Endpoint discovery',
  playwright_bootstrap: 'Playwright browser and session setup', playwright_priority: 'Playwright priority page/API observation',
  katana_standard: 'Katana standard crawling', katana_headless: 'Katana browser crawling',
  playwright_interaction: 'Playwright page interaction', ffuf: 'ffuf path discovery',
  api_secondary: 'API specification and GraphQL discovery', openapi_detection: 'OpenAPI specification detection',
  graphql_detection: 'GraphQL endpoint detection', zap_openapi: 'ZAP OpenAPI discovery',
  zap_graphql: 'ZAP GraphQL discovery', mitm_capture: 'mitmproxy request capture',
};
const reconStateLabelsEn: Record<string, string> = {
  started: 'started', finished: 'finished', skipped: 'skipped', failed: 'failed', planned: 'work scope planned',
};
function reconActivityLabelEn(params: Record<string, string | number>): string {
  if (params.phase === 'endpoint_discovery' && params.state === 'found') {
    const status = typeof params.response_status === 'number' ? params.response_status : null;
    const evidence = status === null ? 'candidate · no HTTP response observed'
      : status === 404 ? 'HTTP 404 observed · valid route unconfirmed'
      : status === 401 || status === 403 ? `HTTP ${status} access restriction observed`
      : status >= 500 ? `HTTP ${status} server error observed`
      : `HTTP ${status} response observed`;
    return `URL found · ${params.method} ${params.url} · ${evidence}${params.source ? ` · source ${params.source}` : ''}`;
  }
  const phase = reconPhaseLabelsEn[String(params.phase)] ?? 'Recon task';
  const state = reconStateLabelsEn[String(params.state)] ?? 'status changed';
  const target = typeof params.index === 'number' && typeof params.total === 'number'
    ? ` · target ${params.index}/${params.total}` : '';
  const count = typeof params.count === 'number' ? ` · ${params.count} results` : '';
  const roots = typeof params.root_count === 'number' ? ` · ${params.root_count} discovery roots` : '';
  const captured = typeof params.allowed_count === 'number'
    ? ` · ${params.allowed_count} allowed, ${Number(params.blocked_count) || 0} blocked` : '';
  const duplicates = typeof params.duplicate_count === 'number' && params.duplicate_count > 0
    ? ` · ${params.duplicate_count} known pages skipped` : '';
  const reason = { time_limit: 'time limit reached', action_limit: 'action limit reached', page_limit: 'page limit reached' }[String(params.reason)] ?? '';
  return `${phase} ${state}${target}${count}${roots}${captured}${duplicates}${reason ? ` · ${reason}` : ''}`;
}
function scopeBrowserProgressEn(message: string): string {
  const staticMessages: Record<string, string> = {
    '등록된 프로그램 페이지에 로그인 없이 접근할 수 있는지 확인합니다.': 'Checking whether the registered program page is accessible without login.',
    '첫 페이지 이동이 끝나지 않았습니다. 브라우저에서 접근 상태를 확인해야 합니다.': 'The first navigation did not finish. Check access in the browser.',
    '현재 페이지에서 로그인 또는 접근 확인이 필요합니다. 브라우저에서 완료한 뒤 대시보드의 계속 버튼을 누르세요.': 'Login or access confirmation is required. Complete it in the browser, then select Continue in the dashboard.',
    '로그인 없이 프로그램 정책 페이지에 접근했습니다. 바로 스코프를 읽습니다.': 'Accessed the program policy page without login. Reading Scope now.',
    'Scope Agent가 현재 정책 화면을 수집 대상으로 선택했습니다.': 'Scope Agent selected the current policy page for collection.',
    '등록된 프로그램 URL로 브라우저를 이동합니다.': 'Navigating the browser to the registered program URL.',
    '등록된 프로그램 URL의 페이지 응답을 받았습니다. 브라우저 탭을 확인합니다.': 'Received the registered program URL response. Checking the browser tab.',
    '등록된 프로그램 페이지 이동을 확인했습니다.': 'Confirmed navigation to the registered program page.',
  };
  if (staticMessages[message]) return staticMessages[message];
  let match = /^프로그램 정책 화면을 읽고 있습니다\. 단계 (\d+)\/(\d+)\.$/.exec(message);
  if (match) return `Reading the program policy page. Step ${match[1]}/${match[2]}.`;
  match = /^프로그램 정책 화면 읽기를 완료했습니다\. 단계 (\d+)\/(\d+), 텍스트 (\d+)자입니다\.$/.exec(message);
  if (match) return `Finished reading the program policy page. Step ${match[1]}/${match[2]}, ${match[3]} characters.`;
  match = /^화면 텍스트 (\d+)자와 이동 후보 (\d+)개를 확인했습니다\. Scope Agent가 스코프 화면을 판단합니다\.$/.exec(message);
  if (match) return `Observed ${match[1]} characters and ${match[2]} navigation candidates. Scope Agent is identifying the Scope page.`;
  match = /^Scope Agent가 화면 이동 후보 (\d+)번을 엽니다\.$/.exec(message);
  if (match) return `Scope Agent is opening navigation candidate ${match[1]}.`;
  match = /^Scope Agent가 화면 이동 후보 (\d+)번 열기를 완료했습니다\.$/.exec(message);
  if (match) return `Scope Agent opened navigation candidate ${match[1]}.`;
  match = /^Scope Agent가 화면 이동 후보 (\d+)번\((.+)\)을 엽니다\.$/.exec(message);
  if (match) return `Scope Agent is opening navigation candidate ${match[1]} (${match[2]}).`;
  match = /^Scope 관련 이동 후보: (.+)\.$/.exec(message);
  if (match) return `Scope-related navigation candidates: ${match[1]}.`;
  return 'Browser policy collection is in progress. See the source event for details.';
}
const englishMessages: Record<string, (params: Record<string, string | number>) => string> = {
  'pipeline.accepted': () => 'Scan request accepted after approval verification.',
  'pipeline.start_failed': () => 'Could not start the scan process.',
  'pipeline.started': () => 'AI DAST pipeline started.',
  'pipeline.completed': () => 'AI DAST pipeline completed.',
  'pipeline.failed': () => 'AI DAST pipeline exited with an error.',
  'pipeline.resumed': () => 'Scan restarted from the failed stage.',
  'pipeline.resume_completed': () => 'Rerun completed.',
  'pipeline.resume_failed': () => 'Rerun exited with an error.',
  'pipeline.stop_requested': () => 'Operator requested scan stop.',
  'pipeline.stopped': () => 'Operator stopped the scan.',
  'pipeline.stop_persist_failed': () => 'The process exited, but saved scan status could not be updated.',
  'pipeline.cancel_requested': () => 'Operator requested scan cancellation.',
  'pipeline.cancelled': () => 'Scan cancelled.',
  'pipeline.cancel_persist_failed': () => 'The process exited, but saved scan status could not be marked cancelled.',
  'pipeline.paused': () => 'Scan execution paused.',
  'pipeline.continued': () => 'Paused scan execution resumed.',
  'pipeline.audit_event': params => `Pipeline event · ${auditLabelsEn[String(params.event_type)] ?? String(params.event_type || 'status changed')}`,
  'recon.activity': params => reconActivityLabelEn(params),
  'scope.started': () => 'Scope collection started.',
  'scope.interrupted': () => 'Scope collection was interrupted by a dashboard restart.',
  'scope.already_approved': () => 'A verified approved Scope already exists.',
  'scope.browser_ready': () => 'The program page was not accessible automatically. Complete login or access confirmation in the browser, then select Continue.',
  'scope.browser_confirmed': () => 'Browser access confirmed. Navigating to the registered program page for capture.',
  'scope.browser_progress': () => 'Collecting the program policy page in the browser.',
  'scope.page_read_started': () => 'Reading the program policy page.',
  'scope.page_read_completed': params => `Finished reading the program policy page. Collected ${Number(params.characters) || 0} characters.`,
  'scope.analysis_started': () => 'Scope Agent is analyzing In-Scope, Out-of-Scope, and policy constraints.',
  'scope.analysis_completed': params => `Read and classified ${Number(params.in_scope) || 0} In-Scope and ${Number(params.out_of_scope) || 0} Out-of-Scope items.`,
  'scope.collection_started': () => 'Scope Agent started page collection and policy analysis.',
  'scope.collection_completed': params => `Page collection and policy analysis completed. Extracted ${Number(params.characters) || 0} characters, ${Number(params.in_scope) || 0} In-Scope and ${Number(params.out_of_scope) || 0} Out-of-Scope items.`,
  'scope.verification_started': () => 'Verifying collected Scope against the source evidence.',
  'scope.verification_completed': () => 'Scope and source evidence verification completed.',
  'scope.draft_started': () => 'Saving the verified Scope draft.',
  'scope.draft_completed': () => 'Scope draft saved.',
  'scope.paused': () => 'Scope collection paused.',
  'scope.continued': () => 'Scope collection resumed.',
  'scope.cancel_requested': () => 'Scope collection cancellation requested.',
  'scope.cancelled': () => 'Scope collection cancelled.',
  'scope.review_required': params => `Scope draft awaits review. ${Number(params.in_scope) || 0} in-scope and ${Number(params.out_of_scope) || 0} out-of-scope assets.`,
  'scope.approved': () => 'Scope draft approved and integrity-bound artifacts published.',
  'scope.rejected': () => 'Operator rejected the Scope draft. No approval artifacts were created.',
  'scope.failed': params => params.reason && !/[가-힣]/.test(String(params.reason)) ? `Scope collection failed: ${String(params.reason)}` : 'Scope collection failed. See server logs for details.',
};

const legacyCodes: Record<string, string> = {
  'Scan request accepted after approval verification.': 'pipeline.accepted',
  'Scan process could not be started.': 'pipeline.start_failed',
  'AI DAST pipeline process started.': 'pipeline.started',
  'AI DAST pipeline completed.': 'pipeline.completed',
  'AI DAST pipeline exited with an error.': 'pipeline.failed',
  'A verified approved Scope already exists.': 'scope.already_approved',
  'Scope collection started.': 'scope.started',
  'Scope login browser opened. Complete the platform login/MFA, return to the exact program page, and open its scope view.': 'scope.browser_ready',
  'Browser opened. Complete login/MFA, return to the exact Scope view, then confirm in the dashboard.': 'scope.browser_ready',
  'Browser login confirmation received; capturing the exact program page.': 'scope.browser_confirmed',
  'Scope draft approved and integrity-bound artifacts published.': 'scope.approved',
  'Scope draft rejected by the operator; no approval artifacts were published.': 'scope.rejected',
};

const demoMessagesKo: Record<string, string> = {
  'Demo Scope and approval hashes match. Only synthetic lab data is used.': '데모 스코프와 승인 해시가 일치합니다. 합성 실습 환경만 사용합니다.',
  'Demo asset inventory finalized · 218 Recon.db paths': '데모 자산 목록 확정 · Recon.db 경로 218개',
  'Handoff.json provenance verified · Pipeline.db created': 'Handoff.json 출처 검증 완료 · Pipeline.db 생성',
  'Access control template batch started · task 84 of 136': '접근 제어 템플릿 묶음 시작 · 작업 136개 중 84개',
  'Response difference detected. Candidate requires validation.': '응답 차이를 탐지했습니다. 검증이 필요한 후보입니다.',
  'Redacted evidence pair saved · credential references excluded': '민감정보를 제거한 증거 쌍 저장 · 인증정보 참조 제외',
  'F-0042 added to review queue · matcher result alone is not a verdict': 'F-0042를 검토 대기열에 추가 · 매처 결과만으로 판정하지 않음',
  'Policy budget checked · synthetic requests scheduled': '정책 예산 확인 완료 · 합성 요청 예약',
  'Comparing response signatures across fixture accounts': '픽스처 계정별 응답 서명 비교 중',
  'attack_attempts evidence references linked · secrets redacted': 'attack_attempts 증거 참조 연결 · 민감정보 제거',
  'Template batch complete · candidates remain unreviewed': '템플릿 묶음 완료 · 후보는 미검토 상태 유지',
};

export function localizeActivityMessage(language: Language, event: ActivityMessage): string {
  const code = event.message_code || legacyCodes[event.message];
  if (language === 'en') {
    if (code === 'recon.activity') return reconActivityLabelEn(event.message_params || {});
    if (code === 'scope.browser_progress' && /[가-힣]/.test(event.message)) return scopeBrowserProgressEn(event.message);
    if (/[가-힣]/.test(event.message) && code && englishMessages[code]) return englishMessages[code](event.message_params || {});
    return event.message;
  }
  if (demoMessagesKo[event.message]) return demoMessagesKo[event.message];
  if (code === 'scope.browser_progress' && /[가-힣]/.test(event.message)) return event.message;
  if (code && koreanMessages[code]) return koreanMessages[code](event.message_params || {});
  const oldDraft = /^Scope draft ready for explicit Yes\/No review: (\d+) in-scope and (\d+) out-of-scope assets\.$/.exec(event.message);
  if (oldDraft) return koreanMessages['scope.review_required']({ in_scope: Number(oldDraft[1]), out_of_scope: Number(oldDraft[2]) });
  if (event.message.startsWith('Scope collection failed:')) return koreanMessages['scope.failed']({});
  if (event.message.startsWith('Pipeline event · ')) {
    const legacyType = event.message.slice('Pipeline event · '.length).replaceAll(' · ', '.').replaceAll(' ', '_');
    return koreanMessages['pipeline.audit_event']({ event_type: legacyType });
  }
  if (/[가-힣]/.test(event.message)) return event.message;
  return '활동이 기록되었습니다. 자세한 내용은 서버 로그를 확인하세요.';
}

export function localizeAuditEventType(language: Language, eventType: string): string {
  return language === 'ko' ? auditLabels[eventType] ?? '상태 변경' : auditLabelsEn[eventType] ?? eventType;
}

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEvent, parseSnapshot, applyEvent, applyOrderedEvent, displayStageStatus, pipelineStageState, stages } from '../src/lib/events.ts';
import { demoSnapshot, DEMO_SCAN } from '../src/data/demo.ts';
import { initialLanguage, translate } from '../src/lib/i18n.ts';
import { localizeActivityMessage, localizeAuditEventType } from '../src/lib/activityMessages.ts';
import { resolveExecutionLimits } from '../src/lib/scan.ts';
import { scopeCollectionRequest } from '../src/lib/scope.ts';
import { auditLevel, readAuditAcknowledgements, saveAuditAcknowledgements } from '../src/lib/audit.ts';
import {
  formatActivityElapsed,
  initialScopeActivityState,
  isScopeActivityActive,
  mergeActivityLogs,
  hideAcknowledgedActivity,
  reduceScopeActivity,
  startScopeElapsedClock,
  startScopeJobPolling,
  shouldPollScopeJob,
} from '../src/lib/activity.ts';

const event = (id = 8, overrides = {}) => ({ version: 1, event_id: id, scan_id: DEMO_SCAN, occurred_at: '2026-09-20T06:00:00Z', type: 'log.appended', payload: { stage: 'Attack', level: 'info', message: 'Redacted fixture event' }, ...overrides });
test('audit acknowledgements persist per scan and invalid storage data is ignored', () => {
  const items = new Map();
  const storage = { getItem: key => items.get(key) ?? null, setItem: (key, value) => { items.set(key, value); } };
  assert.equal(saveAuditAcknowledgements(storage, 'scan-one', new Set(['audit-1'])), true);
  assert.deepEqual([...readAuditAcknowledgements(storage, 'scan-one')], ['audit-1']);
  assert.deepEqual([...readAuditAcknowledgements(storage, 'scan-two')], []);
  items.set('aidast:audit-ack:v1:scan-one', '{invalid');
  assert.deepEqual([...readAuditAcknowledgements(storage, 'scan-one')], []);
  assert.equal(auditLevel({ event_type: 'stage.failed' }), 'error');
});
test('acknowledged audit records disappear from scan activity and return when restored', () => {
  const snapshot = demoSnapshot();
  const merged = mergeActivityLogs(snapshot.logs, []);
  assert.equal(merged.length, snapshot.logs.length);
  assert.equal(hideAcknowledgedActivity(merged, new Set(['demo-4'])).length, snapshot.logs.length - 1);
  assert.equal(hideAcknowledgedActivity(merged, new Set(['demo-4'])).some(log => log.audit_id === 'demo-4'), false);
  assert.equal(hideAcknowledgedActivity(merged, new Set()).length, snapshot.logs.length);
  assert.equal(parseSnapshot(snapshot, DEMO_SCAN)?.logs.find(log => log.audit_id === 'demo-4')?.id, 7);
  assert.equal(parseEvent(event(8, { payload: { stage: 'Recon', level: 'info', message: 'safe', audit_id: 'audit-8' } }), DEMO_SCAN)?.type, 'log.appended');
});
test('dashboard labels use the Korean catalog and preserve English keys', () => {
  for (const key of ['Scopes / Programs', 'Yes · Approve Scope']) {
    assert.notEqual(translate('ko', key), key);
    assert.equal(translate('en', key), key);
  }
});
test('display language defaults to Korean and restores the saved choice', () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  try {
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => null } });
    assert.equal(initialLanguage(), 'ko');
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'en' } });
    assert.equal(initialLanguage(), 'en');
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'invalid' } });
    assert.equal(initialLanguage(), 'ko');
  } finally {
    if (original) Object.defineProperty(globalThis, 'localStorage', original);
    else delete globalThis.localStorage;
  }
});
test('activity codes localize live messages and audit types without exposing raw English', () => {
  const started = { message: 'AI DAST pipeline process started.', message_code: 'pipeline.started', message_params: {} };
  assert.equal(localizeActivityMessage('ko', started), 'AI DAST 파이프라인을 시작했습니다.');
  assert.equal(localizeActivityMessage('en', started), started.message);
  assert.equal(localizeActivityMessage('ko', { message: 'old event', message_code: 'scope.review_required', message_params: { in_scope: 3, out_of_scope: 2 } }), '스코프 초안이 검토를 기다립니다. 허용 범위 3개, 제외 범위 2개입니다.');
  assert.equal(localizeActivityMessage('ko', { message: 'Scope analysis started', message_code: 'scope.analysis_started' }), 'Scope Agent가 In-Scope, Out-of-Scope와 정책 제약을 읽고 분석합니다.');
  assert.equal(localizeActivityMessage('ko', { message: 'Scope analysis completed', message_code: 'scope.analysis_completed', message_params: { in_scope: 4, out_of_scope: 2 } }), 'In-Scope 4개와 Out-of-Scope 2개를 읽고 분류했습니다.');
  assert.equal(localizeActivityMessage('ko', { message: 'Scope failed', message_code: 'scope.failed', message_params: { reason: '원문 근거를 찾지 못했습니다.' } }), '스코프 수집 실패: 원문 근거를 찾지 못했습니다.');
  assert.equal(localizeActivityMessage('ko', { message: 'Pipeline event · stage · started' }), '파이프라인 이벤트 · 단계 시작');
  assert.equal(localizeActivityMessage('ko', { message: 'Scope draft ready for explicit Yes/No review: 5 in-scope and 16 out-of-scope assets.', message_code: null }), '스코프 초안이 검토를 기다립니다. 허용 범위 5개, 제외 범위 16개입니다.');
  assert.equal(localizeActivityMessage('ko', { message: 'Scope collection started.', message_code: null }), '스코프 수집을 시작했습니다.');
  assert.equal(localizeActivityMessage('ko', { message: 'Unexpected internal text' }), '활동이 기록되었습니다. 자세한 내용은 서버 로그를 확인하세요.');
  assert.equal(localizeAuditEventType('ko', 'stage.started'), '단계 시작');
  assert.equal(localizeActivityMessage('ko', { message: 'Recon activity', message_code: 'recon.activity', message_params: { phase: 'playwright_interaction', state: 'started' } }), 'Playwright 화면 상호작용 시작');
  assert.equal(localizeActivityMessage('ko', { message: 'Recon activity', message_code: 'recon.activity', message_params: { phase: 'endpoint_discovery', state: 'found', method: 'GET', url: 'https://example.com/missing', response_status: 404, source: 'ffuf' } }), 'URL 발견 · GET https://example.com/missing · HTTP 404 응답 · 유효 경로 미확인 · 출처 ffuf');
  assert.equal(localizeActivityMessage('en', { message: 'Recon activity', message_code: 'recon.activity', message_params: { phase: 'endpoint_discovery', state: 'found', method: 'GET', url: 'https://example.com/guess' } }), 'URL found · GET https://example.com/guess · candidate · no HTTP response observed');
  assert.equal(localizeActivityMessage('ko', { message: 'Recon activity', message_code: 'recon.activity', message_params: { phase: 'ffuf', state: 'finished', index: 2, total: 3, count: 4 } }), 'ffuf 경로 탐색 종료 · 대상 2/3 · 결과 4건');
  assert.equal(localizeActivityMessage('ko', { message: 'Scan paused by operator.', message_code: 'pipeline.paused' }), '스캔 실행이 일시정지됐습니다.');
});
test('synthetic scan activity follows the selected display language', () => {
  const event = demoSnapshot().logs[0];
  assert.equal(localizeActivityMessage('en', event), 'Demo Scope and approval hashes match. Only synthetic lab data is used.');
  assert.equal(localizeActivityMessage('ko', event), '데모 스코프와 승인 해시가 일치합니다. 합성 실습 환경만 사용합니다.');
});
test('English activity renders Korean-backed Scope and Recon events', () => {
  assert.equal(localizeActivityMessage('en', { message: '스코프 수집을 시작했습니다.', message_code: 'scope.started' }), 'Scope collection started.');
  assert.equal(localizeActivityMessage('en', { message: '프로그램 정책 화면 읽기를 완료했습니다. 단계 2/3, 텍스트 120자입니다.', message_code: 'scope.browser_progress' }), 'Finished reading the program policy page. Step 2/3, 120 characters.');
  assert.equal(localizeActivityMessage('en', { message: '정찰 활동', message_code: 'recon.activity', message_params: { phase: 'playwright_interaction', state: 'started', index: 1, total: 2 } }), 'Playwright page interaction started · target 1/2');
  assert.equal(localizeActivityMessage('en', { message: 'Scope Agent가 화면 이동 후보 3번(Scope)을 엽니다.', message_code: 'scope.browser_progress' }), 'Scope Agent is opening navigation candidate 3 (Scope).');
  assert.equal(localizeActivityMessage('en', { message: 'Scope 관련 이동 후보: 3:Scope.', message_code: 'scope.browser_progress' }), 'Scope-related navigation candidates: 3:Scope.');
  assert.equal(localizeActivityMessage('ko', { message: '스코프 수집 실패', message_code: 'scope.failed', message_params: { reason: 'Scope navigation exhausted its reviewed views before capture' } }), '스코프 수집 실패: 프로그램 화면을 이동했지만 자산 목록과 정책을 함께 확인하지 못했습니다.');
  assert.equal(localizeAuditEventType('en', 'stage.started'), 'Stage started');
});
test('paused scan remains paused even while its current stage is running', () => {
  const source = demoSnapshot();
  const paused = parseSnapshot({ ...source, status: 'paused', stage: 'Recon', stage_statuses: { Recon: 'running' } }, DEMO_SCAN);
  assert.ok(paused);
  assert.equal(displayStageStatus(paused, 'Recon', 'absent'), 'paused');
  const changed = parseEvent(event(8, { type: 'scan.status.changed', payload: { status: 'paused' } }), DEMO_SCAN);
  assert.ok(changed);
  assert.equal(applyEvent(source, changed).status, 'paused');
});
test('failed Recon restarts as a new scan while later failed stages can resume', async () => {
  const { scanRetryAction } = await import('../src/lib/scan.ts');
  assert.equal(scanRetryAction({ status: 'failed', stage: 'Recon' }), 'rescan');
  for (const stage of ['Attack', 'Chaining', 'Validation']) {
    assert.equal(scanRetryAction({ status: 'failed', stage }), 'resume');
  }
  assert.equal(scanRetryAction({ status: 'failed', stage: 'Report' }), 'rescan');
  assert.equal(scanRetryAction({ status: 'cancelled', stage: 'Recon' }), 'rescan');
  assert.equal(scanRetryAction({ status: 'running', stage: 'Recon' }), null);
});
test('structured scan log metadata survives event parsing and stream merging', () => {
  const structured = event(8, { payload: { stage: 'Recon', level: 'info', message: 'started', message_code: 'pipeline.started', message_params: {} } });
  const parsed = parseEvent(structured, DEMO_SCAN);
  assert.ok(parsed);
  const next = applyEvent(demoSnapshot(), parsed);
  assert.equal(mergeActivityLogs(next.logs, []).at(-1).message_code, 'pipeline.started');
});
test('scope collection and scan logs merge into one chronological activity stream', () => {
  const merged = mergeActivityLogs(
    [{ id: 7, time: '2026-09-22T00:00:02Z', stage: 'Attack', level: 'info', message: '스캔 이벤트' }],
    [{ job_id: 'scopejob_fixture', event_id: 2, occurred_at: '2026-09-22T00:00:01Z', level: 'warning', message: '스코프 이벤트' }],
  );
  assert.deepEqual(
    merged.map(({ key, source, stage, message }) => ({ key, source, stage, message })),
    [
      { key: 'scope:scopejob_fixture:2', source: 'scope', stage: 'Scope', message: '스코프 이벤트' },
      { key: 'scan:7', source: 'scan', stage: 'Attack', message: '스캔 이벤트' },
    ],
  );
});
test('active Scope collection elapsed time uses a TUI-style clock', () => {
  assert.equal(formatActivityElapsed(1), '1초');
  assert.equal(formatActivityElapsed(62), '1분 2초');
  assert.equal(formatActivityElapsed(62, 'en'), '1m 2s');
});
test('Scope elapsed clock advances each second across dialog close and cancels on terminal status', () => {
  let now = 0;
  let scheduled;
  let schedulerActive = false;
  let cancelCalls = 0;
  const labels = [];
  const clock = startScopeElapsedClock({
    now: () => now,
    onTick: current => labels.push(formatActivityElapsed(current / 1000)),
    schedule: (callback, delay) => {
      assert.equal(delay, 1000);
      scheduled = callback;
      schedulerActive = true;
      return 9;
    },
    cancel: handle => {
      assert.equal(handle, 9);
      schedulerActive = false;
      cancelCalls += 1;
    },
  });
  let lifecycle = reduceScopeActivity(initialScopeActivityState, { type: 'job-selected', status: 'collecting' });
  lifecycle = reduceScopeActivity(lifecycle, { type: 'dialog-closed' });
  assert.equal(lifecycle.polling, true);
  now = 1000;
  if (schedulerActive) scheduled();
  now = 2000;
  if (schedulerActive) scheduled();
  assert.deepEqual(labels, ['0초', '1초', '2초']);
  assert.equal(isScopeActivityActive('approved'), false);
  assert.equal(isScopeActivityActive('paused'), true);
  assert.equal(isScopeActivityActive('cancelling'), true);
  assert.equal(isScopeActivityActive('cancelled'), false);
  clock.stop();
  assert.equal(schedulerActive, false);
  assert.equal(cancelCalls, 1);
  now = 3000;
  if (schedulerActive) scheduled();
  assert.deepEqual(labels, ['0초', '1초', '2초'], 'terminal cleanup must prevent later elapsed updates');
});
test('unified activity preserves sub-millisecond and numeric event order', () => {
  const merged = mergeActivityLogs([], [
    { job_id: 'scopejob_fixture', event_id: 10, occurred_at: '2026-09-22T00:00:00.000200Z', level: 'info', message: '10' },
    { job_id: 'scopejob_fixture', event_id: 2, occurred_at: '2026-09-22T00:00:00.000200Z', level: 'info', message: '2' },
    { job_id: 'scopejob_fixture', event_id: 11, occurred_at: '2026-09-22T00:00:00.000200Z', level: 'info', message: '11' },
    { job_id: 'scopejob_fixture', event_id: 1, occurred_at: '2026-09-22T00:00:00.000100Z', level: 'info', message: '1' },
  ]);
  assert.deepEqual(merged.map(item => item.message), ['1', '2', '10', '11']);
});
test('unified activity retains the newest 500 entries across both sources', () => {
  const scanLogs = Array.from({ length: 251 }, (_, id) => ({
    id,
    time: `2026-09-22T00:00:${String(id % 60).padStart(2, '0')}.000Z`,
    stage: 'Attack',
    level: 'info',
    message: `scan-${id}`,
  }));
  const scopeEvents = Array.from({ length: 251 }, (_, event_id) => ({
    job_id: 'scopejob_fixture',
    event_id,
    occurred_at: `2026-09-22T00:01:${String(event_id % 60).padStart(2, '0')}.000Z`,
    level: 'info',
    message: `scope-${event_id}`,
  }));
  const merged = mergeActivityLogs(scanLogs, scopeEvents);
  assert.equal(merged.length, 500);
  assert.equal(merged.at(-1).message, 'scope-239');
});
test('Scope activity lifecycle drains final events before cancelling background polling', () => {
  const initialEvent = { job_id: 'scopejob_fixture', event_id: 1, occurred_at: '2026-09-22T00:00:00Z', level: 'info', message: 'started' };
  const finalEvent = { job_id: 'scopejob_fixture', event_id: 2, occurred_at: '2026-09-22T00:00:01Z', level: 'success', message: 'finished' };
  let state = reduceScopeActivity(initialScopeActivityState, { type: 'job-selected', status: 'collecting' });
  state = reduceScopeActivity(state, { type: 'job-response', status: 'collecting', events: [initialEvent] });
  state = reduceScopeActivity(state, { type: 'dialog-closed' });
  assert.equal(shouldPollScopeJob({ hasJob: true, polling: state.polling, dialogOpen: false }), true);
  state = reduceScopeActivity(state, { type: 'program-status', status: 'approved' });
  assert.equal(state.polling, true, 'program-list completion must not cancel the final job fetch');
  state = reduceScopeActivity(state, { type: 'job-response', status: 'approved', events: [initialEvent, finalEvent] });
  assert.equal(state.polling, false, 'terminal job response cancels the polling timer');
  assert.deepEqual(state.events.map(event => event.message), ['started', 'finished']);
  assert.equal(shouldPollScopeJob({ hasJob: true, polling: state.polling, dialogOpen: false }), false);
});
test('Scope job poller cancels its real scheduler after terminal delivery', async () => {
  const responses = [
    { status: 'collecting', payload: ['started'] },
    { status: 'approved', payload: ['started', 'finished'] },
  ];
  const delivered = [];
  let requests = 0;
  let scheduled;
  let schedulerActive = false;
  let cancelCalls = 0;
  let terminalDelivered;
  const terminal = new Promise(resolve => { terminalDelivered = resolve; });
  const poller = startScopeJobPolling({
    repeat: true,
    load: async () => responses[requests++],
    onResponse: result => {
      delivered.push(...result.payload);
      if (result.status === 'approved') terminalDelivered();
    },
    onError: error => { throw error; },
    schedule: callback => {
      scheduled = callback;
      schedulerActive = true;
      return 7;
    },
    cancel: handle => {
      assert.equal(handle, 7);
      schedulerActive = false;
      cancelCalls += 1;
    },
  });
  await poller.first;
  assert.equal(requests, 1);
  assert.equal(schedulerActive, true);
  if (schedulerActive) scheduled();
  await terminal;
  assert.equal(requests, 2);
  assert.equal(schedulerActive, false);
  assert.equal(cancelCalls, 1);
  if (schedulerActive) scheduled();
  await Promise.resolve();
  assert.equal(requests, 2, 'terminal delivery must not schedule another request');
  assert.deepEqual(delivered, ['started', 'started', 'finished']);
});
test('scope collection always uses the persistent operator browser', () => {
  assert.deepEqual(scopeCollectionRequest, {
    login_mode: 'runtime-browser',
    identity: 'primary',
  });
});
test('scan limits use the stricter Scope request rate', () => {
  const requirements = {
    scope_max_requests_per_second: 0.75,
    required_header: null,
    operational_constraints: [],
    profiles: [{
      id: 'focused-discovery',
      limits: {
        requests_per_second: 1,
        concurrency: 3,
        timeout_seconds: 20,
        max_depth: 3,
        max_requests: 2000,
      },
    }],
  };
  assert.deepEqual(
    resolveExecutionLimits(requirements, 'focused-discovery'),
    {
      requests_per_second: 0.75,
      concurrency: 3,
      timeout_seconds: 20,
      max_depth: 3,
      max_requests: 2000,
    },
  );
});
test('pipeline includes report and preserves the real stage order', () => assert.deepEqual(stages, ['Scope','Recon','Attack','Chaining','Validation','Report']));
test('Validation completion does not imply a generated report', () => {
  const snapshot = { stage: 'Validation', status: 'completed' };
  assert.equal(pipelineStageState('Validation', snapshot), 'done');
  assert.equal(pipelineStageState('Report', snapshot), 'separate');
});
test('completion only marks stages through the last observed stage', () => {
  const snapshot = { stage: 'Recon', status: 'completed' };
  assert.equal(pipelineStageState('Scope', snapshot), 'done');
  assert.equal(pipelineStageState('Recon', snapshot), 'done');
  assert.equal(pipelineStageState('Attack', snapshot), 'pending');
});
test('running, failed and cancelled stages remain distinct from completed stages', () => {
  for (const status of ['running', 'failed', 'cancelled']) {
    const snapshot = { stage: 'Chaining', status };
    assert.equal(pipelineStageState('Attack', snapshot), 'done');
    assert.equal(pipelineStageState('Chaining', snapshot), 'current');
    assert.equal(pipelineStageState('Validation', snapshot), 'pending');
  }
  assert.equal(pipelineStageState('Report', { stage: 'Report', status: 'completed' }), 'done');
});
test('completed validation does not imply a report draft or completed chaining', () => {
  const scan = { ...demoSnapshot(), status: 'completed', stage: 'Validation', stage_statuses: { Scope: 'completed', Recon: 'completed', Attack: 'completed', Chaining: 'skipped', Validation: 'completed' } };
  assert.equal(displayStageStatus(scan, 'Chaining', 'absent'), 'skipped');
  assert.equal(displayStageStatus(scan, 'Validation', 'absent'), 'completed');
  assert.equal(displayStageStatus(scan, 'Report', 'absent'), 'not_created');
  assert.equal(displayStageStatus(scan, 'Report', 'present'), 'completed');
});
test('snapshot validates the synthetic scan independently', () => {
  const data = demoSnapshot();
  assert.deepEqual(parseSnapshot(data, DEMO_SCAN), data);
});
test('invalid snapshots do not fall back to fixture data', () => {
  for (const patch of [{ version: 2 }, { last_event_id: -1 }, { stage: 'unknown' }, { progress: 101 }, { budget: -1 }, { findings: [{}] }, { logs: [{}] }, { logs: [{ ...demoSnapshot().logs[0], id: 900 }] }]) assert.equal(parseSnapshot({ ...demoSnapshot(), ...patch }, DEMO_SCAN), null);
  assert.equal(parseSnapshot(demoSnapshot(), 'other-scan'), null);
});
test('snapshot log history is sorted and deduplicated', () => {
  const data = demoSnapshot(); data.logs = [data.logs[3], data.logs[0], data.logs[3]];
  assert.deepEqual(parseSnapshot(data, DEMO_SCAN).logs.map(l => l.id), [1, 4]);
});
test('malformed JSON, foreign scans, versions, and unknown events are rejected', () => {
  for (const raw of ['{', 'null', '[]', event(8,{version:2}), event(8,{scan_id:'other'}), event(-1), event(8,{type:'something.new'}), event(8,{occurred_at:'not-a-date'}), event(8,{payload:{}})]) assert.equal(parseEvent(raw, DEMO_SCAN), null);
});
test('valid event payload is preserved', () => assert.deepEqual(parseEvent(JSON.stringify(event()), DEMO_SCAN), event()));
test('progress payloads reject NaN, negative requests and values beyond 100', () => {
  for (const payload of [{progress:NaN,requests:1},{progress:101,requests:1},{progress:20,requests:-1}]) assert.equal(parseEvent(event(8,{type:'task.progress.updated',payload}), DEMO_SCAN), null);
});
test('activity updates reach the live snapshot without changing progress', () => {
  const start = demoSnapshot();
  const update = event(8, { type: 'task.progress.updated', payload: { progress: start.progress, requests: start.requests, activity: 'DNS resolution' } });
  assert.deepEqual(parseEvent(update, DEMO_SCAN), update);
  assert.equal(applyEvent(start, update).activity, 'DNS resolution');
  assert.equal(parseEvent(event(8, { type: 'task.progress.updated', payload: { progress: 0, requests: 0, activity: 42 } }), DEMO_SCAN), null);
});
test('live endpoint counts update from scan events and reject malformed counts', () => {
  const payload = { progress: 20, requests: 5, endpoints: 12, service_endpoints: 8, live_endpoints: 3 };
  const parsed = parseEvent(event(8, { type: 'task.progress.updated', payload }), DEMO_SCAN);
  assert.ok(parsed);
  assert.equal(applyEvent(demoSnapshot(), parsed).live_endpoints, 3);
  assert.equal(parseEvent(event(8, { type: 'task.progress.updated', payload: { ...payload, live_endpoints: -1 } }), DEMO_SCAN), null);
});
test('duplicate or old events never duplicate logs or regress the cursor', () => {
  const next = applyEvent(demoSnapshot(), event());
  assert.equal(next.last_event_id,8); assert.equal(next.logs.length,8);
  assert.equal(applyEvent(next,event()),next);
  assert.equal(applyEvent(next,event(3)),next);
});
test('out-of-order events buffer until the missing event arrives', () => {
  const pending = new Map(); const start = demoSnapshot();
  const waiting = applyOrderedEvent(start,event(10),pending);
  assert.equal(waiting,start);
  const partial = applyOrderedEvent(waiting,event(8),pending);
  assert.equal(partial.last_event_id,8);
  const complete = applyOrderedEvent(partial,event(9),pending);
  assert.equal(complete.last_event_id,10);
  assert.deepEqual(complete.logs.slice(-3).map(l=>l.id),[8,9,10]); assert.equal(pending.size,0);
});
test('a large event gap fails explicitly and does not grow the buffer', () => {
  const pending = new Map(); assert.throws(() => applyOrderedEvent(demoSnapshot(),event(500),pending), /replay buffer/); assert.equal(pending.size,0);
});
test('heartbeats never consume durable event IDs', () => {
  const start = demoSnapshot(); const heartbeat = event(99,{type:'heartbeat',payload:{}});
  assert.equal(applyOrderedEvent(start,heartbeat,new Map()),start);
});
test('stage, scan status, and finding changes update the snapshot', () => {
  let next = applyEvent(demoSnapshot(),event(8,{type:'stage.status.changed',payload:{stage:'Chaining'}}));
  assert.equal(next.stage,'Chaining'); assert.equal(next.progress,0);
  next = applyEvent(next,event(9,{type:'scan.status.changed',payload:{status:'completed'}})); assert.equal(next.status,'completed');
  next = applyEvent(next,event(10,{type:'finding.updated',payload:{...next.findings[0],status:'confirmed'}}));
  assert.equal(next.findings.length,4); assert.equal(next.findings.find(f=>f.id==='F-0042').status,'confirmed');
});
test('log retention is bounded while event cursor keeps advancing', () => {
  let next = demoSnapshot();
  for (let i=8;i<=700;i++) next=applyEvent(next,event(i));
  assert.equal(next.logs.length,500); assert.equal(next.last_event_id,700); assert.equal(next.logs[0].id,201);
});

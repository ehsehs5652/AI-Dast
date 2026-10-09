import type { Snapshot } from '../lib/events';

export const DEMO_SCAN = 'demo_local_042';
export function demoSnapshot(): Snapshot {
  return {
    version: 1, scan_id: DEMO_SCAN, last_event_id: 7, status: 'running', stage: 'Attack', progress: 62, requests: 391, budget: 2000, per_target_budget: 2000, endpoints: 218,
    findings: [
      { id: 'F-0042', title: '테스트 계정별 객체 접근 결과가 다름', severity: 'HIGH', status: 'unreviewed', endpoint: 'GET /api/accounts/{id}', cwe: 'CWE-639' },
      { id: 'F-0041', title: '검색 응답에 입력값이 반사됨', severity: 'MEDIUM', status: 'unreviewed', endpoint: 'GET /search', cwe: 'CWE-79' },
      { id: 'F-0040', title: '응답 헤더에 서버 버전이 노출됨', severity: 'LOW', status: 'confirmed', endpoint: 'GET /health', cwe: 'CWE-200' },
      { id: 'F-0039', title: '응답 보안 헤더가 누락됨', severity: 'INFO', status: 'rejected', endpoint: 'GET /', cwe: 'CWE-693' },
    ],
    logs: [
      { id: 1, time: '2026-09-20T05:28:00Z', stage: 'Scope', level: 'success', message: 'Demo Scope and approval hashes match. Only synthetic lab data is used.', audit_id: 'demo-1' },
      { id: 2, time: '2026-09-20T05:28:04Z', stage: 'Recon', level: 'success', message: 'Demo asset inventory finalized · 218 Recon.db paths' },
      { id: 3, time: '2026-09-20T05:28:09Z', stage: 'Recon', level: 'info', message: 'Handoff.json provenance verified · Pipeline.db created', audit_id: 'demo-2' },
      { id: 4, time: '2026-09-20T05:28:12Z', stage: 'Attack', level: 'info', message: 'Access control template batch started · task 84 of 136', audit_id: 'demo-3' },
      { id: 5, time: '2026-09-20T05:28:18Z', stage: 'Attack', level: 'warning', message: 'Response difference detected. Candidate requires validation.' },
      { id: 6, time: '2026-09-20T05:28:21Z', stage: 'Attack', level: 'success', message: 'Redacted evidence pair saved · credential references excluded' },
      { id: 7, time: '2026-09-20T05:28:24Z', stage: 'Attack', level: 'info', message: 'F-0042 added to review queue · matcher result alone is not a verdict', audit_id: 'demo-4' },
    ],
  };
}

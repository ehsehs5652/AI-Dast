export const stages = ['Scope', 'Recon', 'Attack', 'Chaining', 'Validation', 'Report'] as const;
export type Stage = typeof stages[number];
export type Level = 'info' | 'success' | 'warning' | 'error';
export type Finding = { id: string; title: string; severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'CRITICAL'; status: 'unreviewed' | 'confirmed' | 'rejected' | 'resolved'; endpoint: string; cwe: string };
export type Log = { id: number; time: string; stage: Stage; level: Level; message: string; message_code?: string | null; message_params?: Record<string, string | number>; audit_id?: string };
export type Snapshot = { version: 1; scan_id: string; last_event_id: number; status: 'running' | 'paused' | 'completed' | 'failed' | 'cancelled' | 'pending'; stage: Stage; stage_statuses?: Partial<Record<Stage, string>>; progress: number; activity?: string | null; requests: number; budget: number; per_target_budget?: number | null; endpoints: number; service_endpoints?: number; live_endpoints?: number; findings: Finding[]; logs: Log[]; scope_approved?: boolean; scope_id?: string; program_id?: string; program_name?: string };
export type ReportDraftStatus = 'loading' | 'present' | 'absent' | 'unavailable';
export function displayStageStatus(snapshot: Snapshot, selected: Stage, reportDraft: ReportDraftStatus): string {
  if (selected === 'Report') return reportDraft === 'present' ? 'completed' : reportDraft === 'absent' ? 'not_created' : 'unknown';
  if (snapshot.status === 'paused' && selected === snapshot.stage) return 'paused';
  const recorded = snapshot.stage_statuses?.[selected];
  if (recorded) return recorded;
  const position = stages.indexOf(selected);
  const current = stages.indexOf(snapshot.stage);
  if (position < current) return 'completed';
  if (position > current) return 'pending';
  return snapshot.status;
}
export function pipelineStageState(stage: Stage, snapshot: Pick<Snapshot, 'stage' | 'status'>): 'done' | 'current' | 'pending' | 'separate' {
  if (stage === 'Report' && snapshot.stage !== 'Report') return 'separate';
  const index = stages.indexOf(snapshot.stage);
  const position = stages.indexOf(stage);
  if (position < index || (position === index && snapshot.status === 'completed')) return 'done';
  return position === index ? 'current' : 'pending';
}
export type ScanEvent = { version: 1; event_id: number; scan_id: string; occurred_at: string } & (
  | { type: 'heartbeat'; payload: Record<string, unknown> }
  | { type: 'log.appended'; payload: Omit<Log, 'id' | 'time'> }
  | { type: 'task.progress.updated'; payload: { progress: number; requests: number; activity?: string | null; endpoints?: number; service_endpoints?: number; live_endpoints?: number } }
  | { type: 'stage.status.changed'; payload: { stage: Stage } }
  | { type: 'scan.status.changed'; payload: { status: Snapshot['status'] } }
  | { type: 'finding.updated'; payload: Finding }
);
const record = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const text = (v: unknown): v is string => typeof v === 'string' && v.length <= 16000;
const messageMetadata = (v: Record<string, unknown>): boolean =>
  (v.message_code === undefined || v.message_code === null || (text(v.message_code) && v.message_code.length <= 100))
  && (v.audit_id === undefined || (text(v.audit_id) && v.audit_id.length > 0 && v.audit_id.length <= 256))
  && (v.message_params === undefined || (record(v.message_params)
    && Object.keys(v.message_params).length <= 8
    && Object.values(v.message_params).every(item => typeof item === 'number' && Number.isFinite(item) || text(item) && item.length <= 180)));
const stage = (v: unknown): v is Stage => stages.includes(v as Stage);
const level = (v: unknown): v is Level => ['info', 'success', 'warning', 'error'].includes(v as string);
const status = (v: unknown) => ['running', 'paused', 'completed', 'failed', 'cancelled', 'pending'].includes(v as string);
const progress = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 100;
const finding = (v: unknown): v is Finding => record(v) && text(v.id) && text(v.title) && text(v.endpoint) && text(v.cwe) && ['HIGH','MEDIUM','LOW','INFO','CRITICAL'].includes(v.severity as string) && ['unreviewed','confirmed','rejected','resolved'].includes(v.status as string);
export function parseEvent(raw: unknown, scanId: string): ScanEvent | null {
  try {
    const e = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (!record(e) || e.version !== 1 || e.scan_id !== scanId || !integer(e.event_id) || !text(e.occurred_at) || !Number.isFinite(Date.parse(e.occurred_at)) || !record(e.payload)) return null;
    const p = e.payload;
    const valid = e.type === 'heartbeat' || (e.type === 'log.appended' && stage(p.stage) && level(p.level) && text(p.message) && messageMetadata(p)) || (e.type === 'task.progress.updated' && progress(p.progress) && integer(p.requests) && (p.activity === undefined || p.activity === null || text(p.activity)) && ['endpoints','service_endpoints','live_endpoints'].every(key => p[key] === undefined || integer(p[key]))) || (e.type === 'stage.status.changed' && stage(p.stage)) || (e.type === 'scan.status.changed' && status(p.status)) || (e.type === 'finding.updated' && finding(p));
    return valid ? e as ScanEvent : null;
  } catch { return null; }
}
export function parseSnapshot(value: unknown, scanId: string): Snapshot | null {
  if (!record(value) || value.version !== 1 || value.scan_id !== scanId || !integer(value.last_event_id) || !status(value.status) || !stage(value.stage) || !progress(value.progress) || !integer(value.requests) || !integer(value.budget) || !integer(value.endpoints) || !Array.isArray(value.findings) || !value.findings.every(finding) || !Array.isArray(value.logs)) return null;
  if (value.stage_statuses !== undefined && (!record(value.stage_statuses) || Object.entries(value.stage_statuses).some(([key, entry]) => !stage(key) || typeof entry !== 'string' || !['pending','running','completed','failed','blocked','skipped'].includes(entry)))) return null;
  if (['service_endpoints','live_endpoints'].some(key => value[key] !== undefined && !integer(value[key]))) return null;
  if ((value.scope_approved !== undefined && typeof value.scope_approved !== 'boolean') || (value.scope_id !== undefined && !text(value.scope_id)) || (value.program_id !== undefined && !text(value.program_id)) || (value.program_name !== undefined && !text(value.program_name))) return null;
  if (value.activity !== undefined && value.activity !== null && !text(value.activity)) return null;
  if (value.per_target_budget !== undefined && value.per_target_budget !== null && !integer(value.per_target_budget)) return null;
  if (!value.logs.every(l => record(l) && integer(l.id) && l.id <= (value.last_event_id as number) && text(l.time) && Number.isFinite(Date.parse(l.time)) && stage(l.stage) && level(l.level) && text(l.message) && messageMetadata(l))) return null;
  return { ...value, logs: [...new Map((value.logs as Log[]).map(l => [l.id, l])).values()].sort((a,b) => a.id-b.id).slice(-500) } as Snapshot;
}
export function applyEvent(snapshot: Snapshot, event: ScanEvent): Snapshot {
  if (event.scan_id !== snapshot.scan_id || event.type === 'heartbeat' || event.event_id <= snapshot.last_event_id) return snapshot;
  const next = { ...snapshot, last_event_id: event.event_id };
  switch (event.type) {
    case 'log.appended': return { ...next, logs: [...next.logs, { ...event.payload, id: event.event_id, time: event.occurred_at }].slice(-500) };
    case 'task.progress.updated': return { ...next, ...event.payload };
    case 'stage.status.changed': return { ...next, stage: event.payload.stage, progress: 0 };
    case 'scan.status.changed': return { ...next, status: event.payload.status };
    case 'finding.updated': return { ...next, findings: [...next.findings.filter(f => f.id !== event.payload.id), event.payload] };
  }
}

/** Per-scan sequence. Heartbeats do not consume durable IDs. Gaps wait for replay. */
export function applyOrderedEvent(snapshot: Snapshot, event: ScanEvent, pending: Map<number, ScanEvent>): Snapshot {
  if (event.scan_id !== snapshot.scan_id || event.type === 'heartbeat' || event.event_id <= snapshot.last_event_id) return snapshot;
  if (event.event_id > snapshot.last_event_id + 128) throw new Error('Event gap exceeds replay buffer. Refresh the snapshot.');
  pending.set(event.event_id, event);
  let next = snapshot;
  while (pending.has(next.last_event_id + 1)) {
    const queued = pending.get(next.last_event_id + 1)!;
    pending.delete(queued.event_id);
    next = applyEvent(next, queued);
  }
  return next;
}

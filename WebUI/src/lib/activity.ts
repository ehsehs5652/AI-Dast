import type { Level, Log, Stage } from './events';

export type ScopeActivityEvent = {
  job_id: string;
  event_id: number;
  occurred_at: string;
  level: string;
  message: string;
  message_code?: string | null;
  message_params?: Record<string, string | number>;
};

export type ActivityLog = {
  key: string;
  source: 'scope' | 'scan';
  stream: string;
  sequence: number;
  time: string;
  stage: Stage;
  level: Level;
  message: string;
  message_code?: string | null;
  message_params?: Record<string, string | number>;
  audit_id?: string;
};

export type ScopeActivityStatus =
  | 'scope_required'
  | 'collecting'
  | 'awaiting_browser'
  | 'paused'
  | 'cancelling'
  | 'cancelled'
  | 'review_required'
  | 'approved'
  | 'rejected'
  | 'failed';

export type ScopeActivityState = {
  polling: boolean;
  events: ScopeActivityEvent[];
};

export type ScopeActivityAction =
  | { type: 'job-selected'; status: ScopeActivityStatus }
  | { type: 'collection-started' }
  | { type: 'external-mutation' }
  | { type: 'dialog-closed' }
  | { type: 'program-status'; status: ScopeActivityStatus | undefined }
  | { type: 'job-response'; status: ScopeActivityStatus | undefined; events: ScopeActivityEvent[] }
  | { type: 'reset' };

export const initialScopeActivityState: ScopeActivityState = { polling: false, events: [] };

const activityLevel = (value: string): Level =>
  value === 'success' || value === 'warning' || value === 'error' ? value : 'info';

export function isScopeActivityActive(status: ScopeActivityStatus | undefined): boolean {
  return status === 'collecting' || status === 'awaiting_browser'
    || status === 'paused' || status === 'cancelling';
}

export function scopePollingAfterJobResponse(status: ScopeActivityStatus | undefined): boolean {
  return isScopeActivityActive(status);
}

export function shouldPollScopeJob({
  hasJob,
  polling,
  dialogOpen,
}: {
  hasJob: boolean;
  polling: boolean;
  dialogOpen: boolean;
}): boolean {
  return hasJob && (polling || dialogOpen);
}

export function reduceScopeActivity(
  state: ScopeActivityState,
  action: ScopeActivityAction,
): ScopeActivityState {
  switch (action.type) {
    case 'job-selected':
      return { polling: scopePollingAfterJobResponse(action.status), events: [] };
    case 'collection-started':
      return { polling: true, events: [] };
    case 'external-mutation':
      return { ...state, polling: true };
    case 'job-response':
      return {
        polling: scopePollingAfterJobResponse(action.status),
        events: action.events,
      };
    case 'dialog-closed':
    case 'program-status':
      return state;
    case 'reset':
      return initialScopeActivityState;
  }
}

export type ScopeJobPollResult<T> = {
  status: ScopeActivityStatus | undefined;
  payload: T;
};

export type ScopeJobPoller = {
  first: Promise<void>;
  stop: () => void;
};

export function startScopeJobPolling<T>({
  repeat,
  load,
  onResponse,
  onError,
  intervalMs = 1000,
  schedule = (callback, delay) => window.setInterval(callback, delay),
  cancel = handle => window.clearInterval(handle),
}: {
  repeat: boolean;
  load: (signal: AbortSignal) => Promise<ScopeJobPollResult<T>>;
  onResponse: (result: ScopeJobPollResult<T>) => void;
  onError: (error: unknown) => void;
  intervalMs?: number;
  schedule?: (callback: () => void, delay: number) => number;
  cancel?: (handle: number) => void;
}): ScopeJobPoller {
  const abort = new AbortController();
  let timer: number | undefined;
  let stopped = false;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    abort.abort();
    if (timer !== undefined) {
      cancel(timer);
      timer = undefined;
    }
  };
  const poll = async () => {
    try {
      const result = await load(abort.signal);
      if (stopped) return;
      onResponse(result);
      if (!scopePollingAfterJobResponse(result.status)) stop();
    } catch (error) {
      if (!stopped && !abort.signal.aborted) onError(error);
    }
  };
  if (repeat) timer = schedule(() => void poll(), intervalMs);
  const first = poll();
  return { first, stop };
}

export function startScopeElapsedClock({
  onTick,
  now = () => Date.now(),
  schedule = (callback, delay) => window.setInterval(callback, delay),
  cancel = handle => window.clearInterval(handle),
}: {
  onTick: (now: number) => void;
  now?: () => number;
  schedule?: (callback: () => void, delay: number) => number;
  cancel?: (handle: number) => void;
}): { stop: () => void } {
  let stopped = false;
  const timer = schedule(() => {
    if (!stopped) onTick(now());
  }, 1000);
  onTick(now());
  return {
    stop: () => {
      if (stopped) return;
      stopped = true;
      cancel(timer);
    },
  };
}

export function formatActivityElapsed(seconds: number, language: 'ko' | 'en' = 'ko'): string {
  const wholeSeconds = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(wholeSeconds / 60);
  const remainder = wholeSeconds % 60;
  if (language === 'en') return minutes > 0 ? `${minutes}m ${remainder}s` : `${remainder}s`;
  return minutes > 0 ? `${minutes}분 ${remainder}초` : `${remainder}초`;
}

export function mergeActivityLogs(
  scanLogs: readonly Log[],
  scopeEvents: readonly ScopeActivityEvent[],
): ActivityLog[] {
  const scopeLogs: ActivityLog[] = scopeEvents.map(event => ({
    key: `scope:${event.job_id}:${event.event_id}`,
    source: 'scope',
    stream: `scope:${event.job_id}`,
    sequence: event.event_id,
    time: event.occurred_at,
    stage: 'Scope',
    level: activityLevel(event.level),
    message: event.message,
    message_code: event.message_code,
    message_params: event.message_params,
  }));
  const normalizedScanLogs: ActivityLog[] = scanLogs.map(log => ({
    key: `scan:${log.id}`,
    source: 'scan',
    stream: 'scan',
    sequence: log.id,
    time: log.time,
    stage: log.stage,
    level: log.level,
    message: log.message,
    message_code: log.message_code,
    message_params: log.message_params,
    audit_id: log.audit_id,
  }));
  return [...scopeLogs, ...normalizedScanLogs]
    .sort((left, right) => {
      const millisecondOrder = Date.parse(left.time) - Date.parse(right.time);
      if (millisecondOrder !== 0) return millisecondOrder;
      const preciseTimeOrder = left.time.localeCompare(right.time);
      if (preciseTimeOrder !== 0) return preciseTimeOrder;
      if (left.stream === right.stream) return left.sequence - right.sequence;
      return left.stream.localeCompare(right.stream);
    })
    .slice(-500);
}

export function hideAcknowledgedActivity(logs: readonly ActivityLog[], acknowledgedIds: ReadonlySet<string>): ActivityLog[] {
  return logs.filter(log => !log.audit_id || !acknowledgedIds.has(log.audit_id));
}

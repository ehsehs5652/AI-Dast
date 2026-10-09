export type AuditLevel = 'info' | 'success' | 'warning' | 'error';
export type AuditEntry = {
  id: string;
  event_type: string;
  stage: string;
  created_at: string;
  task_id?: string | null;
  level?: AuditLevel;
  message_code?: string;
  message_params?: Record<string, string | number>;
  failure_code?: string | null;
};

type AuditStorage = Pick<Storage, 'getItem' | 'setItem'>;
const keyFor = (scanId: string) => `aidast:audit-ack:v1:${scanId}`;

export function readAuditAcknowledgements(storage: AuditStorage, scanId: string): Set<string> {
  try {
    const stored: unknown = JSON.parse(storage.getItem(keyFor(scanId)) || '[]');
    return new Set(Array.isArray(stored) ? stored.filter((id): id is string => typeof id === 'string' && id.length <= 256).slice(-5000) : []);
  } catch {
    return new Set();
  }
}

export function saveAuditAcknowledgements(storage: AuditStorage, scanId: string, ids: Set<string>): boolean {
  try {
    storage.setItem(keyFor(scanId), JSON.stringify([...ids].slice(-5000)));
    return true;
  } catch {
    return false;
  }
}

export function auditLevel(item: AuditEntry): AuditLevel {
  if (item.level && ['info', 'success', 'warning', 'error'].includes(item.level)) return item.level;
  if (/(failed|invalid|error)/i.test(item.event_type)) return 'error';
  if (/(cancelled|blocked|denied)/i.test(item.event_type)) return 'warning';
  if (/(completed|confirmed|approved)/i.test(item.event_type)) return 'success';
  return 'info';
}

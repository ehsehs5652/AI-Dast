import { useEffect, useState } from 'react';
import { applyEvent, applyOrderedEvent, parseEvent, parseSnapshot, type Snapshot, type ScanEvent } from '../lib/events';
import { demoSnapshot } from '../data/demo';

export const transportMode = import.meta.env.VITE_TRANSPORT === 'live' ? 'live' : 'demo';
type Connection = 'idle' | 'loading' | 'demo' | 'connecting' | 'live' | 'reconnecting' | 'offline';
export function useScanSocket(scanId: string) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(transportMode === 'demo' ? demoSnapshot : null);
  const [state, setState] = useState<Connection>(transportMode === 'demo' ? 'demo' : 'loading');
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (transportMode === 'demo') {
      let current = demoSnapshot();
      setSnapshot(current);
      let tick = 0;
      const messages = ['Policy budget checked · synthetic requests scheduled', 'Comparing response signatures across fixture accounts', 'attack_attempts evidence references linked · secrets redacted', 'Template batch complete · candidates remain unreviewed'];
      const timer = window.setInterval(() => {
        tick++;
        const event: ScanEvent = { version: 1, event_id: current.last_event_id + 1, scan_id: current.scan_id, occurred_at: new Date().toISOString(), type: 'log.appended', payload: { stage: 'Attack', level: tick % 4 === 0 ? 'success' : 'info', message: messages[(tick - 1) % messages.length] } };
        current = applyEvent(current, event);
        if (current.progress < 96) current = applyEvent(current, { ...event, event_id: current.last_event_id + 1, type: 'task.progress.updated', payload: { progress: Math.min(96, current.progress + 1), requests: current.requests + 2 } });
        setSnapshot(current);
      }, 4200);
      return () => window.clearInterval(timer);
    }
    if (!scanId) {
      setSnapshot(null);
      setState('idle');
      setError('No scans are available yet. Use New scan to start from a verified approved Scope.');
      return;
    }
    let disposed = false;
    let socket: WebSocket | null = null;
    let retry: number | undefined;
    let watchdog: number | undefined;
    let attempts = 0;
    let lastSeen = Date.now();
    let current: Snapshot | null = null;
    const abort = new AbortController();
    const pending = new Map<number, ScanEvent>();
    setSnapshot(null); setState('loading'); setError('');
    const schedule = () => {
      if (disposed) return;
      setState('reconnecting');
      const delay = Math.min(1000 * 2 ** Math.min(attempts++, 5), 30000) + Math.random() * 500;
      retry = window.setTimeout(connect, delay);
    };
    const connect = () => {
      if (disposed || !current) return;
      setState(attempts ? 'reconnecting' : 'connecting');
      try {
        const base = import.meta.env.VITE_WS_BASE_URL || `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}`;
        const url = new URL(`/ws/scans/${encodeURIComponent(scanId)}`, base);
        url.searchParams.set('after', String(current.last_event_id));
        const ws = new WebSocket(url);
        socket = ws;
        ws.onopen = () => { lastSeen = Date.now(); setState('live'); };
        ws.onmessage = ({ data }) => {
          if (disposed || ws !== socket || !current) return;
          const event = parseEvent(data, scanId);
          if (!event) { setError('An invalid or unsupported event was ignored.'); return; }
          lastSeen = Date.now(); attempts = 0;
          try { current = applyOrderedEvent(current, event, pending); setSnapshot(current); }
          catch (e) { setError(e instanceof Error ? e.message : 'Event replay failed'); ws.close(); }
        };
        ws.onerror = () => ws.close();
        ws.onclose = () => { if (ws === socket) { pending.clear(); schedule(); } };
      } catch { setError('Unable to open the event connection. Check the configured URL.'); schedule(); }
    };
    const fetchSnapshot = async () => {
      const timeout = window.setTimeout(() => abort.abort(), 15000);
      try {
        const base = import.meta.env.VITE_API_BASE_URL || location.origin;
        const response = await fetch(new URL(`/api/v1/scans/${encodeURIComponent(scanId)}`, base), { signal: abort.signal, credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) throw new Error(`Snapshot request returned ${response.status}`);
        const data = parseSnapshot(await response.json(), scanId);
        if (!data) throw new Error('The backend returned an invalid snapshot');
        if (disposed) return;
        current = data; setSnapshot(data); connect();
        watchdog = window.setInterval(() => {
          if (socket?.readyState === WebSocket.OPEN && (Date.now() - lastSeen > 45000 || pending.size > 0)) socket.close();
        }, 10000);
      } catch (e) { if (!disposed) { setState('offline'); setError(e instanceof Error ? e.message : 'Snapshot unavailable'); } }
      finally { window.clearTimeout(timeout); }
    };
    void fetchSnapshot();
    return () => { disposed = true; abort.abort(); window.clearTimeout(retry); window.clearInterval(watchdog); if (socket) { socket.onclose = null; socket.onmessage = null; socket.onopen = null; socket.onerror = null; socket.close(); } };
  }, [scanId, revision]);
  return { snapshot, state, error, refresh: () => setRevision(v => v + 1) };
}

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder, AnnotationBatch, safe_url
from aidast.recon.surface import export_surface
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture


class FakeAgent:
    def __init__(self, invalid=False):
        self.invalid = invalid

    def _run_structured(self, **kwargs):
        self.prompt = kwargs['prompt']
        payload = json.loads(self.prompt.split('\n', 1)[1])
        return AnnotationBatch(annotations=[{
            'observation_id': 'invented' if self.invalid else o['observation_id'],
            'category': 'function', 'tag': 'unknown',
            'rationale': '기능을 판단할 근거가 부족함', 'confidence': None,
        } for o in payload['observations']])


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'recon.db'
        self.conn = db.init_db(self.path)
        db.insert_scan(self.conn, scan_id='scan', scope_type='test', scope_value='example')
        asset = db.insert_asset(self.conn, scan_id='scan', identifier='example.com', asset_type='DOMAIN')
        self.origin = db.upsert_origin(self.conn, asset_id=asset, scheme='https', host='example.com', port=443, base_url='https://example.com')

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def items(self):
        return [{'method': 'POST', 'path': '/api/session', 'source': 'playwright_login',
                 'context': {'context_key': key, 'page_url': page,
                             'action_type': 'click', 'action_target': 'Login'}}
                for key, page in [('one', '/login'), ('two', '/reauth')]]

    def test_preserves_multiple_contexts_and_exports_evidence(self):
        agent = FakeAgent()
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan', agent=agent)
        recorder.record('login', self.items())
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoints').fetchone()[0], 1)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM discovery_contexts').fetchone()[0], 2)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoint_annotations').fetchone()[0], 2)
        target = Path(self.temp.name) / 'surface.json'
        export_surface(self.conn, scan_id='scan', output_path=target)
        output = json.loads(target.read_text())
        endpoint = output['origins'][0]['endpoints'][0]
        self.assertEqual(endpoint['path'], '/api/session')
        self.assertEqual(len(endpoint['observations']), 2)
        self.assertEqual(len(endpoint['annotations']), 2)
        self.assertEqual(output['annotation_runs'][0]['status'], 'completed')

    def test_invalid_llm_output_keeps_observations_without_partial_tags(self):
        recorder = ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan', agent=FakeAgent(True))
        recorder.record('login', self.items())
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoint_observations').fetchone()[0], 2)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM endpoint_annotations').fetchone()[0], 0)
        self.assertEqual(self.conn.execute('SELECT status FROM annotation_runs').fetchone()[0], 'failed')

    def test_proxy_links_endpoint_and_scan_without_guessing_page(self):
        ObservationRecorder(self.conn, origin_id=self.origin, scan_id='scan').record('login', self.items())
        capture = Path(self.temp.name) / 'capture.jsonl'
        capture.write_text(json.dumps({'method': 'POST', 'url': 'https://example.com/api/session', 'response_status': 200}) + '\n')
        self.assertEqual(ingest_mitm_capture(self.conn, capture, origin_id=self.origin), (1, 0))
        row = self.conn.execute('SELECT endpoint_id, origin_id FROM http_transactions').fetchone()
        self.assertIsNotNone(row[0])
        self.assertEqual(row[1], self.origin)
        self.assertEqual(self.conn.execute("SELECT context_id FROM endpoint_observations WHERE source_tool='mitmproxy'").fetchone(), (None,))

    def test_url_sanitization(self):
        self.assertEqual(safe_url('https://user:password@example.com/login?token=secret#secret'), 'https://example.com/login')

    def test_legacy_migration_is_idempotent_and_preserves_rows(self):
        legacy = Path(self.temp.name) / 'legacy.db'
        conn = sqlite3.connect(legacy)
        conn.executescript(db.SCHEMA)
        conn.execute("INSERT INTO http_transactions(http_transaction_id,method,url) VALUES ('old','GET','https://example.com')")
        conn.commit()
        conn.close()
        for _ in range(2):
            conn = db.init_db(legacy)
            self.assertEqual(conn.execute('SELECT http_transaction_id, origin_id FROM http_transactions').fetchall(), [('old', None)])
            self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0], 4)
            self.assertEqual(conn.execute('PRAGMA foreign_key_check').fetchall(), [])
            conn.close()


if __name__ == '__main__':
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aidast.recon.tools.endpoint_discovery import _parse_katana_output, discover_with_ffuf
from aidast.recon.annotations import ObservationRecorder
import test_recon_annotations as fixtures


class ToolEvidenceTests(unittest.TestCase):
    def test_katana_json_keeps_method_parent_and_response_without_secrets(self):
        record = {'request': {'endpoint': 'https://example.com/api/session?token=hidden',
                  'method': 'POST', 'source': 'https://example.com/login?secret=hidden',
                  'tag': 'form', 'attribute': 'action', 'headers': {'Cookie': 'hidden'}},
                  'response': {'status_code': 302, 'headers': {'content_type': 'text/html',
                  'location': '/account?token=hidden', 'set_cookie': 'hidden'}, 'body': 'hidden'}}
        items = _parse_katana_output(json.dumps(record) + '\n{bad\n[]', base_url='https://example.com', source='katana')
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['method'], 'POST')
        self.assertEqual(items[0]['evidence']['parent_url'], 'https://example.com/login')
        self.assertEqual(items[0]['evidence']['redirect_url'], '/account')
        self.assertEqual(items[0]['evidence']['response_status'], 302)
        self.assertNotIn('hidden', json.dumps(items))

    def test_ffuf_preserves_multiple_root_observations(self):
        def run(command, **kwargs):
            Path(command[command.index('-o') + 1]).write_text(json.dumps({'results': [{
                'url': 'https://example.com/api/login', 'status': 302, 'length': 51,
                'words': 3, 'lines': 1, 'content-type': 'text/html',
                'redirectlocation': '/login?token=hidden', 'input': {'FUZZ': 'hidden'},
            }]}))
            return SimpleNamespace(returncode=0)
        with tempfile.NamedTemporaryFile() as wordlist, patch('aidast.recon.tools.endpoint_discovery.shutil.which', return_value='/bin/ffuf'), patch('aidast.recon.tools.endpoint_discovery.subprocess.run', side_effect=run):
            items = discover_with_ffuf('https://example.com', wordlist=wordlist.name,
                seed_endpoints=[{'path': '/api/users', 'source': 'katana'}], auth_headers=None,
                root_selector=lambda _: ['/', '/api'])
        self.assertEqual(len(items), 1)
        self.assertEqual(len(items[0]['observation_variants']), 2)
        self.assertEqual(items[0]['evidence']['content_length'], 51)
        self.assertNotIn('hidden', json.dumps(items))


class EvidencePersistenceTests(unittest.TestCase):
    def test_evidence_reaches_db_and_llm_and_surface(self):
        fixture = fixtures.ObservationTests()
        fixture.setUp()
        try:
            agent = fixtures.FakeAgent()
            item = {'method': 'GET', 'path': '/api', 'source': 'ffuf',
                    'evidence': {'response_status': 401, 'content_length': 51,
                                 'request_body': 'hidden', 'redirect_url': '/login?token=hidden'}}
            ObservationRecorder(fixture.conn, origin_id=fixture.origin, scan_id='scan', agent=agent).record('ffuf', [item])
            saved = json.loads(fixture.conn.execute('SELECT evidence_json FROM endpoint_observations').fetchone()[0])
            self.assertEqual(saved, {'redirect_url': '/login', 'response_status': 401, 'content_length': 51})
            self.assertIn('"response_status": 401', agent.prompt)
            self.assertNotIn('hidden', agent.prompt)
            from aidast.recon.surface import export_surface
            target = Path(fixture.temp.name) / 'surface.json'
            export_surface(fixture.conn, scan_id='scan', output_path=target)
            result = json.loads(target.read_text())
            self.assertEqual(result['origins'][0]['endpoints'][0]['observations'][0]['evidence'], saved)
        finally:
            fixture.tearDown()

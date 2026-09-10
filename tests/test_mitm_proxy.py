from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aidast.recon.tools.mitm_proxy import start_mitmproxy


class MitmProxyStartupTests(unittest.TestCase):
    def test_default_start_uses_a_dynamically_selected_port(self) -> None:
        process = MagicMock()
        with tempfile.TemporaryDirectory() as temporary_dir:
            with (
                patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
                patch("aidast.recon.tools.mitm_proxy._find_free_port", return_value=43123),
                patch("aidast.recon.tools.mitm_proxy.subprocess.Popen", return_value=process) as popen,
                patch("aidast.recon.tools.mitm_proxy._wait_for_proxy_port", return_value=True) as wait,
            ):
                returned_process, proxy_url = start_mitmproxy(
                    Path(temporary_dir) / "capture.jsonl"
                )

        self.assertIs(returned_process, process)
        self.assertEqual(proxy_url, "http://127.0.0.1:43123")
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("-p") + 1], "43123")
        self.assertEqual(wait.call_args.kwargs["process"], process)

    def test_explicit_occupied_port_is_not_mistaken_for_started_proxy(self) -> None:
        occupied = MagicMock()
        occupied.__enter__.return_value = occupied
        with (
            patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
            patch("aidast.recon.tools.mitm_proxy.socket.create_connection", return_value=occupied),
            patch("aidast.recon.tools.mitm_proxy.subprocess.Popen") as popen,
        ):
            process, proxy_url = start_mitmproxy(Path("capture.jsonl"), port=8080)

        self.assertIsNone(process)
        self.assertIsNone(proxy_url)
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()

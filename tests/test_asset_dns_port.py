from __future__ import annotations

import unittest
from unittest.mock import patch

from aidast.recon.tools.asset_dns_port import run_naabu, run_nmap


class PortPolicyTests(unittest.TestCase):
    def test_empty_allowed_ports_skip_port_tools(self) -> None:
        with patch("aidast.recon.tools.asset_dns_port._run_tool") as run_tool:
            self.assertEqual(run_naabu(["example.com"], ports=[]), [])
        run_tool.assert_not_called()

        with patch("aidast.recon.tools.asset_dns_port.shutil.which") as which:
            self.assertEqual(run_nmap(["example.com"], ports=[]), [])
        which.assert_not_called()

    def test_naabu_receives_only_policy_allowed_ports(self) -> None:
        with patch(
            "aidast.recon.tools.asset_dns_port._run_tool", return_value=[]
        ) as run_tool:
            run_naabu(["example.com"], ports=[443, 8443])

        self.assertEqual(
            run_tool.call_args.args[0],
            ["naabu", "-silent", "-p", "443,8443"],
        )


if __name__ == "__main__":
    unittest.main()

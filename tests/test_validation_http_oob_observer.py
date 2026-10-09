"""Configured HTTP OOB observer authentication and cursor tests."""

import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from aidast.validation import HttpJsonOobObserver, HttpOobObserverConfig


class Response:
    status = 200

    def __init__(self, value):
        self.body = json.dumps(value).encode("utf-8")
        self.closed = False

    def read(self, maximum):
        return self.body

    def close(self):
        self.closed = True


class HttpJsonOobObserverTests(unittest.TestCase):
    def test_arm_cursor_excludes_stale_events_and_auth_is_runtime_only(self):
        calls = []

        def transport(request, timeout):
            calls.append((request, timeout))
            if request.get_method() == "POST":
                self.assertEqual(json.loads(request.data), {"token": "attempt.cb.test"})
                return Response({"cursor": 10})
            return Response({"events": [
                {"cursor": 10, "token": "attempt.cb.test", "protocol": "dns"},
                {"cursor": 11, "token": "attempt.cb.test", "protocol": "https"},
                {"cursor": 12, "token": "wrong.cb.test", "protocol": "dns"},
            ]})

        config = HttpOobObserverConfig(
            arm_url="https://observer.test/v1/arm",
            poll_url="https://observer.test/v1/events",
            auth_env="AIDAST_TEST_OOB_HEADERS",
        )
        observer = HttpJsonOobObserver(config, transport=transport)
        with patch.dict(os.environ, {
            "AIDAST_TEST_OOB_HEADERS": json.dumps({"Authorization": "Bearer private"}),
        }):
            observer.arm("attempt.cb.test")
            snapshot = observer.poll("attempt.cb.test", wait_seconds=3)

        self.assertEqual(snapshot, {"events": [
            {"token": "attempt.cb.test", "protocol": "https"},
            {"token": "wrong.cb.test", "protocol": "dns"},
        ]})
        self.assertEqual([call[0].get_method() for call in calls], ["POST", "GET"])
        query = parse_qs(urlsplit(calls[1][0].full_url).query)
        self.assertEqual(query, {
            "token": ["attempt.cb.test"], "after": ["10"], "wait_seconds": ["3.000"],
        })
        self.assertEqual(calls[0][0].get_header("Authorization"), "Bearer private")
        with self.assertRaisesRegex(ValueError, "not armed"):
            observer.poll("attempt.cb.test", wait_seconds=0)

    def test_environment_config_is_optional_and_rejects_insecure_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(HttpJsonOobObserver.from_environment())
        with patch.dict(os.environ, {
            "AIDAST_OOB_OBSERVER_CONFIG": json.dumps({
                "arm_url": "https://observer.test/arm",
                "poll_url": "https://observer.test/events",
            }),
        }):
            self.assertIsInstance(
                HttpJsonOobObserver.from_environment(transport=lambda request, timeout: None),
                HttpJsonOobObserver,
            )
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            HttpOobObserverConfig(
                arm_url="http://observer.test/arm",
                poll_url="http://observer.test/events",
            )

    def test_arm_and_poll_must_share_one_origin(self):
        with self.assertRaisesRegex(ValueError, "one origin"):
            HttpOobObserverConfig(
                arm_url="https://arm.test/v1/arm",
                poll_url="https://poll.test/v1/events",
            )


if __name__ == "__main__":
    unittest.main()

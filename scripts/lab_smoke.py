"""Small loopback-only HTTP availability check."""

from __future__ import annotations

import argparse
import http.client
import json
import statistics
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit


def local_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or not port or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise argparse.ArgumentTypeError("use http://127.0.0.1:<port>/")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="append", required=True, type=local_url)
    args = parser.parse_args()
    results = []
    for url in dict.fromkeys(args.url):
        attempts = []
        for index in range(3):
            if index:
                time.sleep(1)
            connection = http.client.HTTPConnection("127.0.0.1", urlsplit(url).port, timeout=5)
            started = time.perf_counter()
            try:
                connection.request("GET", "/", headers={"User-Agent": "aidast-lab-smoke/1"})
                response = connection.getresponse()
                sample = response.read(65536)
                attempts.append({
                    "status": response.status,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                    "sample_bytes": len(sample),
                    "ok": response.status == 200 and bool(sample),
                })
            except (OSError, http.client.HTTPException) as exc:
                attempts.append({"ok": False, "error": str(exc)})
            finally:
                connection.close()
        times = [item["elapsed_ms"] for item in attempts if item.get("ok")]
        results.append({
            "url": url, "attempts": attempts,
            "ok": all(item["ok"] for item in attempts),
            "median_elapsed_ms": statistics.median(times) if times else None,
        })
    document = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "check": "homepage availability, up to 64 KiB; no redirects followed",
        "results": results,
    }
    print(json.dumps(document, ensure_ascii=False, indent=2))
    return 0 if all(item["ok"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

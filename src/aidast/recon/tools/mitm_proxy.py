"""mitmdump 프로세스를 띄우고/끄고, 캡처된 JSONL을 DB로 적재하는 헬퍼.

katana/ffuf/Playwright 전부가 이 프록시를 거쳐가게 되며, mitmdump가
정책 강제가 필수인 경우에는 시작 실패를 오류로 보고한다.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sqlite3
import tempfile
import time
from pathlib import Path

from aidast.recon import db as dbmod
from aidast.core.http_safety import sanitize_headers, validate_scope_rules

_ADDON_PATH = Path(__file__).parent / "mitm_addon.py"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _wait_for_proxy_port(
    port: int,
    *,
    process: subprocess.Popen | None = None,
    timeout: float = 8.0,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def start_mitmproxy(
    capture_path: Path, *, port: int | None = None, scope_rules: dict | None = None,
) -> tuple[subprocess.Popen | None, str | None]:
    required = scope_rules is not None and scope_rules.get("enforcement_required", True) is not False
    if scope_rules is not None:
        validate_scope_rules(scope_rules)
    if shutil.which("mitmdump") is None:
        if required:
            raise RuntimeError("required policy proxy is unavailable: mitmdump is not installed")
        print("  [건너뜀] mitmdump 미설치 - mitmproxy 관찰 없이 진행")
        return None, None

    selected_port = port if port is not None else _find_free_port()
    if port is not None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                if required:
                    raise RuntimeError("required policy proxy port is already in use")
                print(f"  [경고] 요청한 mitmproxy 포트 {port}가 이미 사용 중")
                return None, None
        except OSError:
            pass

    command = [
        "mitmdump", "-s", str(_ADDON_PATH), "-p", str(selected_port),
        "--set", "http2=false",
        "--set", f"out_file={capture_path}",
        "--set", f"enforcement_required={'true' if required else 'false'}",
    ]

    if scope_rules is not None:
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        )
        scope_file = Path(handle.name)
        json.dump(scope_rules, handle)
        handle.close()
        command += ["--set", f"scope_file={scope_file}"]

    try:
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        if required:
            raise RuntimeError("required policy proxy could not start") from exc
        print(f"  [경고] mitmdump 실행 실패: {exc} - mitmproxy 관찰 없이 진행")
        return None, None

    if not _wait_for_proxy_port(selected_port, process=proc):
        print("  [경고] mitmdump가 제시간에 포트를 열지 않음 - mitmproxy 관찰 없이 진행")
        proc.terminate()
        if required:
            raise RuntimeError("required policy proxy did not become ready")
        return None, None

    print(f"  [mitmproxy] 127.0.0.1:{selected_port}에서 관찰 시작")
    return proc, f"http://127.0.0.1:{selected_port}"


def stop_mitmproxy(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def ingest_mitm_capture(conn: sqlite3.Connection, jsonl_path: Path, *, origin_id: str | None = None) -> tuple[int, int]:
    if not jsonl_path.is_file():
        return 0, 0

    count = 0
    blocked = 0
    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("policy_blocked", False):
                blocked += 1
                continue
            capture_bodies = record.get("capture_bodies", False) is True
            request_body = record.get("request_body") if capture_bodies else None
            response_body = record.get("response_body") if capture_bodies else None
            endpoint_id = None
            if origin_id is not None:
                from urllib.parse import urlsplit
                from aidast.recon.judgment import normalize_path
                row = conn.execute(
                    "SELECT endpoint_id FROM endpoints WHERE origin_id=? AND method=? AND normalized_path=?",
                    (origin_id, record["method"].upper(), normalize_path(urlsplit(record["url"]).path)),
                ).fetchone()
                endpoint_id = row[0] if row else None
            transaction_id = dbmod.insert_http_transaction(
                conn,
                endpoint_id=endpoint_id,
                source=record.get("source", "mitmproxy"),
                method=record["method"],
                url=record["url"],
                request_headers=sanitize_headers(record.get("request_headers")),
                request_body=request_body.encode("utf-8") if request_body else None,
                response_status=record.get("response_status"),
                response_headers=sanitize_headers(record.get("response_headers")),
                response_body=response_body.encode("utf-8") if response_body else None,
                content_type=record.get("content_type"),
            )
            if origin_id is not None:
                conn.execute("UPDATE http_transactions SET origin_id=? WHERE http_transaction_id=?",
                             (origin_id, transaction_id))
                if endpoint_id is not None:
                    from aidast.recon.annotations import safe_url
                    conn.execute("""INSERT INTO endpoint_observations
                        (observation_id,endpoint_id,http_transaction_id,source_tool,
                         discovery_kind,observed_url,association_method,observed_at)
                        VALUES (?,?,?,'mitmproxy','http_request',?,'proxy_capture',?)""",
                        (dbmod.new_id('observation'), endpoint_id, transaction_id,
                         safe_url(record['url']), record.get('captured_at') or dbmod.now()))
                conn.commit()
            count += 1

    jsonl_path.unlink(missing_ok=True)
    return count, blocked

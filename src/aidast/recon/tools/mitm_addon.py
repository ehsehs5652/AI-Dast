"""mitmdump가 로드하는 addon 스크립트.

mitmdump -s tools/mitm_addon.py -p 8080 \\
    --set out_file=mitm_capture.jsonl \\
    --set scope_file=/path/to/scope_rules.json

역할 두 가지:
1. 지나가는 모든 요청/응답을 한 쌍으로 JSONL 파일에 append(관찰)
2. scope_file이 주어지면 그 안의 allowed_hosts에 없는 호스트로 가는
   요청을 막는다(스코프 강제). 필수 설정이 없거나 잘못되면 요청을 막는다.

이 파일은 mitmdump 자체 파이썬 프로세스 안에서 실행되므로(우리 aidast
패키지가 깔린 venv가 아님), aidast 쪽 코드를 import하지 않는다.
"""

from __future__ import annotations

import json
import runpy
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import ctx, http

# mitmdump may use a different Python environment; load only the dependency-free
# shared helpers, without importing aidast's Pydantic-dependent package modules.
_safety = runpy.run_path(str(Path(__file__).resolve().parents[2] / "core" / "http_safety.py"))
sanitize_headers = _safety["sanitize_headers"]
validate_scope_rules = _safety["validate_scope_rules"]


class ScopeAndCaptureAddon:
    def __init__(self) -> None:
        self.allowed_hosts: set[str] = set()
        self.scope_loaded = False
        self.out_path: Path | None = None
        self.rules: dict = {}
        self.request_count = 0
        self.enforcement_required = True

    def load(self, loader) -> None:
        loader.add_option(
            name="scope_file",
            typespec=str,
            default="",
            help="승인된 Scope에서 뽑은 allow-list JSON 경로.",
        )
        loader.add_option(name="enforcement_required", typespec=bool, default=True,
                          help="정책 설정이 없거나 잘못되면 요청 차단.")
        loader.add_option(
            name="out_file",
            typespec=str,
            default="mitm_capture.jsonl",
            help="캡처한 요청/응답을 append하는 JSONL 경로.",
        )

    def configure(self, updated) -> None:
        if "enforcement_required" in updated:
            self.enforcement_required = ctx.options.enforcement_required
        if "scope_file" in updated:
            self.scope_loaded = False
            self.allowed_hosts = set()
            self.rules = {}
            try:
                if not ctx.options.scope_file:
                    raise ValueError("scope_file is missing")
                path = Path(ctx.options.scope_file)
                data = validate_scope_rules(json.loads(path.read_text(encoding="utf-8")))
                self.allowed_hosts = set(data.get("allowed_hosts", []))
                self.rules = data
                self.scope_loaded = True
                ctx.log.info(f"[scope] {len(self.allowed_hosts)}개 호스트 로드됨")
            except (OSError, ValueError, TypeError):
                ctx.log.warn("[scope] 유효한 scope_file 설정 없음")

        if "out_file" in updated and ctx.options.out_file:
            self.out_path = Path(ctx.options.out_file)

    def request(self, flow: http.HTTPFlow) -> None:
        if not self.scope_loaded:
            if self.enforcement_required:
                self._block(flow)
            return
        try:
            parsed = urlsplit(flow.request.pretty_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            self._block(flow)
            return
        host = (parsed.hostname or "").lower().rstrip(".")
        allowed_hosts = {value.lower().rstrip(".") for value in self.allowed_hosts}
        include_subdomains = bool(self.rules.get("include_subdomains", False))
        host_allowed = host in allowed_hosts or (
            include_subdomains
            and any(host.endswith("." + root) for root in allowed_hosts)
        )
        path = parsed.path or "/"
        allowed_paths = self.rules.get("allowed_path_prefixes", ["/"])
        excluded_paths = self.rules.get("excluded_path_prefixes", [])
        allowed_methods = self.rules.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
        max_requests = int(self.rules.get("max_requests", 3000))
        boundary_allowed = (
            host_allowed
            and not (parsed.username or parsed.password)
            and parsed.scheme in self.rules.get("allowed_schemes", ["https"])
            and port in self.rules.get("allowed_ports", [443])
            and flow.request.method.upper() in allowed_methods
            and any(self._path_matches(path, prefix) for prefix in allowed_paths)
            and not any(self._path_matches(path, prefix) for prefix in excluded_paths)
        )
        if boundary_allowed:
            self.request_count += 1
        allowed = boundary_allowed and self.request_count <= max_requests
        if not allowed:
            self._block(flow)

    @staticmethod
    def _block(flow: http.HTTPFlow) -> None:
        ctx.log.warn("[scope 차단] TargetPolicy가 요청을 허용하지 않음")
        flow.metadata["aidast_policy_blocked"] = True
        flow.response = http.Response.make(
            403, b"Blocked by AI-DAST TargetPolicy\n",
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    @staticmethod
    def _path_matches(path: str, prefix: str) -> bool:
        if prefix == "/":
            return True
        normalized = prefix.rstrip("/")
        return path == normalized or path.startswith(normalized + "/")

    def response(self, flow: http.HTTPFlow) -> None:
        if self.out_path is None:
            return
        capture_bodies = self.scope_loaded and self.rules.get("mitm_capture_bodies", False) is True
        record = {
            "source": "mitmproxy",
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": sanitize_headers(dict(flow.request.headers)),
            "request_body": flow.request.get_text(strict=False) if capture_bodies and flow.request.content else None,
            "response_status": flow.response.status_code if flow.response else None,
            "response_headers": sanitize_headers(dict(flow.response.headers)) if flow.response else None,
            "response_body": (
                flow.response.get_text(strict=False)
                if capture_bodies and flow.response and flow.response.content
                else None
            ),
            "content_type": flow.response.headers.get("content-type") if flow.response else None,
            "policy_blocked": bool(
                flow.metadata.get("aidast_policy_blocked", False)
            ),
            "capture_bodies": capture_bodies,
        }
        with self.out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [ScopeAndCaptureAddon()]

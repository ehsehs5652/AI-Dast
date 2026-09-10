"""Executes a ReconCoordinator-produced task list without Codex/Main Agent.

Each ReconTask.task_type dispatches to a handler below. Handlers are wrapped
with `_stage`, which mirrors the recon_stage/ReconFailureReport pattern from
the design docs: unexpected exceptions are logged to pipeline_runs and
re-raised as ReconExecutionError rather than being swallowed.

MVP scope: ENDPOINT_DISCOVERY runs katana in both standard and headless
modes unconditionally (see tools/endpoint_discovery.py), so the two modes'
results are always merged together with no separate re-crawl decision.
"""

from __future__ import annotations

import functools
from pathlib import Path
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid5

from aidast.recon import db as dbmod
from aidast.auth.browser import TargetSession, BrowserLoginError, origin
from aidast.recon.judgment import merge_and_normalize
from aidast.recon.models import (
    ReconStep,
    ReconTask,
    ReconTaskStatus,
    ReconTaskTarget,
)
from aidast.recon.origin import resolve_origin
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType
from aidast.recon.tools.asset_dns_port import run_dnsx, run_naabu, run_nmap, run_subfinder
from aidast.recon.tools.endpoint_discovery import discover_endpoints
from aidast.recon.tools.http_probe import ProbeResult, probe
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture, start_mitmproxy, stop_mitmproxy


class ReconExecutionError(RuntimeError):
    pass


def _stage(stage_name: str):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(self: "ReconExecutor", task: ReconTask, *args, **kwargs):
            try:
                return fn(self, task, *args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - intentionally broad
                dbmod.log_pipeline_run(
                    self.conn,
                    scan_id=self.scan_id,
                    task_id=task.task_id,
                    stage=stage_name,
                    status="failed",
                    error_type=type(exc).__name__,
                    message=str(exc),
                    recoverable=False,
                )
                task.status = ReconTaskStatus.FAILED
                raise ReconExecutionError(
                    f"{stage_name} 실패 (task={task.task_id}): {exc}"
                ) from exc

        return wrapper

    return decorator


def _as_url(asset: str) -> str:
    return asset if asset.startswith("http") else f"https://{asset}"


def _extract_host(asset: str) -> str:
    """dnsx/naabu/nmap에 넘길 순수 호스트만 뽑아낸다.

    scope target이 URL(예: http://localhost:3000)로 주어져도 이 도구들은
    scheme/port가 붙은 문자열이 아니라 호스트명/IP만 받아야 하므로 필요하다.
    """
    if asset.startswith("http://") or asset.startswith("https://"):
        return urlparse(asset).hostname or asset
    return asset


def _parse_host_port(entry: str) -> tuple[str, int] | None:
    """naabu/nmap이 내놓는 `host:port` 문자열을 (host, port)로 분리한다."""
    host, sep, port = entry.rpartition(":")
    if not sep or not port.isdigit():
        return None
    return host, int(port)


class ReconExecutor:
    def __init__(
        self,
        *,
        scan_id: str,
        scope_type: str,
        scope_value: str,
        db_path: Path,
        ffuf_wordlist: str | None = None,
        # 승인된 Scope에서 뽑은 {"allowed_hosts": [...]} 형태.
        # 아직 Scope 파이프라인이 안 붙어서 None이면 mitmproxy가
        # 스코프 강제 없이(fail-open) 관찰만 한다.
        scope_rules: dict | None = None,
        target_policies: dict[tuple[str, str], TargetPolicy] | None = None,
        require_policy_enforcement: bool = False,
        execution_start_urls: dict[tuple[str, str], str] | None = None,
        annotation_agent=None,
        auth_bootstrap: dict | None = None,
        target_sessions: dict[tuple[str, str], TargetSession] | None = None,
    ):
        self.target_sessions = target_sessions
        self.annotation_agent = annotation_agent
        self.auth_bootstrap = auth_bootstrap or {}
        self.scan_id = scan_id
        self.conn = dbmod.init_db(db_path)
        dbmod.insert_scan(self.conn, scan_id=scan_id, scope_type=scope_type, scope_value=scope_value)
        self.ffuf_wordlist = ffuf_wordlist
        self.scope_rules = scope_rules
        self.target_policies = target_policies or {}
        self.require_policy_enforcement = require_policy_enforcement
        self.execution_start_urls = execution_start_urls or {}
        self._asset_ids: dict[str, str] = {}
        self._origin_ids: dict[str, str] = {}
        self._probe_cache: dict[str, ProbeResult] = {}
        self._spawned_tasks: list[ReconTask] = []
        self._scheduled_hosts: set[str] = set()

    def run(self, tasks: list[ReconTask]) -> None:
        if self.target_sessions is not None:
            for task in tasks:
                self._session_for(task)
        completed_ids: set[str] = set()
        pending = list(tasks)
        while pending:
            progressed = False
            for task in list(pending):
                if all(dep in completed_ids for dep in task.depends_on_task_ids):
                    self._execute(task)
                    completed_ids.add(task.task_id)
                    pending.remove(task)
                    if self._spawned_tasks:
                        pending.extend(self._spawned_tasks)
                        self._spawned_tasks = []
                    progressed = True
            if not progressed:
                raise ReconExecutionError("의존관계를 풀 수 없는 Task가 남아 있음")

    def _execute(self, task: ReconTask) -> None:
        task.status = ReconTaskStatus.RUNNING
        handler = {
            ReconStep.ASSET_DISCOVERY: self._handle_asset_discovery,
            ReconStep.DNS_RESOLUTION: self._handle_dns_resolution,
            ReconStep.HOST_PORT_DISCOVERY: self._handle_host_port_discovery,
            ReconStep.HTTP_PROBE: self._handle_http_probe,
            ReconStep.ORIGIN_DISCOVERY: self._handle_origin_discovery,
            ReconStep.ENDPOINT_DISCOVERY: self._handle_endpoint_discovery,
        }[task.task_type]
        print(f"-> {task.task_type.value} 시작 (target={task.target.asset})")
        handler(task)
        task.status = ReconTaskStatus.COMPLETED
        dbmod.log_pipeline_run(
            self.conn, scan_id=self.scan_id, task_id=task.task_id,
            stage=task.task_type.value, status="success",
        )
        print("   완료")

    def _ensure_asset(self, task: ReconTask) -> str:
        asset_id = self._asset_ids.get(task.target.asset)
        if asset_id is None:
            asset_id = dbmod.insert_asset(
                self.conn, scan_id=self.scan_id,
                identifier=task.target.asset, asset_type=task.target.asset_type.value,
            )
            self._asset_ids[task.target.asset] = asset_id
        return asset_id

    def _policy_for(self, task: ReconTask) -> TargetPolicy | None:
        policy = self.target_policies.get(
            (task.target.asset_type.value, task.target.asset)
        )
        if self.require_policy_enforcement and policy is None:
            raise ReconExecutionError(
                f"검증된 TargetPolicy가 없음: {task.target.asset}"
            )
        return policy

    def _url_for(self, task: ReconTask) -> str:
        return self.execution_start_urls.get(
            (task.target.asset_type.value, task.target.asset),
            _as_url(task.target.asset),
        )

    def _session_for(self, task: ReconTask) -> TargetSession | None:
        if self.target_sessions is None:
            return None
        session = self.target_sessions.get((task.target.asset_type.value, task.target.asset))
        if session is None:
            raise BrowserLoginError("target has no pre-Recon login session; select and log in to this target first")
        session.verify()
        if origin(session.start_url) != origin(self._url_for(task)):
            raise BrowserLoginError("target session cannot be forwarded to another origin")
        return session

    def _probe_headers(self, task: ReconTask) -> dict:
        session = self._session_for(task)
        if session is None:
            return {}
        from aidast.recon.tools.playwright_driver import ManualSessionConfig, PlaywrightDriver
        # Header extraction reads the scoped snapshot without launching a browser.
        reader = PlaywrightDriver(self._url_for(task), ManualSessionConfig(
            login_url=self._url_for(task), session_file=str(session.runtime_path(self.scan_id)),
        ))
        return reader.get_auth_headers()

    @_stage("asset_discovery")
    def _handle_asset_discovery(self, task: ReconTask) -> None:
        asset_id = self._ensure_asset(task)
        policy = self._policy_for(task)
        asset_type = task.target.asset_type.value
        if asset_type not in {"DOMAIN", "WILDCARD"}:
            return
        root = task.target.asset.removeprefix("*.")
        if policy is not None:
            if not policy.include_subdomains:
                print("   [건너뜀] TargetPolicy가 서브도메인 탐색을 허용하지 않음")
                return
            if not policy.allows_host(root):
                raise ReconExecutionError(
                    f"TargetPolicy가 subfinder 루트를 허용하지 않음: {root}"
                )
        for sub in run_subfinder(root):
            hostname = sub.lower().rstrip(".")
            if policy is not None and not policy.allows_host(hostname):
                print(f"   [제외] subfinder 범위 밖 결과: {sub}")
                continue
            dbmod.insert_dns_resolution(
                self.conn, asset_id=asset_id, hostname=hostname, source="subfinder",
            )
            if policy is not None:
                self._schedule_discovered_host(task, hostname, policy)

    def _schedule_discovered_host(
        self, parent: ReconTask, hostname: str, wildcard_policy: TargetPolicy
    ) -> None:
        if hostname in self._scheduled_hosts:
            return
        self._scheduled_hosts.add(hostname)
        child_policy = wildcard_policy.model_copy(
            update={
                "asset_type": AssetType.DOMAIN,
                "asset": hostname,
                "allowed_hosts": [hostname],
                "include_subdomains": False,
                "policy_id": f"{wildcard_policy.policy_id}:host:{hostname}",
            }
        )
        self.target_policies[(AssetType.DOMAIN.value, hostname)] = child_policy
        previous = parent.task_id
        for sequence, step in enumerate(
            (
                ReconStep.DNS_RESOLUTION,
                ReconStep.HOST_PORT_DISCOVERY,
                ReconStep.HTTP_PROBE,
                ReconStep.ORIGIN_DISCOVERY,
                ReconStep.ENDPOINT_DISCOVERY,
            ),
            start=1,
        ):
            task_id = "task_" + uuid5(
                NAMESPACE_URL,
                f"{parent.plan_id}:{parent.task_id}:{hostname}:{step.value}",
            ).hex
            self._spawned_tasks.append(
                ReconTask(
                    task_id=task_id,
                    plan_id=parent.plan_id,
                    scope_id=parent.scope_id,
                    task_type=step,
                    sequence=sequence,
                    target=ReconTaskTarget(
                        asset_type=AssetType.DOMAIN,
                        asset=hostname,
                    ),
                    depends_on_task_ids=[previous],
                    constraints=parent.constraints,
                )
            )
            previous = task_id

    @_stage("dns_resolution")
    def _handle_dns_resolution(self, task: ReconTask) -> None:
        asset_id = self._ensure_asset(task)
        host = _extract_host(task.target.asset)
        for hostname in run_dnsx([host]):
            dbmod.insert_dns_resolution(
                self.conn, asset_id=asset_id, hostname=hostname, source="dnsx",
            )

    @_stage("host_port_discovery")
    def _handle_host_port_discovery(self, task: ReconTask) -> None:
        asset_id = self._ensure_asset(task)
        host = _extract_host(task.target.asset)
        policy = self._policy_for(task)
        allowed_ports = policy.allowed_ports if policy is not None else None
        found: list[tuple[str, str]] = (
            [(entry, "naabu") for entry in run_naabu([host], ports=allowed_ports)]
            + [(entry, "nmap") for entry in run_nmap([host], ports=allowed_ports)]
        )
        for entry, source in found:
            parsed = _parse_host_port(entry)
            if parsed is None:
                continue
            found_host, port = parsed
            dbmod.upsert_host_port(
                self.conn, asset_id=asset_id, host=found_host, port=port, source_tool=source,
            )

    @_stage("http_probe")
    def _handle_http_probe(self, task: ReconTask) -> None:
        url = self._url_for(task)
        policy = self._policy_for(task)
        if policy is not None and not policy.allows_url(url):
            raise ReconExecutionError(f"TargetPolicy가 HTTP 요청을 허용하지 않음: {url}")
        result = probe(
            url,
            timeout=policy.limits.timeout_seconds if policy else 30.0,
            policy=policy,
            headers=self._probe_headers(task),
        )
        self._probe_cache[task.target.asset] = result
        if not result.ok:
            raise ReconExecutionError(f"{url} 응답 없음")

    @_stage("origin_discovery")
    def _handle_origin_discovery(self, task: ReconTask) -> None:
        asset_id = self._ensure_asset(task)
        url = self._url_for(task)

        policy = self._policy_for(task)
        if policy is not None and not policy.allows_url(url):
            raise ReconExecutionError(f"TargetPolicy가 Origin 요청을 허용하지 않음: {url}")
        probe_result = self._probe_cache.get(task.target.asset) or probe(
            url,
            timeout=policy.limits.timeout_seconds if policy else 30.0,
            policy=policy,
            headers=self._probe_headers(task),
        )
        resolution = resolve_origin(probe_result)

        origin_id = dbmod.upsert_origin(
            self.conn, asset_id=asset_id,
            scheme=probe_result.scheme, host=probe_result.host, port=probe_result.port,
            base_url=url, http_probe_status=probe_result.status_code,
            spa_detected=resolution.spa_detected,
            framework_signature=resolution.framework_signature,
            main_crawler_mode=resolution.main_crawler_mode,
        )
        self._origin_ids[task.target.asset] = origin_id
        print(
            f"   SPA={resolution.spa_detected} "
            f"({resolution.framework_signature or '시그니처 없음'}) "
            f"-> {resolution.main_crawler_mode}"
        )

    @_stage("endpoint_discovery")
    def _handle_endpoint_discovery(self, task: ReconTask) -> None:
        origin_id = self._origin_ids.get(task.target.asset)
        if origin_id is None:
            raise ReconExecutionError("ORIGIN_DISCOVERY가 먼저 끝나야 함")

        url = self._url_for(task)
        policy = self._policy_for(task)
        session = self._session_for(task)
        # katana_standard/headless를 discover_endpoints()가 둘 다 돌리므로
        # origins.main_crawler_mode(SPA 추정값)는 더 이상 실행 분기에 쓰이지
        # 않는다 - 참고용 기록으로만 origins 테이블에 남아 있다.
        capture_path = Path(f"mitm_capture_{self.scan_id}.jsonl")
        rules = policy.mitm_rules() if policy is not None else self.scope_rules
        if rules is not None and self.auth_bootstrap:
            rules = dict(rules)
            rules["auth_bootstrap"] = self.auth_bootstrap
        from aidast.recon.annotations import ObservationRecorder
        recorder = ObservationRecorder(self.conn, origin_id=origin_id,
                                       scan_id=self.scan_id, agent=self.annotation_agent)
        proxy_process, proxy_url = start_mitmproxy(capture_path, scope_rules=rules)
        try:
            if self.require_policy_enforcement and proxy_url is None:
                raise ReconExecutionError("정책 강제 mitmproxy를 시작할 수 없음")
            raw = discover_endpoints(
                url,
                ffuf_wordlist=self.ffuf_wordlist,
                mitm_proxy_url=proxy_url,
                target_policy=policy,
                observation_callback=recorder.record,
                run_id=self.scan_id,
                auth_bootstrap=self.auth_bootstrap,
                session_file=str(session.runtime_path(self.scan_id)) if session else None,
                identity_id=session.identity if session else None,
                preauthenticated=session is not None,
            )
        finally:
            stop_mitmproxy(proxy_process)
            if proxy_url is not None:
                ingested, blocked = ingest_mitm_capture(self.conn, capture_path, origin_id=origin_id)
                print(
                    f"   [mitmproxy] 허용 {ingested}건 적재, "
                    f"정책 차단 {blocked}건"
                )

        merged = merge_and_normalize(raw)
        for item in merged:
            dbmod.upsert_endpoint(
                self.conn, origin_id=origin_id, method=item["method"],
                path=item["path"], normalized_path=item["normalized_path"],
                content_type=item.get("content_type"),
                source_tool=",".join(sorted(item["source_tools"])),
                is_excluded=item["is_excluded"], exclude_reason=item["exclude_reason"],
            )

        included = [e for e in merged if not e["is_excluded"]]
        print(f"   발견 {len(included)}건 (제외 {len(merged) - len(included)}건)")

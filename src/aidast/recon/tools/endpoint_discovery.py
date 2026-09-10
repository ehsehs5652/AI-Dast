"""ENDPOINT DISCOVERY

최종 Flow
==========

1. Playwright Manual Authentication
   - Chromium 자동 실행
   - 사용자 직접 로그인
   - Cookie / localStorage / sessionStorage 저장
   - 로그인 과정 HTTP 관찰

2. Authenticated Katana Standard
   - Cookie / Authorization Header 사용

3. Authenticated Katana Headless
   - Playwright 로그인 Chromium에 CDP 연결
   - 실패 시 Header 방식 Fallback

4. Playwright Runtime 복구
   - Katana가 Context를 종료했어도
     session.json으로 새로운 Browser 생성

5. Katana 결과 Merge

6. Authenticated ffuf
   - Katana / 로그인 과정 Endpoint 기반
   - Path Prefix Fuzzing

7. Playwright UI Interaction
   - 발견한 HTML 페이지 방문
   - 메뉴 / Tab / Accordion 등 안전 Action
   - XHR / Fetch / WebSocket 관찰

8. OpenAPI / GraphQL Secondary Discovery

9. 전체 Merge

기존 DB 호환을 위해 반환값은 list[dict].
"""

from __future__ import annotations

import json
import html
import math
import re
import shutil
import subprocess
import tempfile
import hashlib
import uuid

from dataclasses import replace
from pathlib import Path
from typing import Callable
from urllib.parse import (
    urljoin,
    urlparse,
    unquote,
)

from .api_secondary_discovery import (
    discover_api_secondary,
)

from .playwright_driver import (
    InteractionConfig,
    ManualSessionConfig,
    PlaywrightDriver,
)

from .ffuf_root_selector import (
    FfufRootSelectionError,
    select_ffuf_roots_from_endpoints,
)
from aidast.recon.policy import TargetPolicy


ALLOWED_SCHEMES = {
    "http",
    "https",
}


def _tool_rate_args(tool: str, requests_per_second: float) -> list[str]:
    """Translate a fractional policy rate without ever rounding it upward."""
    if requests_per_second < 1:
        delay_seconds = math.ceil(1 / requests_per_second)
        return ["-delay", str(delay_seconds)] if tool == "katana" else [
            "-p", str(delay_seconds)
        ]
    integer_rate = math.floor(requests_per_second)
    return ["-rl", str(integer_rate)] if tool == "katana" else [
        "-rate", str(integer_rate)
    ]


# =========================================================
# Origin
# =========================================================

def _effective_port(
    parsed,
) -> int | None:

    if parsed.port is not None:
        return parsed.port

    scheme = (
        parsed.scheme.lower()
    )

    if scheme == "http":
        return 80

    if scheme == "https":
        return 443

    return None


def _same_origin(
    url: str,
    base_url: str,
) -> bool:

    try:

        parsed = urlparse(
            url
        )

        base = urlparse(
            base_url
        )

        return (
            parsed.scheme.lower()
            ==
            base.scheme.lower()

            and

            (
                parsed.hostname
                or ""
            ).lower()
            ==
            (
                base.hostname
                or ""
            ).lower()

            and

            _effective_port(
                parsed
            )
            ==
            _effective_port(
                base
            )
        )

    except ValueError:

        return False


# =========================================================
# Normalize
# =========================================================

def _normalize_route(
    value: str | None,
    base_url: str,
) -> str | None:

    if not value:
        return None

    value = (
        value.strip()
    )

    if not value:
        return None

    try:

        full_url = urljoin(
            base_url.rstrip("/")
            + "/",

            value,
        )

        parsed = urlparse(
            full_url
        )

    except (
        ValueError,
        TypeError,
    ):

        return None

    if (
        parsed.scheme.lower()
        not in ALLOWED_SCHEMES
    ):

        return None

    if not parsed.hostname:
        return None

    # 외부 Origin 제거
    if not _same_origin(
        full_url,
        base_url,
    ):

        return None

    # Canonical Endpoint:
    # Query / Fragment 제외
    path = (
        parsed.path
        or "/"
    )

    # Katana/browser error pages can leak escaped fragments into a discovered
    # URL (for example `%5C`, `\\`, `&quot;`).  They are not reliable routes;
    # reject them instead of decoding or rewriting them into a new target.
    # Decode only for validation (the returned route remains in its original
    # canonical encoding).  A second pass catches double-escaped separators
    # such as ``%255C`` without rewriting legitimate encoded characters.
    decoded_path = path
    for _ in range(2):
        decoded_path = html.unescape(unquote(decoded_path))
    if (
        "\\" in decoded_path
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded_path)
        or re.search(r"%(?![0-9A-Fa-f]{2})", path)
        or re.search(r"&(?:amp|quot|apos|lt|gt|#(?:\d+|x[0-9A-Fa-f]+));?", path, re.IGNORECASE)
    ):
        return None

    if not path.startswith(
        "/"
    ):

        path = (
            "/" + path
        )

    return path


# =========================================================
# Deduplication
# =========================================================

def _deduplicate_results(
    results: list[dict],
) -> list[dict]:

    unique: dict[
        tuple[str, str],
        dict,
    ] = {}

    for result in results:

        method = (
            result.get(
                "method",
                "GET",
            )
            .upper()
        )

        path = (
            result.get(
                "path"
            )
        )

        if not path:
            continue

        key = (
            method,
            path,
        )

        incoming_sources: list[
            str
        ] = []

        source = (
            result.get(
                "source"
            )
        )

        if source:

            incoming_sources.append(
                source
            )

        for source_name in (
            result.get(
                "sources",
                [],
            )
        ):

            if (
                source_name
                not in incoming_sources
            ):

                incoming_sources.append(
                    source_name
                )

        if key not in unique:

            item = dict(
                result
            )

            item[
                "method"
            ] = method

            item[
                "path"
            ] = path

            item["observation_variants"] = result.get("observation_variants", [dict(result)])

            item[
                "sources"
            ] = (
                incoming_sources.copy()
            )

            unique[key] = item

            continue

        unique[key]["observation_variants"].extend(
            result.get("observation_variants", [dict(result)])
        )

        stored_sources = (
            unique[key]
            .setdefault(
                "sources",
                [],
            )
        )

        for source_name in (
            incoming_sources
        ):

            if (
                source_name
                not in stored_sources
            ):

                stored_sources.append(
                    source_name
                )

    return list(
        unique.values()
    )


# =========================================================
# CLI Headers
# =========================================================

def _append_headers(
    command: list[str],
    headers: dict[str, str] | None,
) -> None:

    if not headers:
        return

    for (
        name,
        value,
    ) in headers.items():

        command.extend(
            [
                "-H",
                f"{name}: {value}",
            ]
        )


# =========================================================
# Katana Scope
# =========================================================

def _katana_scope_regex(
    base_url: str,
) -> str:

    parsed = urlparse(
        base_url
    )

    # scheme://host:port 만 사용
    origin = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}"
    )

    return (
        "^"
        + re.escape(
            origin
        )
        + r"(?:/|$)"
    )


# =========================================================
# Katana Output
# =========================================================

def _parse_katana_output(
    stdout: str,
    *,
    base_url: str,
    source: str,
    target_policy: TargetPolicy | None = None,
) -> list[dict]:

    results: list[
        dict
    ] = []

    raw_count = 0
    removed_count = 0

    for line in (
        stdout.splitlines()
    ):

        line = (
            line.strip()
        )

        if not line:
            continue

        raw_count += 1

        request = {}
        response = {}
        endpoint = line
        if line.startswith(('{', '[')):
            try:
                record = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(record, dict) or not isinstance(record.get('request'), dict):
                continue
            request = record['request']
            response = record.get('response') or {}
            if not isinstance(response, dict):
                response = {}
            endpoint = request.get('endpoint')
        if not isinstance(endpoint, str):
            continue
        path = _normalize_route(endpoint, base_url)
        if path is None:
            removed_count += 1
            continue
        method = str(request.get('method') or 'GET').upper()
        if not re.fullmatch(r'[A-Z]{1,20}', method):
            continue
        if target_policy is not None:
            parsed_base = urlparse(base_url)
            if not target_policy.allows_url(
                f'{parsed_base.scheme}://{parsed_base.netloc}{path}', method=method
            ):
                removed_count += 1
                continue
        from aidast.recon.annotations import sanitize_evidence, safe_url
        headers = response.get('headers') or {}
        headers = {str(k).lower().replace('_', '-'): v for k, v in headers.items()} if isinstance(headers, dict) else {}
        evidence = sanitize_evidence({
            'parent_url': request.get('source'),
            'html_tag': request.get('tag'),
            'html_attribute': request.get('attribute'),
            'response_status': response.get('status_code'),
            'content_type': headers.get('content-type'),
            'content_length': response.get('content_length'),
            'redirect_url': headers.get('location'),
        })
        parent_url = evidence.get('parent_url', '')
        results.append({
            'method': method, 'path': path,
            'url': safe_url(urljoin(base_url, endpoint)),
            'content_type': evidence.get('content_type'), 'source': source,
            'discovery_kind': 'http_response' if evidence.get('response_status') else 'tool_report',
            'evidence': evidence,
            'context': {
                'context_key': f'{source}:parent:{parent_url}',
                'page_url': parent_url, 'action_type': 'tool_run',
                'association_method': 'crawler_source' if parent_url else 'tool_batch',
            },
        })

    print(
        f"  {source} Raw : "
        f"{raw_count}건"
    )

    print(
        f"  외부/비허용 제거 : "
        f"{removed_count}건"
    )

    print(
        f"  Target 결과 : "
        f"{len(results)}건"
    )

    return results


def _filter_results_by_policy(
    results: list[dict], *, base_url: str, target_policy: TargetPolicy | None
) -> list[dict]:
    if target_policy is None:
        return results
    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    filtered: list[dict] = []
    for result in results:
        path = result.get("path")
        if not path:
            continue
        candidate = origin + path
        if target_policy.allows_url(
            candidate, method=result.get("method", "GET")
        ):
            filtered.append(result)
    return filtered


# =========================================================
# Katana Runner
# =========================================================

def _run_katana(
    command: list[str],
) -> subprocess.CompletedProcess:

    return subprocess.run(
        command,

        capture_output=True,

        text=True,

        timeout=180,
    )


# =========================================================
# Katana
# =========================================================

def discover_with_katana(
    base_url: str,
    *,
    mode: str,
    auth_headers: dict[str, str] | None,
    chrome_ws_url: str | None = None,
    proxy_url: str | None = None,
    target_policy: TargetPolicy | None = None,
) -> list[dict]:

    if target_policy is not None and not proxy_url:
        raise ValueError("policy-enforced katana requires a proxy")

    if shutil.which(
        "katana"
    ) is None:

        print(
            "  [건너뜀] katana 미설치"
        )

        return []

    base_command = [
        "katana",

        "-u",
        base_url,

        "-silent",
        "-j", "-or", "-ob",

        # JavaScript Crawl
        "-jc",

        # Target Origin Scope
        "-cs",
        _katana_scope_regex(
            base_url
        ),
    ]

    if target_policy is not None:
        base_command += [
            "-d", str(target_policy.limits.max_depth),
            "-c", str(target_policy.limits.concurrency),
            "-timeout", str(target_policy.limits.timeout_seconds),
            # Keep a focused recon phase bounded even when the request budget
            # is large; the policy budget remains enforced by mitmproxy.
            "-ct", "150s",
        ]
        base_command += _tool_rate_args(
            "katana", target_policy.limits.requests_per_second
        )

    if proxy_url:

        base_command += [
            "-proxy",
            proxy_url,
        ]

    # =====================================================
    # Standard
    # =====================================================

    if mode == "standard":

        source = (
            "katana_auth_standard"
        )

        command = list(
            base_command
        )

        _append_headers(
            command,
            auth_headers,
        )

        try:

            completed = (
                _run_katana(
                    command
                )
            )

        except (
            subprocess.TimeoutExpired,
            OSError,
        ) as exc:

            print(
                "  [경고] "
                "Katana Standard 실패: "
                f"{exc}"
            )

            return []

    # =====================================================
    # Headless
    # =====================================================

    elif mode == "headless":

        source = (
            "katana_auth_headless"
        )

        completed = None

        # ---------------------------------------------
        # Playwright 로그인 Chromium에 CDP 연결
        # ---------------------------------------------

        if chrome_ws_url:

            print(
                "  [Katana Headless] "
                "로그인 Chromium CDP 연결"
            )

            command = (
                list(
                    base_command
                )
                + [
                    "-hl",

                    "-cwu",
                    chrome_ws_url,

                    "-noi",
                ]
            )

            try:

                completed = (
                    _run_katana(
                        command
                    )
                )

            except (
                subprocess.TimeoutExpired,
                OSError,
            ) as exc:

                print(
                    "  [경고] "
                    "Katana CDP 실패: "
                    f"{exc}"
                )

                completed = None

        # ---------------------------------------------
        # CDP 실패 → Header 방식 Headless
        # ---------------------------------------------

        if (
            completed is None
            or completed.returncode != 0
        ):

            if chrome_ws_url:

                print(
                    "  [Katana Headless] "
                    "CDP 실패 → "
                    "Header 방식 Fallback"
                )

            else:

                print(
                    "  [Katana Headless] "
                    "CDP 없음 → "
                    "Header 방식"
                )

            command = (
                list(
                    base_command
                )
                + [
                    "-hl"
                ]
            )

            _append_headers(
                command,
                auth_headers,
            )

            try:

                completed = (
                    _run_katana(
                        command
                    )
                )

            except (
                subprocess.TimeoutExpired,
                OSError,
            ) as exc:

                print(
                    "  [경고] "
                    "Katana Headless 실패: "
                    f"{exc}"
                )

                return []

    else:

        raise ValueError(
            "mode는 "
            "'standard' 또는 "
            "'headless'여야 합니다."
        )

    # =====================================================
    # Result
    # =====================================================

    if completed is None:

        return []

    if completed.returncode != 0:

        print(
            "  [경고] "
            "Katana 비정상 종료 "
            f"(code={completed.returncode})"
        )

        if completed.stderr:

            print(
                "  [Katana stderr] "
                f"{completed.stderr.strip()[:500]}"
            )

        return []

    return (
        _parse_katana_output(
            completed.stdout,

            base_url=base_url,

            source=source,
            target_policy=target_policy,
        )
    )


# =========================================================
# ffuf Roots
# =========================================================

def _build_ffuf_roots(
    endpoints: list[dict],
    *,
    max_depth: int = 3,
    max_roots: int = 50,
) -> list[str]:

    roots: set[
        str
    ] = {
        "/"
    }

    for endpoint in endpoints:

        path = (
            endpoint.get(
                "path"
            )
        )

        if not path:
            continue

        parts = [
            part

            for part in (
                path.split("/")
            )

            if part
        ]

        if not parts:
            continue

        max_prefix = min(
            len(parts) - 1,
            max_depth,
        )

        for depth in range(
            1,
            max_prefix + 1,
        ):

            roots.add(
                "/"
                + "/".join(
                    parts[:depth]
                )
            )

        # /api/Products 같은
        # 짧은 Path도 Fuzz Root
        if (
            len(parts) <= 2
            and not parts[-1].isdigit()
        ):

            roots.add(
                "/"
                + "/".join(
                    parts
                )
            )

    ordered = sorted(
        roots,

        key=lambda value: (
            value.count("/"),
            value,
        ),
    )

    return ordered[
        :max_roots
    ]


# =========================================================
# ffuf
# =========================================================

def discover_with_ffuf(
    base_url: str,
    *,
    wordlist: str | None,
    seed_endpoints: list[dict],
    auth_headers: dict[str, str] | None,
    proxy_url: str | None = None,
    root_selector: Callable[[list[dict]], list[str]] | None = None,
    target_policy: TargetPolicy | None = None,
) -> list[dict]:
    parsed_base = urlparse(base_url)
    ffuf_origin = (
        f"{parsed_base.scheme}://{parsed_base.netloc}"
        if parsed_base.scheme and parsed_base.netloc
        else base_url.rstrip("/")
    )

    if target_policy is not None and not target_policy.tools.ffuf_enabled:
        print("  [건너뜀] TargetPolicy에서 ffuf가 허용되지 않음")
        return []

    if target_policy is not None and not proxy_url:
        raise ValueError("policy-enforced ffuf requires a proxy")

    if shutil.which(
        "ffuf"
    ) is None:

        print(
            "  [건너뜀] ffuf 미설치"
        )

        return []

    if not wordlist:

        print(
            "  [건너뜀] "
            "ffuf Wordlist 없음"
        )

        return []

    if not Path(
        wordlist
    ).is_file():

        print(
            "  [건너뜀] "
            f"Wordlist 없음: {wordlist}"
        )

        return []

    selector = root_selector or select_ffuf_roots_from_endpoints
    try:
        roots = selector(seed_endpoints)
    except FfufRootSelectionError as exc:
        print(
            "  [경고] ffuf Root 선택 Agent 실패, "
            f"기존 Prefix 방식으로 대체: {exc}"
        )
        roots = _build_ffuf_roots(seed_endpoints)

    if not roots:
        print(
            "  [경고] 선택된 ffuf Root가 없어 "
            "기존 Prefix 방식으로 대체"
        )
        roots = _build_ffuf_roots(seed_endpoints)

    if target_policy is not None:
        roots = [
            root for root in roots
            if target_policy.allows_url(
                ffuf_origin + (root if root.startswith("/") else "/" + root)
            )
        ]

    print(
        f"  ffuf Root : "
        f"{len(roots)}개"
    )

    results: list[
        dict
    ] = []

    for (
        index,
        root,
    ) in enumerate(
        roots,
        start=1,
    ):

        if root == "/":

            fuzz_url = (
                ffuf_origin
                + "/FUZZ"
            )

        else:

            fuzz_url = (
                ffuf_origin
                + f"{root.rstrip('/')}"
                + "/FUZZ"
            )

        print(
            f"  [ffuf "
            f"{index}/{len(roots)}] "
            f"{fuzz_url}"
        )

        tmp = (
            tempfile
            .NamedTemporaryFile(
                suffix=".json",
                delete=False,
            )
        )

        tmp_path = (
            Path(
                tmp.name
            )
        )

        tmp.close()

        command = [
            "ffuf",

            "-u",
            fuzz_url,

            "-w",
            wordlist,

            "-of",
            "json",

            "-o",
            str(
                tmp_path
            ),

            "-s",

            # SPA Soft-404 보정
            "-ac",
        ]

        if proxy_url:
            command += ["-x", proxy_url]

        if target_policy is not None:
            command += [
                "-t", str(target_policy.limits.concurrency),
                "-timeout", str(target_policy.limits.timeout_seconds),
                "-maxtime", "150",
            ]
            command += _tool_rate_args(
                "ffuf", target_policy.limits.requests_per_second
            )

        run_timeout = 180

        _append_headers(
            command,
            auth_headers,
        )

        try:

            completed = (
                subprocess.run(
                    command,

                    capture_output=True,

                    text=True,

                    timeout=run_timeout,
                )
            )

        except (
            subprocess.TimeoutExpired,
            OSError,
        ) as exc:

            print(
                "    [경고] "
                f"ffuf 실패: {exc}"
            )

            tmp_path.unlink(
                missing_ok=True
            )

            continue

        if (
            completed.returncode
            != 0
        ):

            print(
                "    [경고] "
                "ffuf 종료 code="
                f"{completed.returncode}"
            )

        try:

            payload = json.loads(
                tmp_path
                .read_text(
                    encoding="utf-8"
                )
            )

        except (
            json.JSONDecodeError,
            OSError,
        ):

            payload = {
                "results": []
            }

        finally:

            tmp_path.unlink(
                missing_ok=True
            )

        discovered_count = 0

        for entry in (
            payload.get(
                "results",
                [],
            )
        ):

            discovered_url = (
                entry.get(
                    "url"
                )
            )

            if not discovered_url:

                fuzz_value = (
                    entry
                    .get(
                        "input",
                        {},
                    )
                    .get(
                        "FUZZ",
                        "",
                    )
                )

                if not fuzz_value:
                    continue

                discovered_url = (
                    fuzz_url.replace(
                        "FUZZ",
                        fuzz_value,
                    )
                )

            path = (
                _normalize_route(
                    discovered_url,
                    base_url,
                )
            )

            if path is None:
                continue

            if target_policy is not None and not target_policy.allows_url(ffuf_origin + path):
                continue
            from aidast.recon.annotations import sanitize_evidence, safe_url
            evidence = sanitize_evidence({
                'fuzz_root': root,
                'seed_paths': [item.get('path') for item in seed_endpoints
                               if isinstance(item.get('path'), str)
                               and (root == '/' or item['path'] == root.rstrip('/')
                                    or item['path'].startswith(root.rstrip('/') + '/'))][:10],
                'response_status': entry.get('status'),
                'content_type': entry.get('content-type'),
                'content_length': entry.get('length'),
                'word_count': entry.get('words'), 'line_count': entry.get('lines'),
                'redirect_url': entry.get('redirectlocation'),
            })
            results.append(
                {
                    "method": "GET",

                    "path": path,

                    "content_type": (
                        entry.get(
                            "content-type"
                        )
                    ),

                    "source": "ffuf",
                    "url": safe_url(discovered_url),
                    "discovery_kind": "http_response" if evidence.get('response_status') else "tool_report",
                    "evidence": evidence,
                    "context": {
                        "context_key": f"ffuf:root:{root}",
                        "action_type": "tool_run",
                        "action_target": safe_url(fuzz_url),
                        "association_method": "fuzz_root",
                    },
                }
            )

            discovered_count += 1

        print(
            f"    -> "
            f"{discovered_count}건"
        )

    unique = (
        _deduplicate_results(
            results
        )
    )

    print(
        f"  ffuf Unique : "
        f"{len(unique)}건"
    )

    return unique


# =========================================================
# Default Session File
# =========================================================

def _make_default_session_file(
    base_url: str,
    *,
    run_id: str | None = None,
    identity_id: str | None = None,
    auth_bootstrap: dict | None = None,
) -> str:

    parsed = urlparse(
        base_url
    )

    hostname = (
        parsed.hostname
        or "target"
    )

    port = (
        parsed.port

        or
        _effective_port(
            parsed
        )

        or 0
    )

    safe_host = re.sub(
        r"[^a-zA-Z0-9_.-]",
        "_",
        hostname,
    )

    # Hash identifiers so caller input cannot escape the session directory or
    # disclose identity labels. An omitted run ID deliberately starts fresh.
    run_key = hashlib.sha256((run_id or uuid.uuid4().hex).encode()).hexdigest()[:24]
    identity_key = hashlib.sha256((identity_id or "manual").encode()).hexdigest()[:24]
    origin_key = hashlib.sha256(base_url.encode()).hexdigest()[:16]
    return str(Path(".aidast_sessions") / run_key / identity_key
               / f"{safe_host}_{port}_{origin_key}.json")


# =========================================================
# Main
# =========================================================

def discover_endpoints(
    base_url: str,
    *,
    ffuf_wordlist: str | None = None,

    # None이면 base_url을 Browser에 표시
    login_url: str | None = None,

    # None이면 Target 기준 자동 생성
    session_file: str | None = None,

    # 알고 있으면 설정 권장
    auth_check_url: str | None = None,

    # 사이트별 Token Mapping
    storage_header_map: (
        dict[
            str,
            tuple[str, str],
        ]
        | None
    ) = None,

    interaction_config: (
        InteractionConfig
        | None
    ) = None,

    # mitmproxy 사용 시
    #
    # http://127.0.0.1:8080
    playwright_proxy_url: (
        str | None
    ) = None,

    # katana/ffuf도 같이 이 프록시를 거치게 하려면 지정.
    # playwright_proxy_url이 따로 없으면 Playwright도 이 값을 같이 씀.
    mitm_proxy_url: (
        str | None
    ) = None,

    enable_playwright_interaction: bool = True,

    zap_executable: str = "zaproxy",
    target_policy: TargetPolicy | None = None,
    observation_callback=None,
    run_id: str | None = None,
    identity_id: str | None = None,
    auth_bootstrap: dict | None = None,
    preauthenticated: bool = False,
) -> list[dict]:

    if target_policy is not None and not mitm_proxy_url:
        raise ValueError("policy-enforced endpoint discovery requires a proxy")
    if target_policy is not None and playwright_proxy_url and playwright_proxy_url != mitm_proxy_url:
        raise ValueError("policy-enforced browser must use the shared enforcement proxy")
    if target_policy is not None and not target_policy.allows_url(base_url):
        raise ValueError(f"TargetPolicy가 base URL을 허용하지 않음: {base_url}")

    def observe(phase, items):
        if observation_callback is not None:
            observation_callback(phase, _filter_results_by_policy(
                items, base_url=base_url, target_policy=target_policy))

    def observe_browser(phase):
        if observation_callback is not None and driver is not None:
            observe(phase, driver.drain_observations())

    driver: (
        PlaywrightDriver
        | None
    ) = None

    try:

        # =================================================
        # PHASE 1
        # Playwright Authentication
        # =================================================

        print()
        print(
            "  =================================="
        )
        print(
            "  PHASE 1 - "
            "Playwright Session Restore" if preauthenticated else "Playwright Authentication"
        )
        print(
            "  =================================="
        )

        actual_session_file = (
            session_file

            or
            _make_default_session_file(
                base_url, run_id=run_id, identity_id=identity_id,
            )
        )

        session_config = (
            ManualSessionConfig(
                login_url=(
                    login_url
                    or base_url
                ),

                session_file=(
                    actual_session_file
                ),

                auth_check_url=(
                    auth_check_url
                ),

                storage_header_map=(
                    storage_header_map
                    or {}
                ),
            )
        )

        effective_interaction_config = interaction_config or InteractionConfig()
        effective_interaction_config = replace(
            effective_interaction_config,
            allow_form_submission=bool(
                target_policy is not None
                and target_policy.tools.form_submission
                and effective_interaction_config.allow_form_submission
            ),
        )

        driver = (
            PlaywrightDriver(
                base_url,

                session_config,

                interaction_config=(
                    effective_interaction_config
                ),

                proxy_url=(
                    playwright_proxy_url
                    or mitm_proxy_url
                ),
                target_policy=target_policy,
                auth_bootstrap=auth_bootstrap,
                preauthenticated=preauthenticated,
            )
        )

        # ---------------------------------------------
        # 실제 Chromium 실행
        #
        # 사용자가 직접 로그인
        #
        # Enter
        #
        # Session 저장
        # ---------------------------------------------

        if preauthenticated:
            driver.start_from_session()
        else:
            driver.capture_and_start()
        observe_browser("playwright_login")

        auth_headers = (
            driver.get_auth_headers()
        )

        print()
        print(
            "  [Playwright] "
            "외부 도구용 인증정보 생성 완료"
        )

        print(
            "  Header 종류 : "
            f"{list(auth_headers.keys())}"
        )

        # 로그인 과정에서 발생한
        # XHR / Fetch / Document
        login_results = (
            driver.get_http_results()
        )
        login_results = _filter_results_by_policy(
            login_results, base_url=base_url, target_policy=target_policy
        )

        print(
            "  로그인 과정 HTTP : "
            f"{len(login_results)}건"
        )

        # =================================================
        # PHASE 2
        # Authenticated Katana
        # =================================================

        print()
        print(
            "  =================================="
        )
        print(
            "  PHASE 2 - "
            "Authenticated Katana"
        )
        print(
            "  =================================="
        )

        # ---------------------------------------------
        # Standard
        # ---------------------------------------------

        driver.ensure_session()

        auth_headers = (
            driver.get_auth_headers()
        )

        print()
        print(
            "  [1/2] Katana Standard"
        )

        standard_results = (
            discover_with_katana(
                base_url,

                mode="standard",

                auth_headers=(
                    auth_headers
                ),

                proxy_url=(
                    mitm_proxy_url
                ),
                target_policy=target_policy,
            )
        )

        observe("katana_standard", standard_results)

        # ---------------------------------------------
        # Headless
        # ---------------------------------------------

        headless_allowed = (
            target_policy is None or target_policy.tools.katana_headless
        )
        if headless_allowed:
            driver.ensure_session()
            auth_headers = driver.get_auth_headers()
            chrome_ws_url = driver.get_chrome_ws_url()
            print()
            print("  [2/2] Katana Headless")
            headless_results = discover_with_katana(
                base_url,
                mode="headless",
                auth_headers=auth_headers,
                chrome_ws_url=chrome_ws_url,
                proxy_url=mitm_proxy_url,
                target_policy=target_policy,
            )
        else:
            print("  [건너뜀] TargetPolicy에서 Katana Headless가 허용되지 않음")
            headless_results = []

        # =================================================
        # ★ 중요
        #
        # Katana Headless가 같은 Chromium Context를
        # 건드리거나 종료했을 수 있으므로
        # 생존 여부에 관계없이 저장된 세션으로
        # 새 Playwright Runtime을 만든다.
        # =================================================

        observe("katana_headless", headless_results)
        observe_browser("playwright_katana")
        if headless_allowed:
            driver.restore_runtime(force=True)

        auth_headers = (
            driver.get_auth_headers()
        )

        # ---------------------------------------------
        # Katana Merge
        # ---------------------------------------------

        katana_results = (
            _deduplicate_results(
                standard_results
                + headless_results
            )
        )

        print()
        print(
            "  ----------------------------------"
        )

        print(
            f"  Standard      : "
            f"{len(standard_results)}"
        )

        print(
            f"  Headless      : "
            f"{len(headless_results)}"
        )

        print(
            f"  Katana Unique : "
            f"{len(katana_results)}"
        )

        # =================================================
        # PHASE 3
        # Authenticated ffuf
        # =================================================

        print()
        print(
            "  =================================="
        )
        print(
            "  PHASE 3 - "
            "Authenticated ffuf"
        )
        print(
            "  =================================="
        )

        driver.ensure_session()

        auth_headers = (
            driver.get_auth_headers()
        )

        # Katana뿐 아니라 로그인 과정에서
        # 관찰된 /api/login 등의 Path도
        # ffuf Root Seed로 활용
        ffuf_seed_results = (
            _deduplicate_results(
                katana_results
                + login_results
            )
        )

        ffuf_results = (
            discover_with_ffuf(
                base_url,

                wordlist=(
                    ffuf_wordlist
                ),

                seed_endpoints=(
                    ffuf_seed_results
                ),

                auth_headers=(
                    auth_headers
                ),

                proxy_url=(
                    mitm_proxy_url
                ),
                target_policy=target_policy,
            )
        )

        observe("ffuf", ffuf_results)

        # =================================================
        # PHASE 4
        # Playwright UI Interaction
        # =================================================

        print()
        print(
            "  =================================="
        )
        print(
            "  PHASE 4 - "
            "Playwright UI Interaction"
        )
        print(
            "  =================================="
        )

        if enable_playwright_interaction and (
            target_policy is None or target_policy.tools.playwright_interaction
        ):

            driver.ensure_session()

            # ffuf가 찾은 HTML도 확인할 수 있도록
            # Katana + ffuf를 Interaction Seed로 사용.
            interaction_seed = (
                _deduplicate_results(
                    katana_results
                    + ffuf_results
                )
            )

            try:

                driver.run_interaction_pass(
                    interaction_seed
                )

            except Exception as exc:

                print(
                    "  [경고] "
                    "Playwright Interaction 실패: "
                    f"{exc}"
                )

        # 로그인 과정 + Interaction 과정
        playwright_results = (
            driver.get_http_results()
        )
        playwright_results = _filter_results_by_policy(
            playwright_results, base_url=base_url, target_policy=target_policy
        )

        observe_browser("playwright_interaction")

        websocket_results = (
            driver.get_websocket_results()
        )

        print()
        print(
            "  Playwright HTTP Unique : "
            f"{len(playwright_results)}"
        )

        print(
            "  WebSocket Connections  : "
            f"{len(websocket_results)}"
        )

        # =================================================
        # Primary Surface
        # =================================================

        primary_results = (
            _deduplicate_results(
                katana_results
                + ffuf_results
                + playwright_results
            )
        )

        print()
        print(
            "  =================================="
        )
        print(
            "  1차 Surface"
        )
        print(
            "  =================================="
        )

        print(
            f"  Katana     : "
            f"{len(katana_results)}"
        )

        print(
            f"  ffuf       : "
            f"{len(ffuf_results)}"
        )

        print(
            f"  Playwright : "
            f"{len(playwright_results)}"
        )

        print(
            f"  Unique     : "
            f"{len(primary_results)}"
        )

        # =================================================
        # PHASE 5
        # OpenAPI / GraphQL
        # =================================================

        print()
        print(
            "  =================================="
        )
        print(
            "  PHASE 5 - "
            "API Secondary Discovery"
        )
        print(
            "  =================================="
        )

        driver.ensure_session()

        auth_headers = (
            driver.get_auth_headers()
        )

        secondary_results: list[
            dict
        ] = []

        try:
            secondary_results = discover_api_secondary(
                base_url,

                primary_results,

                headers=(
                    auth_headers
                ),

                zap_executable=(
                    zap_executable
                ),
                target_policy=target_policy,
                proxy_url=mitm_proxy_url,
            )

        except Exception as exc:

            print(
                "  [경고] "
                "API Secondary Discovery 실패: "
                f"{exc}"
            )

        observe("api_secondary", secondary_results)
        observe_browser("playwright_final")

        # =================================================
        # Final
        # =================================================

        final_results = (
            _deduplicate_results(
                primary_results
                + secondary_results
            )
        )

        secondary_new = (
            len(final_results)
            - len(primary_results)
        )

        print()
        print(
            "  =================================="
        )
        print(
            "  Endpoint Discovery FINAL"
        )
        print(
            "  =================================="
        )

        print(
            f"  Katana Standard   : "
            f"{len(standard_results)}"
        )

        print(
            f"  Katana Headless   : "
            f"{len(headless_results)}"
        )

        print(
            f"  Katana Unique     : "
            f"{len(katana_results)}"
        )

        print(
            f"  ffuf              : "
            f"{len(ffuf_results)}"
        )

        print(
            f"  Playwright HTTP   : "
            f"{len(playwright_results)}"
        )

        print(
            f"  WebSocket 연결    : "
            f"{len(websocket_results)}"
        )

        print(
            f"  API Secondary     : "
            f"{len(secondary_results)}"
        )

        print(
            f"  API 신규 Endpoint : "
            f"{secondary_new}"
        )

        print(
            f"  최종 Unique       : "
            f"{len(final_results)}"
        )

        print(
            "  =================================="
        )

        return final_results

    finally:

        if driver is not None:
            try:
                observe_browser("playwright_cleanup")
            finally:
                driver.close()

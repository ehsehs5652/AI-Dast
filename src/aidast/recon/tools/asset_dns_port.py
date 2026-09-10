"""ASSET_DISCOVERY / DNS_RESOLUTION / HOST_PORT_DISCOVERY - Domain/Wildcard
scope only. A URL-scope target (e.g. Juice Shop) never reaches these.

Every wrapper skips gracefully (prints a warning, returns []) when the
underlying binary isn't installed, so the pipeline never hard-crashes just
because subfinder/dnsx/naabu aren't on PATH yet.
"""

from __future__ import annotations

import shutil
import subprocess


def _run_tool(command: list[str], *, tool_name: str, input_text: str | None = None, timeout: int = 120) -> list[str]:
    if shutil.which(command[0]) is None:
        print(f"  [건너뜀] {tool_name}이 설치돼 있지 않음")
        return []
    try:
        completed = subprocess.run(
            command, input=input_text, capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"  [경고] {tool_name} 실행 실패: {exc}")
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def run_subfinder(domain: str) -> list[str]:
    return _run_tool(["subfinder", "-d", domain, "-silent"], tool_name="subfinder")


def run_dnsx(hosts: list[str]) -> list[str]:
    if not hosts:
        return []
    return _run_tool(["dnsx", "-silent"], tool_name="dnsx", input_text="\n".join(hosts))


def run_naabu(hosts: list[str], *, ports: list[int] | None = None) -> list[str]:
    if not hosts or ports == []:
        return []
    command = ["naabu", "-silent"]
    if ports is not None:
        command += ["-p", ",".join(str(port) for port in ports)]
    return _run_tool(command, tool_name="naabu", input_text="\n".join(hosts))


def run_nmap(hosts: list[str], *, ports: list[int] | None = None) -> list[str]:
    """호스트별로 nmap을 돌려서 열린 포트를 `host:port` 문자열 리스트로 반환.

    naabu와 출력 형식(host:port)을 맞춰서 executor.py가 두 도구 결과를 같은
    방식으로 파싱할 수 있게 한다. nmap은 naabu와 달리 표준입력으로 여러
    호스트를 한 번에 못 받아서(호스트 인자 방식) 호스트마다 따로 실행한다.
    """
    if not hosts or ports == []:
        return []
    if shutil.which("nmap") is None:
        print("  [건너뜀] nmap이 설치돼 있지 않음")
        return []
    results: list[str] = []
    for host in hosts:
        try:
            command = ["nmap", "-Pn", "-T2", "--open"]
            if ports is not None:
                command += ["-p", ",".join(str(port) for port in ports)]
            command += ["-oG", "-", host]
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"  [경고] nmap 실행 실패: {exc}")
            continue
        for line in completed.stdout.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            ports_field = line.split("Ports:", 1)[1].split("\t")[0]
            for entry in ports_field.split(","):
                fields = entry.strip().split("/")
                if len(fields) >= 2 and fields[0].isdigit() and fields[1] == "open":
                    results.append(f"{host}:{fields[0]}")
    return results

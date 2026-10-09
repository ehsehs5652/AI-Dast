"""Owned ordinary HTTP I/O with one deadline through DNS, TLS, headers and EOF."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request

from aidast.core.request_broker import BrokerResponse
from .transport_broker import ValidationTransportError

_MAX_RESPONSE_BYTES = 200_000
_RESPONSE_READ_CHUNK_BYTES = 65_536


class HttpDeadlineError(ValidationTransportError):
    """Ordinary HTTP could not complete before its absolute deadline."""


class MultipartResponseIncompleteError(ValidationTransportError):
    """The response cannot establish bounded, complete assertion evidence."""


_MAX_RESOLVER_WORK = 20


class _BoundedResolverFacility:
    """One owned, globally bounded home for deadline-limited hostname lookup."""

    def __init__(self, capacity: int) -> None:
        self._slots = threading.BoundedSemaphore(capacity)
        self._executor = ThreadPoolExecutor(
            max_workers=capacity, thread_name_prefix="ValidationHttpResolver",
        )

    def resolve(self, host: str, port: int, *, deadline: float,
                clock: Callable[[], float]) -> tuple[tuple[int, tuple[Any, ...]], ...]:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        flags = socket.AI_NUMERICHOST if literal is not None else 0

        remaining = deadline - clock()
        if remaining <= 0 or not self._slots.acquire(timeout=remaining):
            raise HttpDeadlineError("HTTP operation deadline exceeded")
        try:
            future = self._executor.submit(
                socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM, 0, flags,
            )
        except BaseException:
            self._slots.release()
            raise
        future.add_done_callback(lambda _: self._slots.release())
        try:
            addresses = future.result(timeout=max(0.0, deadline - clock()))
        except TimeoutError as error:
            future.cancel()  # releases immediately if queued; running work stays owned/bounded.
            raise HttpDeadlineError("HTTP operation deadline exceeded") from error
        except BaseException as error:
            raise HttpDeadlineError("HTTP hostname resolution failed") from error
        if clock() >= deadline or not addresses:
            raise HttpDeadlineError("HTTP hostname resolution failed")
        return tuple((family, sockaddr) for family, _, _, _, sockaddr in addresses)


_RESOLVER_FACILITY = _BoundedResolverFacility(_MAX_RESOLVER_WORK)


def content_length_is_incomplete(response, received_bytes: int) -> bool:
    """Recognize declared-length EOF truncation, including HTTPError wrappers."""
    candidates = (response, getattr(response, "fp", None))
    for candidate in candidates:
        if candidate is None:
            continue
        remaining = getattr(candidate, "length", None)
        if type(remaining) is int and remaining >= 0:
            return remaining > 0
    headers = getattr(response, "headers", None)
    transfer_encoding = headers.get("Transfer-Encoding") if headers is not None else None
    content_length = headers.get("Content-Length") if headers is not None else None
    if transfer_encoding is not None or content_length is None:
        return False
    try:
        declared = int(content_length)
    except (TypeError, ValueError):
        return False
    return declared >= 0 and received_bytes < declared


def read_complete_response(response, *, deadline: float | None = None,
                            clock: Callable[[], float] = time.monotonic,
                            before_read: Callable[[], None] | None = None) -> bytes:
    """Read complete data below the capture limit, never a byte beyond it."""
    content = bytearray()
    # read1 returns buffered/available bytes without waiting to fill a whole
    # chunk. This leaves a deadline check between socket reads while the
    # caller's watchdog bounds HTTP framing/header reads inside read1.
    read_available = getattr(response, "read1", None) if deadline is not None else None
    reader = read_available or response.read
    maximum = _RESPONSE_READ_CHUNK_BYTES if deadline is None or read_available else 1
    while len(content) < _MAX_RESPONSE_BYTES:
        if deadline is not None and clock() >= deadline:
            raise MultipartResponseIncompleteError("multipart response exceeded its absolute deadline")
        if before_read is not None:
            before_read()
        chunk = reader(min(maximum, _MAX_RESPONSE_BYTES - len(content)))
        if deadline is not None and clock() >= deadline:
            raise MultipartResponseIncompleteError("multipart response exceeded its absolute deadline")
        if type(chunk) is not bytes:
            raise ValidationTransportError("multipart response reader returned invalid bytes")
        if not chunk:
            if content_length_is_incomplete(response, len(content)):
                raise MultipartResponseIncompleteError(
                    "multipart response ended before its declared content length"
                )
            return bytes(content)
        content.extend(chunk)
    # Reading even one lookahead byte would exceed the durable response-byte reservation.
    raise MultipartResponseIncompleteError("multipart response completeness is unknown at capture limit")


class DeadlineHttpTransport:
    """Preserve injected callables; own cancellation for the native default."""

    def __init__(self, *, transport=None, clock=time.monotonic, monotonic_ns=time.monotonic_ns):
        self.transport, self.clock, self.monotonic_ns = transport, clock, monotonic_ns
        self._ordinary_http = transport is None

    def send(self, request: Request, *, deadline: float,
             timeout: float) -> tuple[BrokerResponse, float, int]:
        method = request.get_method()
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise HttpDeadlineError("HTTP operation deadline exceeded")
        started = self.clock()
        connection: http.client.HTTPConnection | None = None
        timer: threading.Timer | None = None
        response = None
        connecting_socket: socket.socket | None = None

        def sockets() -> tuple[socket.socket, ...]:
            candidates = [connecting_socket, None if connection is None else connection.sock]
            fp = None if response is None else getattr(response, "fp", None)
            candidates.append(getattr(getattr(fp, "raw", None), "_sock", None))
            return tuple(dict.fromkeys(item for item in candidates if isinstance(item, socket.socket)))

        def abort() -> None:
            for item in sockets():
                try:
                    item.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            try:
                if connection is not None:
                    connection.close()
            except OSError:
                pass

        def ensure_remaining() -> float:
            value = deadline - self.clock()
            if value <= 0:
                raise HttpDeadlineError("HTTP operation deadline exceeded")
            return value

        def connect_with_deadline(address: tuple[str, int], connection_timeout: float, source_address=None) -> socket.socket:
            # Installed as http.client's connection factory, retaining normal
            # HTTP(S) framing and HTTPS verification/SNI while making DNS and
            # acquisition separately deadline-aware.
            del connection_timeout, source_address
            nonlocal connecting_socket
            host, port = address
            candidates = _RESOLVER_FACILITY.resolve(host, port, deadline=deadline, clock=self.clock)
            last_error: OSError | None = None
            for family, sockaddr in candidates:
                ensure_remaining()
                candidate = socket.socket(family, socket.SOCK_STREAM)
                connecting_socket = candidate
                try:
                    candidate.settimeout(ensure_remaining())
                    candidate.connect(sockaddr)
                    candidate.settimeout(ensure_remaining())
                    return candidate
                except BaseException as error:
                    try:
                        candidate.close()
                    except OSError:
                        pass
                    if connecting_socket is candidate:
                        connecting_socket = None
                    if not isinstance(error, OSError):
                        raise
                    last_error = error
            if last_error is not None:
                raise last_error
            raise HttpDeadlineError("HTTP hostname resolution failed")

        try:
            try:
                if self._ordinary_http:
                    parsed = urlsplit(request.full_url)
                    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
                    connection = connection_type(parsed.hostname, parsed.port, timeout=min(timeout, remaining))
                    timer = threading.Timer(max(0.0, deadline - self.clock()), abort)
                    timer.daemon = True
                    timer.start()
                    target = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
                    # Test seams that model just request/getresponse intentionally
                    # omit connect.  Real http.client connections acquire first so
                    # expiry cannot turn into a later request transmission.
                    if hasattr(connection, "connect"):
                        connection._create_connection = connect_with_deadline
                        if parsed.scheme == "https":
                            # Acquire TCP with the absolute deadline, then take
                            # ownership of the TLS socket before its handshake
                            # blocks. Implicit wrapping detaches the raw socket
                            # before the watchdog can see the handshaking socket.
                            http.client.HTTPConnection.connect(connection)
                            connecting_socket = connection._context.wrap_socket(
                                connection.sock, server_hostname=connection.host,
                                do_handshake_on_connect=False,
                            )
                            connection.sock = connecting_socket
                            connecting_socket.settimeout(ensure_remaining())
                            connecting_socket.do_handshake()
                            connecting_socket.settimeout(ensure_remaining())
                        else:
                            connection.connect()
                    ensure_remaining()  # immediately after socket acquisition
                    dispatch_ns = self.monotonic_ns()  # immediately before send
                    connection.request(method, target, body=request.data, headers=dict(request.header_items()))
                    if connection.sock is not None:
                        connection.sock.settimeout(ensure_remaining())
                    response = connection.getresponse()
                else:
                    # Injected transports own cancellation of a blocking call; the
                    # adapter still invokes them and fail-closes if they return
                    # after the absolute deadline.
                    timer = threading.Timer(max(0.0, deadline - self.clock()), abort)
                    timer.daemon = True
                    timer.start()
                    dispatch_ns = self.monotonic_ns()  # immediately before seam invocation
                    response = self.transport(request, timeout=min(timeout, ensure_remaining()))
                    ensure_remaining()
            except HTTPError as error:
                response = error
            def before_read() -> None:
                for item in sockets():
                    try:
                        item.settimeout(ensure_remaining())
                    except OSError:
                        # http.client can detach its connection socket once the
                        # response owns it; the response socket remains in the
                        # candidate set and retains the current deadline.
                        continue
            body = read_complete_response(
                response, deadline=deadline, clock=self.clock, before_read=before_read,
            )
            result = BrokerResponse(int(getattr(response, "status", getattr(response, "code", 0))),
                request.full_url if connection is not None else response.geturl(),
                dict(getattr(response, "headers", {}) or {}), body)
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            if response is not None:
                try:
                    response.close()
                except OSError:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            if connecting_socket is not None:
                try:
                    connecting_socket.close()
                except OSError:
                    pass
        duration = max(0.0, (self.clock() - started) * 1000)
        if self.clock() >= deadline:
            raise HttpDeadlineError("HTTP operation deadline exceeded")
        return result, duration, dispatch_ns

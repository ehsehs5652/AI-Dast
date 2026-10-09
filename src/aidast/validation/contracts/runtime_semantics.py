"""Profile-aware minimum proof rules for target-supplied runtime contracts."""

from __future__ import annotations

from typing import Any, Iterable

from .browser_contract import BrowserRuntimeContract
from .models import canonical_json, canonical_sha256
from .multipart_contract import MultipartRuntimeContract
from .oob_contract import OobRuntimeContract
from .websocket_contract import WebSocketRuntimeContract
from .grpc_contract import GrpcRuntimeContract
from .concurrent_contract import ConcurrentRuntimeContract
from ..core.profiles import ValidationProfile
from .runtime_contract import HttpRuntimeContract


class RuntimeSemanticError(ValueError):
    """A valid runtime schema cannot prove the profile's declared signal."""


_HTTP_CONTENT_ASSERTIONS = frozenset({"header_equals", "body_contains", "json_equals"})
_HTTP_DURATION_ASSERTIONS = frozenset({
    "duration_at_least_ms", "duration_at_most_ms",
})


def _different(left: object, right: object, message: str) -> None:
    if canonical_sha256(left) == canonical_sha256(right):
        raise RuntimeSemanticError(message)


def _proof_assertions(
    assertions: Iterable[Any], kinds: frozenset[str],
) -> tuple[str, ...]:
    return tuple(sorted(
        canonical_json(item.model_dump(mode="json", exclude={"assertion_id"}))
        for item in assertions if item.kind in kinds
    ))


def _same_proof_assertions(
    target: Iterable[Any], negative: Iterable[Any], kinds: frozenset[str], message: str,
) -> None:
    if _proof_assertions(target, kinds) != _proof_assertions(negative, kinds):
        raise RuntimeSemanticError(message)


def validate_runtime_semantics(
    runtime: HttpRuntimeContract | BrowserRuntimeContract | OobRuntimeContract | MultipartRuntimeContract | WebSocketRuntimeContract | GrpcRuntimeContract | ConcurrentRuntimeContract,
    profile: ValidationProfile,
) -> None:
    """Reject controls or assertions that cannot establish the profile signal."""

    if isinstance(runtime, HttpRuntimeContract):
        _different(
            runtime.target.request.model_dump(mode="json"),
            runtime.negative_control.request.model_dump(mode="json"),
            "HTTP target and inert negative control requests must differ",
        )
        assertion_kinds = {item.kind for item in runtime.target.assertions}
        if "timing" in profile.signal_types:
            if not assertion_kinds & _HTTP_DURATION_ASSERTIONS:
                raise RuntimeSemanticError(
                    "timing profiles require a target duration assertion"
                )
            proof_kinds = _HTTP_DURATION_ASSERTIONS
        elif not assertion_kinds & _HTTP_CONTENT_ASSERTIONS:
            raise RuntimeSemanticError(
                "HTTP target proof requires a header, body, or JSON assertion"
            )
        else:
            proof_kinds = _HTTP_CONTENT_ASSERTIONS
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            proof_kinds,
            "HTTP negative control must evaluate the same target proof assertions",
        )
        return

    if isinstance(runtime, BrowserRuntimeContract):
        _different(
            runtime.target.navigation.model_dump(mode="json"),
            runtime.negative_control.navigation.model_dump(mode="json"),
            "browser target and inert negative control navigations must differ",
        )
        assertion_kinds = {item.kind for item in runtime.target.assertions}
        if profile.attack_skill_name == "hunt-xss" and "console_contains" not in assertion_kinds:
            raise RuntimeSemanticError(
                "XSS target proof requires an execution marker in browser console observations"
            )
        proof_kinds = (
            frozenset({"console_contains"})
            if profile.attack_skill_name == "hunt-xss"
            else frozenset(assertion_kinds)
        )
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            proof_kinds,
            "browser negative control must evaluate the same target proof assertions",
        )
        return

    if isinstance(runtime, MultipartRuntimeContract):
        _different(
            runtime.target.request.model_dump(mode="json"),
            runtime.negative_control.request.model_dump(mode="json"),
            "multipart target and inert negative control requests must differ",
        )
        assertion_kinds = {item.kind for item in runtime.target.assertions}
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            _HTTP_CONTENT_ASSERTIONS,
            "multipart negative control must evaluate the same target proof assertions",
        )
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            _HTTP_DURATION_ASSERTIONS,
            "multipart negative control must evaluate the same target proof assertions",
        )
        if "timing" in profile.signal_types:
            if not assertion_kinds & _HTTP_DURATION_ASSERTIONS:
                raise RuntimeSemanticError(
                    "multipart timing profiles require a target duration assertion"
                )
        elif not assertion_kinds & _HTTP_CONTENT_ASSERTIONS:
            raise RuntimeSemanticError(
                "multipart target proof requires a header, body, or JSON assertion"
            )
        return

    if isinstance(runtime, WebSocketRuntimeContract):
        _different(
            [frame.model_dump(mode="json") for frame in runtime.target.frames],
            [frame.model_dump(mode="json") for frame in runtime.negative_control.frames],
            "WebSocket target and inert negative outbound frames must differ",
        )
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            frozenset({"text_contains", "json_equals", "binary_sha256", "close_code_equals",
                       "subprotocol_equals", "frame_kind_sequence"}),
            "WebSocket negative control must evaluate the same target proof assertions",
        )
        return

    if isinstance(runtime, GrpcRuntimeContract):
        _different(
            runtime.target.message, runtime.negative_control.message,
            "gRPC target and inert negative request messages must differ",
        )
        _same_proof_assertions(
            runtime.target.assertions, runtime.negative_control.assertions,
            frozenset({"grpc_status_equals", "protobuf_path_equals", "trailer_equals",
                       "error_detail_contains", "duration_at_least_ms", "duration_at_most_ms"}),
            "gRPC negative control must evaluate the same target proof assertions",
        )
        return

    if isinstance(runtime, ConcurrentRuntimeContract):
        _different(
            runtime.target.request.model_dump(mode="json"),
            runtime.negative_control.request.model_dump(mode="json"),
            "concurrent target and inert negative child requests must differ",
        )
        _same_proof_assertions(
            runtime.target.member_assertions, runtime.negative_control.member_assertions,
            frozenset(item.kind for item in runtime.target.member_assertions)
            | frozenset(item.kind for item in runtime.negative_control.member_assertions),
            "concurrent negative control must evaluate the same target proof assertions",
        )
        _same_proof_assertions(
            runtime.target.aggregate_assertions, runtime.negative_control.aggregate_assertions,
            frozenset(item.kind for item in runtime.target.aggregate_assertions)
            | frozenset(item.kind for item in runtime.negative_control.aggregate_assertions),
            "concurrent negative control must evaluate the same target proof assertions",
        )
        if runtime.target.start_skew_at_most_ms != runtime.negative_control.start_skew_at_most_ms:
            raise RuntimeSemanticError(
                "concurrent negative control must use the same start skew proof assertion"
            )
        target_final, negative_final = runtime.target.final_verification, runtime.negative_control.final_verification
        if (target_final is None) != (negative_final is None):
            raise RuntimeSemanticError(
                "concurrent negative control must use the same final HTTP proof assertion"
            )
        if target_final is not None and negative_final is not None:
            _same_proof_assertions(
                target_final.assertions, negative_final.assertions,
                frozenset(item.kind for item in target_final.assertions)
                | frozenset(item.kind for item in negative_final.assertions),
                "concurrent negative control must evaluate the same final HTTP proof assertions",
            )
        if "timing" in profile.signal_types and not (
            {item.kind for item in runtime.target.member_assertions} & _HTTP_DURATION_ASSERTIONS
            or runtime.target.start_skew_at_most_ms is not None
        ):
            raise RuntimeSemanticError(
                "concurrent timing profiles require a duration or start skew assertion"
            )
        if "state_change" in profile.signal_types and not (
            any(item.kind in {"success_count_equals", "success_count_at_least"}
                for item in runtime.target.aggregate_assertions)
            or runtime.target.final_verification is not None
        ):
            raise RuntimeSemanticError(
                "concurrent state-change profiles require aggregate success or final-state assertion"
            )
        return

    if isinstance(runtime, OobRuntimeContract):
        _different(
            runtime.target.trigger.model_dump(mode="json"),
            runtime.negative_control.trigger.model_dump(mode="json"),
            "OOB target and inert negative control triggers must differ",
        )
        target_criteria = (
            runtime.target.token_template, runtime.target.protocols,
            runtime.target.minimum_callbacks,
        )
        negative_criteria = (
            runtime.negative_control.token_template, runtime.negative_control.protocols,
            runtime.negative_control.minimum_callbacks,
        )
        if target_criteria != negative_criteria:
            raise RuntimeSemanticError(
                "OOB negative control must use the same callback proof criteria"
            )
        return

    raise RuntimeSemanticError("unsupported runtime contract for a Validation profile")

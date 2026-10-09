"""Shared live Validation with explicit legacy database compatibility."""

from .legacy.agent import (
    EvidenceOnlyReviewer,
    ValidationAgent,
    ValidationReviewer,
    load_skill,
    prepare_validation,
    record_validation,
    validate_assessment,
)
from .contracts.models import (
    AttackClaim,
    BlindCase,
    BlindDisclosureError,
    DevelopmentCapability,
    ImpactDevelopmentCapability,
    StagedBlindCase,
)
from .execution.browser_adapter import BrowserExecutor, BrowserReproductionPort
from .contracts.browser_contract import (
    BrowserAssertion,
    BrowserAttemptContract,
    BrowserElementSnapshot,
    BrowserObservationSnapshot,
    BrowserRuntimeContract,
    evaluate_browser_observation,
)
from .execution.chain_adapter import ChainReproductionPort
from .contracts.chain_contract import (
    ChainBindingContract,
    ChainRuntimeContract,
    ChainStepContract,
    extract_chain_value,
    inject_chain_value,
)
from .orchestration.coordinator import (
    PolicyProvider,
    ValidationAgentRunner,
    ValidationCoordinator,
    ValidationCoordinatorError,
)
from .orchestration.codex_runner import CodexBlindValidationRunner
from .orchestration.eligibility_runner import CodexEligibilityRunner, EligibilityAgentRunner
from .orchestration.impact_runner import CodexImpactDevelopmentRunner
from .execution.credentials import KeyringCredentialBackend, PipelineCredentialResolver
from .core.decision import DecisionEngine, DecisionInput
from .contracts.development import (
    DevelopmentActionContract,
    DevelopmentRuntimeContract,
    NativePrerequisiteResolver,
)
from .contracts.impact_development import (
    ImpactDevelopmentActionContract,
    ImpactDevelopmentRuntimeContract,
)
from .core.decision import ImpactGapAnalyzer
from .execution.http_adapter import HttpReproductionPort
from .execution.impact_development import (
    ImpactDevelopmentError,
    ImpactDevelopmentObservation,
    ImpactDevelopmentPlan,
    ImpactDevelopmentPlanner,
    ImpactDevelopmentPort,
    ImpactDevelopmentRequest,
    ImpactHypothesisExecutor,
)
from .execution.native_impact import NativeImpactDevelopmentPort
from .execution.http_oob_observer import HttpJsonOobObserver, HttpOobObserverConfig
from .core.decision import ImpactResult, evaluate_impact
from .core.integrity import (
    CandidateIntegrityError,
    CandidateIntegrityGate,
    ValidatedCandidate,
    canonical_reproduction_spec,
    reproduction_spec_digest,
)
from .legacy.models import (
    PoCAssessment,
    QuestionAnswer,
    ValidationAssessment,
    ValidationError,
)
from .core.matching import (
    KnownCandidate,
    KnownMatch,
    KnownMatcher,
    canonical_payload,
    payload_structure_sha256,
)
from .contracts.models import (
    BlindAssessment,
    ClaimComparison,
    ValidationCaseSnapshot,
    ValidationStageResult,
    canonical_json,
    canonical_sha256,
)
from .contracts.eligibility import (
    EligibilityAssessment,
    EligibilityRequest,
    RequiredImpactCondition,
    ScopeEligibilityError,
    ScopePolicySource,
)
from .core.scope_eligibility import unknown_assessment, validate_grounding
from .orchestration.native import build_native_validation_coordinator
from .execution.oob_adapter import OobObserver, OobReproductionPort
from .contracts.oob_contract import (
    OobAttemptContract,
    OobEvent,
    OobObservationSnapshot,
    OobRuntimeContract,
    evaluate_oob_observation,
)
from .execution.playwright_browser import (
    BrowserExecutionError,
    BrowserPolicyRejection,
    PlaywrightBrowserExecutor,
)
from .core.policy import TargetPolicyProvider
from .core.profiles import (
    ResolvedValidationProfile,
    SkillProfileResolver,
    ValidationProfile,
    ValidationProfileError,
)
from .persistence.repository import (
    ConcurrentValidationUpdate,
    ValidationRepository,
    ValidationRepositoryError,
)
from .contracts.models import (
    PrerequisiteResolverPort,
    ReproductionObservation,
    ReproductionPort,
)
from .execution.request_broker import (
    ValidationPolicyRejection,
    ValidationRequestBroker,
    ValidationRequestError,
)
from .execution.runtime_adapter import RuntimeReproductionRouter
from .contracts.runtime_contract import (
    HttpAttemptContract,
    HttpRequestTemplate,
    HttpRuntimeContract,
    ResponseAssertion,
    evaluate_http_response,
    render_http_request,
    validate_runtime_contract,
)
from .contracts.runtime_semantics import RuntimeSemanticError, validate_runtime_semantics
from .persistence.repository import shared_validation_status
from .legacy.store import read_verified_validation, validation_status

SharedValidationError = ValidationCoordinatorError

__all__ = [
    "AttackClaim",
    "BlindAssessment",
    "BlindCase",
    "BlindDisclosureError",
    "BinaryArtifactResolver",
    "BinaryArtifactUnavailable",
    "BinaryFrame",
    "BinaryValue",
    "BrowserAssertion",
    "BrowserAttemptContract",
    "BrowserElementSnapshot",
    "BrowserExecutionError",
    "BrowserExecutor",
    "BrowserObservationSnapshot",
    "BrowserPolicyRejection",
    "BrowserReproductionPort",
    "BrowserRuntimeContract",
    "CandidateIntegrityError",
    "CandidateIntegrityGate",
    "ChainBindingContract",
    "ChainReproductionPort",
    "ChainRuntimeContract",
    "ChainStepContract",
    "ClaimComparison",
    "CloseFrame",
    "CodexBlindValidationRunner",
    "CodexEligibilityRunner",
    "CodexImpactDevelopmentRunner",
    "ConcurrentValidationUpdate",
    "ConcurrentAggregateAssertion",
    "ConcurrentAttemptContract",
    "ConcurrentExecutionError",
    "ConcurrentMemberResult",
    "ConcurrentReproductionPort",
    "ConcurrentRuntimeContract",
    "DecisionEngine",
    "DecisionInput",
    "DevelopmentActionContract",
    "DevelopmentCapability",
    "DevelopmentRuntimeContract",
    "DescriptorMethod",
    "EligibilityAssessment",
    "EligibilityAgentRunner",
    "EligibilityRequest",
    "EvidenceOnlyReviewer",
    "HttpAttemptContract",
    "HttpJsonOobObserver",
    "HttpOobObserverConfig",
    "HttpReproductionPort",
    "HttpRequestTemplate",
    "HttpRuntimeContract",
    "ImpactGapAnalyzer",
    "ImpactDevelopmentError",
    "ImpactDevelopmentActionContract",
    "ImpactDevelopmentCapability",
    "ImpactDevelopmentObservation",
    "ImpactDevelopmentPlan",
    "ImpactDevelopmentPlanner",
    "ImpactDevelopmentPort",
    "ImpactDevelopmentRequest",
    "ImpactDevelopmentRuntimeContract",
    "ImpactHypothesisExecutor",
    "ImpactResult",
    "KeyringCredentialBackend",
    "KnownCandidate",
    "KnownMatch",
    "KnownMatcher",
    "JsonFrame",
    "GrpcAssertion",
    "GrpcAttemptContract",
    "GrpcReproductionPort",
    "GrpcRuntimeContract",
    "GrpcSessionError",
    "LoadedGrpcMethod",
    "NativePrerequisiteResolver",
    "NativeImpactDevelopmentPort",
    "MultipartAttemptContract",
    "MultipartFilePart",
    "MultipartReproductionPort",
    "MultipartRequestTemplate",
    "MultipartResponseIncompleteError",
    "MultipartRuntimeContract",
    "MultipartTextPart",
    "OobAttemptContract",
    "OobEvent",
    "OobObservationSnapshot",
    "OobObserver",
    "OobReproductionPort",
    "OobRuntimeContract",
    "PipelineCredentialResolver",
    "PlaywrightBrowserExecutor",
    "PoCAssessment",
    "PolicyProvider",
    "PrerequisiteResolverPort",
    "QuestionAnswer",
    "ReproductionObservation",
    "ReproductionPort",
    "ResolvedValidationProfile",
    "ResponseAssertion",
    "RuntimeReproductionRouter",
    "RuntimeSemanticError",
    "RequiredImpactCondition",
    "SharedValidationError",
    "SkillProfileResolver",
    "ScopeEligibilityError",
    "ScopePolicySource",
    "StagedBlindCase",
    "TargetPolicyProvider",
    "TextFrame",
    "TransportDispatchResult",
    "TransportOperationSpec",
    "TransportReservation",
    "ValidatedCandidate",
    "ValidationAgent",
    "ValidationAgentRunner",
    "ValidationAssessment",
    "ValidationCaseSnapshot",
    "ValidationCoordinator",
    "ValidationCoordinatorError",
    "ValidationError",
    "ValidationPolicyRejection",
    "ValidationProfile",
    "ValidationProfileError",
    "ValidationRepository",
    "ValidationRepositoryError",
    "ValidationRequestBroker",
    "ValidationRequestError",
    "ValidationReviewer",
    "ValidationStageResult",
    "ValidationTransportBroker",
    "ValidationTransportError",
    "WebSocketAssertion",
    "WebSocketAttemptContract",
    "WebSocketReproductionPort",
    "WebSocketRuntimeContract",
    "WebSocketSessionError",
    "build_native_validation_coordinator",
    "canonical_json",
    "canonical_payload",
    "canonical_reproduction_spec",
    "canonical_sha256",
    "evaluate_browser_observation",
    "evaluate_concurrent_results",
    "evaluate_grpc_response",
    "evaluate_http_response",
    "evaluate_impact",
    "evaluate_oob_observation",
    "evaluate_websocket_observation",
    "encode_multipart",
    "extract_chain_value",
    "inject_chain_value",
    "load_skill",
    "payload_structure_sha256",
    "prepare_validation",
    "read_verified_validation",
    "record_validation",
    "render_http_request",
    "reproduction_spec_digest",
    "shared_validation_status",
    "validate_assessment",
    "validate_grounding",
    "validate_runtime_contract",
    "validate_runtime_semantics",
    "validation_status",
    "unknown_assessment",
]

# Preserve established module paths while implementations live in responsibility packages.
import sys as _sys
from importlib import import_module as _import_module

_COMPAT_MODULES = {
    "agent": "legacy.agent",
    "blind": "contracts.models",
    "browser_adapter": "execution.browser_adapter",
    "browser_contract": "contracts.browser_contract",
    "binary": "contracts.binary",
    "chain_adapter": "execution.chain_adapter",
    "chain_contract": "contracts.chain_contract",
    "codex_runner": "orchestration.codex_runner",
    "coordinator": "orchestration.coordinator",
    "concurrent_adapter": "execution.concurrent_adapter",
    "concurrent_contract": "contracts.concurrent_contract",
    "credentials": "execution.credentials",
    "decision": "core.decision",
    "development": "contracts.development",
    "eligibility": "contracts.eligibility",
    "evidence_policy": "persistence.evidence_policy",
    "gaps": "core.decision",
    "grpc_adapter": "execution.grpc_adapter",
    "grpc_contract": "contracts.grpc_contract",
    "http_adapter": "execution.http_adapter",
    "http_oob_observer": "execution.http_oob_observer",
    "impact": "core.decision",
    "integrity": "core.integrity",
    "matching": "core.matching",
    "multipart_adapter": "execution.multipart_adapter",
    "multipart_contract": "contracts.multipart_contract",
    "models": "contracts.models",
    "native": "orchestration.native",
    "oob_adapter": "execution.oob_adapter",
    "oob_contract": "contracts.oob_contract",
    "playwright_browser": "execution.playwright_browser",
    "policy": "core.policy",
    "profiles": "core.profiles",
    "repository": "persistence.repository",
    "reproduction": "contracts.models",
    "request_broker": "execution.request_broker",
    "runtime_adapter": "execution.runtime_adapter",
    "runtime_contract": "contracts.runtime_contract",
    "runtime_semantics": "contracts.runtime_semantics",
    "scope_eligibility": "core.scope_eligibility",
    "source": "persistence.source",
    "status": "persistence.repository",
    "store": "legacy.store",
    "transport_broker": "execution.transport_broker",
    "websocket_adapter": "execution.websocket_adapter",
    "websocket_contract": "contracts.websocket_contract",
}
for _old_name, _new_name in _COMPAT_MODULES.items():
    try:
        _module = _import_module(f".{_new_name}", __name__)
    except (ImportError, OSError):
        continue
    else:
        _sys.modules[f"{__name__}.{_old_name}"] = _module
        globals()[_old_name] = _module

_LAZY_EXPORTS = {
    "BinaryArtifactResolver": ("contracts.binary", "BinaryArtifactResolver"),
    "BinaryArtifactUnavailable": ("contracts.binary", "BinaryArtifactUnavailable"),
    "BinaryValue": ("contracts.binary", "BinaryValue"),
    "MultipartTextPart": ("contracts.multipart_contract", "MultipartTextPart"),
    "MultipartFilePart": ("contracts.multipart_contract", "MultipartFilePart"),
    "MultipartRequestTemplate": ("contracts.multipart_contract", "MultipartRequestTemplate"),
    "MultipartAttemptContract": ("contracts.multipart_contract", "MultipartAttemptContract"),
    "MultipartRuntimeContract": ("contracts.multipart_contract", "MultipartRuntimeContract"),
    "encode_multipart": ("contracts.multipart_contract", "encode_multipart"),
    "MultipartReproductionPort": ("execution.multipart_adapter", "MultipartReproductionPort"),
    "MultipartResponseIncompleteError": (
        "execution.multipart_adapter", "MultipartResponseIncompleteError",
    ),
    "WebSocketAssertion": ("contracts.websocket_contract", "WebSocketAssertion"),
    "TextFrame": ("contracts.websocket_contract", "TextFrame"),
    "JsonFrame": ("contracts.websocket_contract", "JsonFrame"),
    "BinaryFrame": ("contracts.websocket_contract", "BinaryFrame"),
    "CloseFrame": ("contracts.websocket_contract", "CloseFrame"),
    "WebSocketAttemptContract": ("contracts.websocket_contract", "WebSocketAttemptContract"),
    "WebSocketRuntimeContract": ("contracts.websocket_contract", "WebSocketRuntimeContract"),
    "evaluate_websocket_observation": (
        "contracts.websocket_contract", "evaluate_websocket_observation",
    ),
    "WebSocketReproductionPort": ("execution.websocket_adapter", "WebSocketReproductionPort"),
    "WebSocketSessionError": ("execution.websocket_adapter", "WebSocketSessionError"),
    "GrpcAssertion": ("contracts.grpc_contract", "GrpcAssertion"),
    "DescriptorMethod": ("contracts.grpc_contract", "DescriptorMethod"),
    "LoadedGrpcMethod": ("contracts.grpc_contract", "LoadedGrpcMethod"),
    "GrpcAttemptContract": ("contracts.grpc_contract", "GrpcAttemptContract"),
    "GrpcRuntimeContract": ("contracts.grpc_contract", "GrpcRuntimeContract"),
    "evaluate_grpc_response": ("contracts.grpc_contract", "evaluate_grpc_response"),
    "GrpcReproductionPort": ("execution.grpc_adapter", "GrpcReproductionPort"),
    "GrpcSessionError": ("execution.grpc_adapter", "GrpcSessionError"),
    "ConcurrentAggregateAssertion": (
        "contracts.concurrent_contract", "ConcurrentAggregateAssertion",
    ),
    "ConcurrentAttemptContract": ("contracts.concurrent_contract", "ConcurrentAttemptContract"),
    "ConcurrentRuntimeContract": ("contracts.concurrent_contract", "ConcurrentRuntimeContract"),
    "ConcurrentMemberResult": ("execution.concurrent_adapter", "ConcurrentMemberResult"),
    "evaluate_concurrent_results": ("execution.concurrent_adapter", "evaluate_concurrent_results"),
    "ConcurrentReproductionPort": ("execution.concurrent_adapter", "ConcurrentReproductionPort"),
    "ConcurrentExecutionError": ("execution.concurrent_adapter", "ConcurrentExecutionError"),
    "TransportDispatchResult": ("execution.transport_broker", "TransportDispatchResult"),
    "TransportOperationSpec": ("execution.transport_broker", "TransportOperationSpec"),
    "TransportReservation": ("execution.transport_broker", "TransportReservation"),
    "ValidationTransportBroker": ("execution.transport_broker", "ValidationTransportBroker"),
    "ValidationTransportError": ("execution.transport_broker", "ValidationTransportError"),
}


def __getattr__(name):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(_import_module(f".{module_name}", __name__), attribute)
    globals()[name] = value
    return value

del _COMPAT_MODULES, _module, _new_name, _old_name, _sys

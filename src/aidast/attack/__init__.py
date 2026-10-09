"""Local handoff consumers for reviewing existing evidence."""

from .runtime import ReviewPlan, ReviewPreparationError, prepare_review
from .skill_agent import (
    AttackTestResult,
    AuthorizedTest,
    FindingAssessment,
    HypothesisBatch,
    HypothesisProposal,
    SkillAttackAgent,
    SkillAttackResult,
    StructuredSkillAttackPlanner,
)
from .skills import AttackSkill, AttackSkillLibrary
from .workflow import SkillAttackWorkflow
from .authorization import sign_ed25519, verify_ed25519
from .ed25519_authorization import (
    LocalEd25519AuthorizationProvider,
    generate_keypair,
    load_verified,
    new_document,
    sign_authorization,
    to_run_authorization,
)
from .executor_factory import select_executor
from .idor import DualIdentityIdorExecutor
from .intent_manifest import (
    bind_intents_to_authorization,
    intent_digest,
    load_intent_manifest,
    write_intent_manifest,
)
from .intent_resolver import ObservedIntentResolver
from .launcher import SessionAttackLauncher
from .local_workflow import CodexSkillAttackPlanner, build_local_skill_workflow
from .playwright_transport import PlaywrightSessionTransport
from .policy_executor import PolicyServiceAttackExecutor
from .service_factory import build_policy_service
from .session_binding import SessionBindingError, SessionBindings
from .session_pool import PersistentSessionPool
from .template_loader import (
    AttackTemplateError,
    load_attack_template,
    template_descriptors,
    template_ids_for_skill,
)
from .template_models import AttackTemplate, TemplateTarget
from .template_runner import compile_template_probes, evaluate_template_response

__all__ = [
    "AttackSkill",
    "AttackTemplate",
    "AttackTemplateError",
    "AttackSkillLibrary",
    "AttackTestResult",
    "AuthorizedTest",
    "FindingAssessment",
    "HypothesisBatch",
    "HypothesisProposal",
    "ReviewPlan",
    "ReviewPreparationError",
    "SkillAttackAgent",
    "SkillAttackResult",
    "SkillAttackWorkflow",
    "CodexSkillAttackPlanner",
    "DualIdentityIdorExecutor",
    "LocalEd25519AuthorizationProvider",
    "ObservedIntentResolver",
    "PersistentSessionPool",
    "PlaywrightSessionTransport",
    "PolicyServiceAttackExecutor",
    "SessionAttackLauncher",
    "SessionBindingError",
    "SessionBindings",
    "TemplateTarget",
    "bind_intents_to_authorization",
    "build_local_skill_workflow",
    "build_policy_service",
    "generate_keypair",
    "compile_template_probes",
    "evaluate_template_response",
    "intent_digest",
    "load_intent_manifest",
    "load_attack_template",
    "load_verified",
    "new_document",
    "select_executor",
    "sign_authorization",
    "sign_ed25519",
    "to_run_authorization",
    "template_descriptors",
    "template_ids_for_skill",
    "verify_ed25519",
    "write_intent_manifest",
    "StructuredSkillAttackPlanner",
    "prepare_review",
]

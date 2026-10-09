"""Offline stage tracking and validated data handoffs.

This package stores workflow state and artifacts; it does not execute tools.
"""

from aidast.pipeline.models import ArtifactReference, HandoffManifest, hash_artifact, verify_artifact

__all__ = ["ArtifactReference", "HandoffManifest", "hash_artifact", "verify_artifact"]

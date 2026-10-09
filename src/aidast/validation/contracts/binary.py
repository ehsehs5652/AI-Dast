"""Strict, bounded binary values for trusted Validation contract data."""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable
from typing import Annotated

from pydantic import Field, model_validator

from .models import Digest, StrictContract


BinaryArtifactResolver = Callable[[str], bytes]
_ARTIFACT_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_MAX_BINARY_BYTES = 1_000_000


class BinaryArtifactUnavailable(ValueError):
    """A trusted resolver cannot currently provide an otherwise valid artifact."""


class BinaryValue(StrictContract):
    """One verified inline value or one opaque resolver-backed artifact."""

    inline_base64: str | None = Field(default=None, max_length=1_333_336)
    artifact_ref: str | None = Field(default=None, max_length=256)
    length: Annotated[int, Field(ge=0, le=_MAX_BINARY_BYTES)]
    sha256: Digest

    @model_validator(mode="after")
    def one_verified_representation(self) -> "BinaryValue":
        if (self.inline_base64 is None) == (self.artifact_ref is None):
            raise ValueError("binary value requires exactly one inline_base64 or artifact_ref")
        if self.artifact_ref is not None and _ARTIFACT_REFERENCE.fullmatch(self.artifact_ref) is None:
            raise ValueError("binary artifact reference must be an opaque identifier")
        if self.inline_base64 is not None:
            try:
                decoded = base64.b64decode(self.inline_base64.encode("ascii"), validate=True)
            except (UnicodeEncodeError, ValueError) as exc:
                raise ValueError("binary inline_base64 must be strict base64") from exc
            self._verify(decoded)
        return self

    def _verify(self, value: bytes) -> bytes:
        if type(value) is not bytes:
            raise ValueError("binary resolver must return bytes")
        if len(value) != self.length:
            raise ValueError("binary value length does not match its declaration")
        if hashlib.sha256(value).hexdigest() != self.sha256:
            raise ValueError("binary value digest does not match its declaration")
        return value

    def resolve(self, resolver: BinaryArtifactResolver | None) -> bytes:
        """Resolve only an already-injected opaque reference and verify its bytes."""
        if self.inline_base64 is not None:
            # Validation in the model constructor already proved this decode is safe.
            return self._verify(base64.b64decode(self.inline_base64.encode("ascii"), validate=True))
        if resolver is None:
            raise BinaryArtifactUnavailable("binary artifact resolver is unavailable")
        try:
            value = resolver(self.artifact_ref)
        except (OSError, ValueError, KeyError) as exc:
            raise BinaryArtifactUnavailable("binary artifact resolution failed") from exc
        return self._verify(value)

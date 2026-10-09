"""Conservative, local identity checks for browser discovery screens."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_TRACKING_KEYS = frozenset({"gclid", "fbclid", "msclkid", "mc_cid", "mc_eid"})


def canonical_visit_key(url: str) -> str:
    """Collapse URL presentation noise without discarding functional parameters."""
    parsed = urlsplit(url)
    query = sorted(
        (key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.lower().startswith("utm_") and key.lower() not in _TRACKING_KEYS
    )
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    # Fragments are absent from HTTP requests but may select distinct SPA views.
    # Keep them in the browser visit key; the rendered screen decides whether
    # two fragment routes can share an interaction pass.
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path,
                       urlencode(query, doseq=True), parsed.fragment))


def screen_fingerprint(snapshot: object, *, origin: str) -> str | None:
    """Hash visible page content and controls; never persist or send page text."""
    if not isinstance(snapshot, dict):
        return None
    text = snapshot.get("main_text")
    controls = snapshot.get("controls")
    if not isinstance(text, str) or not isinstance(controls, list):
        return None
    normalized_text = re.sub(r"\s+", " ", text).strip().casefold()
    normalized_controls = [
        re.sub(r"\s+", " ", control).strip().casefold()
        for control in controls[:100] if isinstance(control, str)
    ]
    # A loading shell or near-empty error page is too weak to identify safely.
    if len(normalized_text) < 40 or not normalized_controls:
        return None
    length = snapshot.get("text_length")
    payload = [origin.lower(), normalized_text[:16000], normalized_controls]
    if type(length) is int and length >= 0:
        payload.append(length)
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

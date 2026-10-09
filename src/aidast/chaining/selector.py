"""Select bounded Hunt references from Attack findings for chaining."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from contextlib import closing
from pathlib import Path
from typing import Iterable


MAX_CHAIN_HUNT_SKILLS = 8

_RULES = (
    (("idor", "object authorization", "access control"),
     ("hunt-idor", "hunt-auth-bypass", "hunt-business-logic")),
    (("xss", "cross-site scripting"),
     ("hunt-xss", "hunt-session", "hunt-csrf", "hunt-ato")),
    (("ssrf", "server-side request forgery"),
     ("hunt-ssrf", "hunt-cloud-misconfig", "hunt-rce")),
    (("open redirect", "redirect"),
     ("hunt-open-redirect", "hunt-oauth", "hunt-ato")),
    (("cors",), ("hunt-cors", "hunt-session", "hunt-idor")),
    (("csrf",), ("hunt-csrf", "hunt-xss", "hunt-auth-bypass")),
    (("oauth", "oidc", "sso"),
     ("hunt-oauth", "hunt-open-redirect", "hunt-session", "hunt-ato")),
    (("jwt",), ("hunt-jwt-crypto", "hunt-session", "hunt-auth-bypass", "hunt-ato")),
    (("upload",), ("hunt-file-upload", "hunt-xss", "hunt-xxe", "hunt-rce")),
    (("path traversal", "lfi", "file read"),
     ("hunt-lfi", "hunt-source-leak", "hunt-rce")),
    (("sqli", "sql injection"),
     ("hunt-sqli", "hunt-auth-bypass", "hunt-source-leak")),
    (("graphql",), ("hunt-graphql", "hunt-idor", "hunt-auth-bypass")),
    (("rate limit", "brute force", "otp"),
     ("hunt-brute-force", "hunt-ato", "hunt-business-logic")),
    (("session", "cookie"), ("hunt-session", "hunt-xss", "hunt-ato")),
)


def select_chaining_skills(
    db_path: Path, scan_id: str, available_skills: Iterable[str],
    *, limit: int = MAX_CHAIN_HUNT_SKILLS,
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    if type(limit) is not int or not 1 <= limit <= MAX_CHAIN_HUNT_SKILLS:
        raise ValueError("Chaining Hunt Skill limit must be between 1 and 8")
    available = frozenset(available_skills)
    scores: dict[str, int] = defaultdict(int)
    reasons: dict[str, set[str]] = defaultdict(set)
    uri = Path(db_path).resolve(strict=True).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        rows = conn.execute(
            """SELECT f.vuln_type,f.title
               FROM findings f
               WHERE f.scan_id=? AND f.status IN ('unreviewed','confirmed')
                 AND EXISTS (SELECT 1 FROM attack_attempts a
                             WHERE a.finding_id=f.finding_id AND a.outcome='confirmed')
               ORDER BY f.created_at,f.finding_id""",
            (scan_id,),
        ).fetchall()
    for vuln_type, title in rows:
        text = f"{vuln_type or ''} {title or ''}".casefold()
        for needles, skills in _RULES:
            if any(needle in text for needle in needles):
                for position, skill in enumerate(skills):
                    if skill in available:
                        scores[skill] += 100 - position * 10
                        reasons[skill].add(f"chain neighbor for {needles[0]}")
    if not scores and "hunt-business-logic" in available:
        scores["hunt-business-logic"] = 1
        reasons["hunt-business-logic"].add("generic impact composition")
    selected = tuple(sorted(scores, key=lambda item: (-scores[item], item))[:limit])
    return selected, {
        name: tuple(sorted(reasons[name]))[:5] for name in selected
    }

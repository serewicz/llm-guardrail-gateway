"""Who is asking.

DEMO ONLY: the user comes from the X-User header and the department from a
static map in the policy file. Anyone can set a header. Replacing this with
SSO/OIDC (department from an IdP group claim) is roadmap work.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Identity:
    user: str
    dept: str


def identify(user_header: str | None, users: dict[str, str], default_dept: str = "unassigned") -> Identity:
    user = (user_header or "anonymous").strip() or "anonymous"
    return Identity(user, users.get(user, default_dept))  # unknown users get the default (least) dept

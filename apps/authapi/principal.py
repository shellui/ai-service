"""Authenticated principal extracted from identity-service JWTs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StoragePrincipal:
    """Lightweight stand-in for Django's User, built from JWT claims."""

    user_id: int
    company_id: int | None
    email: str = ''
    username: str = ''
    is_staff: bool = False
    is_company_owner: bool = False
    is_company_admin: bool = False
    access_global_metrics: bool = False
    claims: dict[str, Any] = field(default_factory=dict)

    @property
    def pk(self) -> int:
        return self.user_id

    @property
    def id(self) -> int:
        return self.user_id

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def __str__(self) -> str:
        return self.email or self.username or str(self.user_id)


_ADMIN_GROUP_NAMES = frozenset({'admin', 'admins', 'company admin', 'company admins'})


def _claim_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'on'}
    return False


def company_admin_from_claims(claims: dict[str, Any], user_metadata: dict[str, Any] | None = None) -> bool:
    """True for a company admin who is not necessarily an owner.

    Identity marks owners with ``is_company_owner``. A company admin is
    ``is_company_admin``, or a group named admin, admins, or company admins.
    """
    meta = user_metadata if isinstance(user_metadata, dict) else {}
    if _claim_flag(meta.get('is_company_admin')) or _claim_flag(claims.get('is_company_admin')):
        return True
    groups = meta.get('groups')
    if groups is None:
        groups = claims.get('groups')
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, list):
        return False
    for group in groups:
        if str(group).strip().lower() in _ADMIN_GROUP_NAMES:
            return True
    return False


def principal_from_claims(claims: dict[str, Any]) -> StoragePrincipal:
    user_metadata = claims.get('user_metadata') or {}
    if not isinstance(user_metadata, dict):
        user_metadata = {}

    raw_uid = claims.get('user_id', claims.get('sub'))
    try:
        user_id = int(raw_uid)
    except (TypeError, ValueError) as exc:
        raise ValueError('JWT is missing a numeric user id / sub claim.') from exc

    raw_company = claims.get('company_id')
    company_id: int | None
    if raw_company in (None, ''):
        company_id = None
    else:
        try:
            company_id = int(raw_company)
        except (TypeError, ValueError) as exc:
            raise ValueError('JWT company_id must be an integer.') from exc

    return StoragePrincipal(
        user_id=user_id,
        company_id=company_id,
        email=str(claims.get('email') or user_metadata.get('email') or ''),
        username=str(claims.get('username') or user_metadata.get('username') or ''),
        is_staff=bool(user_metadata.get('is_staff', False)) or _claim_flag(claims.get('is_staff')),
        is_company_owner=bool(user_metadata.get('is_company_owner', False)) or _claim_flag(claims.get('is_company_owner')),
        is_company_admin=company_admin_from_claims(claims, user_metadata),
        access_global_metrics=bool(claims.get('pat_agm', False)),
        claims=claims,
    )

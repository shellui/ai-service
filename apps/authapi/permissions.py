from rest_framework.permissions import BasePermission


class IsAuthenticatedPrincipal(BasePermission):
    """Require a StoragePrincipal from IdentityJWKSAuthentication."""

    def has_permission(self, request, view):
        user = request.user
        return bool(user and getattr(user, 'is_authenticated', False))


class IsStaffOrCompanyOwner(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not getattr(user, 'is_authenticated', False):
            return False
        return bool(getattr(user, 'is_staff', False) or getattr(user, 'is_company_owner', False))


def _is_agent_principal(user) -> bool:
    """Agent access tokens are not company admin callers."""
    claims = getattr(user, 'claims', None)
    if not isinstance(claims, dict):
        claims = {}
    if claims.get('agent_id') and str(claims.get('sub') or '').startswith('agent:'):
        return True
    username = str(getattr(user, 'username', '') or '')
    return username.startswith('agent:')


class IsMcpCallLogReader(BasePermission):
    """Staff, company owners, or company admins. Agent tokens are refused.

    Staff follows the existing ai-service admin rule (``IsStaffOrCompanyOwner``):
    a staff user may read the company on their JWT. Company admins are
    ``is_company_admin`` or an admin group, and do not have to be owners.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not getattr(user, 'is_authenticated', False):
            return False
        if _is_agent_principal(user):
            return False
        return bool(
            getattr(user, 'is_staff', False)
            or getattr(user, 'is_company_owner', False)
            or getattr(user, 'is_company_admin', False)
        )

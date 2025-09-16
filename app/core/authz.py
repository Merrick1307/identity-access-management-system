import asyncpg
from fastapi import HTTPException, status

from app.core.queries import fetch_user_condition
from app.models.authz import Action


class AuthFactory:
    permission_map = {
        'read': Action.READ,
        'write': Action.WRITE,
        'delete': Action.DELETE,
        'approve': Action.APPROVE,
        'reject': Action.REJECT,
        'execute': Action.EXECUTE,
        'assign': Action.ASSIGN,
        'manage': Action.MANAGE,
        'export': Action.EXPORT,
        'import': Action.IMPORT,
        'activate': Action.ACTIVATE,
        'archive': Action.ARCHIVE
    }

    @staticmethod
    def check_permission(user_policy: dict, permission_needed: str, resource: str):
        user_perm = user_policy.get(resource, 0)
        needed_perm = AuthFactory.permission_map.get(permission_needed.lower(), 0)
        return bool(user_perm & needed_perm)

    @staticmethod
    def check_role(user_policy: dict, required_role: str):
        user_role = user_policy.get("role")
        if user_role.lower() != required_role.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized role"
            )
        return True

    @staticmethod
    async def check_condition(
            db: asyncpg.Connection, conditions_to_compare: dict,
            resource: str, user_policy: dict, user_id: str,
            tenant_id: str
    ):
        if conditions_to_compare["validity_time"]:
            if user_policy.get(resource):
                if len(conditions_to_compare) == 1:
                    return True

                conditions: dict = await db.fetchval(
                    fetch_user_condition, user_id, tenant_id, resource
                )
                conditions_to_compare.pop("validity_time", 0)
                filtered_conditions = {k: v for k,v in conditions.items() if (k,v) in conditions_to_compare.items()}

                if not all(value in filtered_conditions.values() for value in conditions_to_compare.values()):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Unauthorized action, Reason: condition not satisfied"
                    )

                return True
            return False






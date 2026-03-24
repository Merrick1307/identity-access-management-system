from fastapi import APIRouter

from .auth import router as auth_router
from .authz import router as authz_router
from .onboarding import router as onboarding_router
from .policies import router as policies_router
from .users import router as users_router
from .tenants import router as tenants_router
from .federation import router as federation_router
from app.sso.oidc import discovery_router, oidc_router, signup_router, clients_router

router: APIRouter = APIRouter()

router.include_router(auth_router, prefix="/authenticate", tags=["authentication"])
router.include_router(authz_router, prefix="/pdp", tags=["authorization"])
router.include_router(onboarding_router, prefix="/onboarding", tags=["onboarding"])
router.include_router(policies_router, prefix="/policies", tags=["policies"])
router.include_router(users_router, prefix="/users", tags=["users"])
router.include_router(tenants_router)
router.include_router(discovery_router, tags=["oidc-discovery"])
router.include_router(oidc_router, prefix="/oidc", tags=["oidc"])
router.include_router(signup_router, prefix="/oidc", tags=["oidc-signup"])
router.include_router(clients_router, prefix="/oidc", tags=["oidc-clients"])
router.include_router(federation_router)
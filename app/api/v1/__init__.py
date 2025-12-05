from fastapi import APIRouter

from .auth import router as auth_router
from .authz import router as authz_router
from .onboarding import router as onboarding_router
from .policies import router as policies_router

router: APIRouter = APIRouter()

router.include_router(auth_router, prefix="/authenticate", tags=["authentication"])
router.include_router(authz_router, prefix="/authorize", tags=["authorization"])
router.include_router(onboarding_router, prefix="/onboarding", tags=["onboarding"])
router.include_router(policies_router, prefix="/policies", tags=["policies"])
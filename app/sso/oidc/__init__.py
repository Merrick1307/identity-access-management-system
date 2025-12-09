from .discovery import router as discovery_router
from .endpoints import router as oidc_router
from .signup import router as signup_router
from .clients import router as clients_router

__all__ = ["discovery_router", "oidc_router", "signup_router", "clients_router"]

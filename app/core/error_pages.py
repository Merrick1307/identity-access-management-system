"""
Browser-friendly error page utilities.
Provides helpers to detect browser requests and render themed HTML error pages.
"""
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent.parent
_templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def wants_html(request: Request) -> bool:
    """Determine if the client prefers an HTML response."""
    accept = request.headers.get("accept", "")
    sec_fetch_dest = request.headers.get("sec-fetch-dest", "")
    sec_fetch_mode = request.headers.get("sec-fetch-mode", "")

    if "text/html" in accept:
        return True

    if sec_fetch_dest == "document" or sec_fetch_mode == "navigate":
        return True

    return False


def resolve_safe_back_url(request: Request, candidate: Optional[str] = None) -> str:
    """Resolve a safe same-origin back URL from an explicit value or the Referer header."""
    value = candidate or request.headers.get("referer")
    if not value:
        return "/"

    parsed = urlparse(value)
    if not parsed.scheme and not parsed.netloc:
        if parsed.path.startswith("/") and not parsed.path.startswith("//"):
            back_url = parsed.path or "/"
            if parsed.query:
                back_url = f"{back_url}?{parsed.query}"
            return back_url
        return "/"

    request_url = request.url
    same_origin = (
        parsed.scheme == request_url.scheme
        and parsed.hostname == request_url.hostname
        and (parsed.port or request_url.port) == request_url.port
    )
    if not same_origin:
        return "/"

    back_url = parsed.path or "/"
    if parsed.query:
        back_url = f"{back_url}?{parsed.query}"
    return back_url


def render_html_error(
    request: Request,
    title: str = "Something went wrong",
    message: str = "An unexpected error occurred while processing your request.",
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    error_code: Optional[str] = None,
    details: Optional[str] = None,
    retry_url: Optional[str] = None,
    back_url: Optional[str] = None,
) -> HTMLResponse:
    """Render a themed HTML error page."""
    safe_back_url = resolve_safe_back_url(request, back_url)
    return _templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "title": title,
            "message": message,
            "error_code": error_code,
            "details": details,
            "retry_url": retry_url,
            "back_url": safe_back_url,
        },
        status_code=status_code,
    )

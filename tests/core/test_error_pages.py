from starlette.requests import Request

from app.core.error_pages import resolve_safe_back_url, wants_html


def make_request(*, method: str = "GET", headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": "/test",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "query_string": b"",
        "scheme": "https",
        "server": ("example.com", 443),
        "client": ("127.0.0.1", 1234),
    }
    return Request(scope)


def test_wants_html_with_explicit_html_accept():
    request = make_request(headers={"Accept": "text/html,application/xhtml+xml"})
    assert wants_html(request) is True


def test_wants_html_with_navigation_headers():
    request = make_request(headers={"Sec-Fetch-Mode": "navigate"})
    assert wants_html(request) is True


def test_wants_html_no_accept_defaults_to_false():
    request = make_request()
    assert wants_html(request) is False


def test_resolve_safe_back_url_from_same_origin_referer():
    request = make_request(headers={"Referer": "https://example.com/previous?page=2"})
    assert resolve_safe_back_url(request) == "/previous?page=2"


def test_resolve_safe_back_url_rejects_external_referer():
    request = make_request(headers={"Referer": "https://attacker.example/phish"})
    assert resolve_safe_back_url(request) == "/"


def test_resolve_safe_back_url_allows_safe_relative_candidate():
    request = make_request()
    assert resolve_safe_back_url(request, "/settings/profile") == "/settings/profile"

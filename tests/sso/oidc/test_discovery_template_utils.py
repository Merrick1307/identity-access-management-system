from app.core.config import ALGORITHM
from starlette.requests import Request

from app.sso.oidc.discovery import openid_configuration
from app.sso.oidc import template_utils as tu


def make_request(path='/'):
    return Request({'type': 'http', 'method': 'GET', 'path': path, 'headers': [], 'scheme': 'https', 'server': ('hexiam.test', 443), 'client': ('127.0.0.1', 1234), 'query_string': b''})


async def test_openid_configuration_and_scope_items():
    resp = await openid_configuration(make_request())
    assert resp.status_code == 200
    body = resp.body.decode()
    assert 'authorization_endpoint' in body and '/api/v1/oidc/authorize' in body
    assert '/api/v1/oidc/introspect' in body
    assert ALGORITHM in body
    items = tu.get_scope_items(['openid', 'custom'])
    assert items[0].description.startswith('Access your user ID')
    assert items[1].description == 'Access to custom'


def test_provider_helpers():
    assert tu._provider_domain('https://accounts.google.com/o/oauth2') == 'accounts.google.com'
    assert tu._provider_icon_url('accounts.google.com') == 'https://www.google.com/s2/favicons?domain=accounts.google.com&sz=64'
    assert tu._provider_initials('Google Workspace', 'accounts.google.com') == 'GW'
    assert tu._provider_initials(None, None) == 'SS'


def test_template_renderers():
    req = make_request()
    assert tu.render_login_page(req, 'HexShare', 'cid', 'https://cb', 'code', 'openid email', 'state', 'nonce', 'cc', 'S256').status_code == 200
    assert tu.render_consent_page(req, 'HexShare', 'cid', 'user@example.com', ['openid', 'email'], 'https://cb', 'code', 'openid email', 'state', 'nonce', 'cc', 'S256').status_code == 200
    chooser = tu.render_provider_chooser_page(
        req,
        'HexShare',
        [{'id': 'p1', 'name': 'Google Workspace', 'issuer_url': 'https://accounts.google.com'}],
        'cid',
        'https://cb',
        'code',
        'openid',
        'state',
        None,
        None,
        None,
    )
    chooser_body = chooser.body.decode()
    assert chooser.status_code == 200
    assert 'accounts.google.com' in chooser_body
    assert 'https://www.google.com/s2/favicons?domain=accounts.google.com&amp;sz=64' in chooser_body
    assert 'Use local HEX IAM login' in chooser_body
    assert tu.render_signup_page(req, client_name='HexShare').status_code == 200
    assert tu.render_verification_sent_page(req, 'user@example.com').status_code == 200
    assert tu.render_error_page(req, title='Oops').status_code == 400

import json
from datetime import timedelta
from pathlib import Path

import pytest

from app.core.signing_keys import SigningKeyManager, _isoformat, _utc_now


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
def test_asymmetric_signing_and_jwks(tmp_path: Path, algorithm: str):
    manager = SigningKeyManager(
        algorithm=algorithm,
        keyset_path=tmp_path / f"{algorithm.lower()}.json",
        rotation_enabled=False,
    )

    token = manager.sign_token({"sub": "user@example.com", "tenant_id": "tenant-1"})
    header = __import__("jwt").get_unverified_header(token)
    payload = manager.decode_token(token, verify_aud=False)
    jwks = manager.jwks()

    assert header["alg"] == algorithm
    assert "kid" in header
    assert payload["sub"] == "user@example.com"
    assert jwks["keys"][0]["kid"] == header["kid"]
    assert jwks["keys"][0]["alg"] == algorithm


def test_key_rotation_keeps_existing_tokens_valid(tmp_path: Path):
    keyset_path = tmp_path / "jwks.json"
    manager = SigningKeyManager(
        algorithm="RS256",
        keyset_path=keyset_path,
        rotation_enabled=True,
        rotation_interval_seconds=1,
        retention_seconds=3600,
        rotation_check_interval_seconds=1,
    )

    first_token = manager.sign_token({"sub": "user@example.com", "tenant_id": "tenant-1"})
    first_header = __import__("jwt").get_unverified_header(first_token)

    state = json.loads(keyset_path.read_text(encoding="utf-8"))
    state["keys"][0]["created_at"] = _isoformat(_utc_now() - timedelta(seconds=5))
    keyset_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    manager._state = None
    manager._state_mtime = None
    manager._last_rotation_check = 0
    manager.ensure_ready()

    second_token = manager.sign_token({"sub": "user@example.com", "tenant_id": "tenant-1"})
    second_header = __import__("jwt").get_unverified_header(second_token)
    jwks = manager.jwks()

    assert first_header["kid"] != second_header["kid"]
    assert len(jwks["keys"]) == 2
    assert manager.decode_token(first_token, verify_aud=False)["sub"] == "user@example.com"
    assert manager.decode_token(second_token, verify_aud=False)["sub"] == "user@example.com"

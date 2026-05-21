import asyncio
import base64
import copy
import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.core.config import (
    ALGORITHM,
    JWT_KEYSET_PATH,
    JWT_KEY_RETENTION_SECONDS,
    JWT_KEY_ROTATION_CHECK_INTERVAL_SECONDS,
    JWT_KEY_ROTATION_ENABLED,
    JWT_KEY_ROTATION_INTERVAL_SECONDS,
    JWT_SECRET,
)

SUPPORTED_SIGNING_ALGORITHMS = {"HS256", "RS256", "ES256"}
ASYMMETRIC_SIGNING_ALGORITHMS = {"RS256", "ES256"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _int_to_bytes(value: int, size: Optional[int] = None) -> bytes:
    if size is None:
        size = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(size, byteorder="big")


class SigningKeyManager:
    def __init__(
        self,
        *,
        algorithm: str,
        secret: Optional[str] = None,
        keyset_path: Optional[Path] = None,
        rotation_enabled: bool = True,
        rotation_interval_seconds: int = 7 * 24 * 60 * 60,
        retention_seconds: int = 14 * 24 * 60 * 60,
        rotation_check_interval_seconds: int = 300,
    ) -> None:
        self.algorithm = (algorithm or "HS256").upper()
        if self.algorithm not in SUPPORTED_SIGNING_ALGORITHMS:
            raise ValueError(f"Unsupported JWT algorithm: {self.algorithm}")

        self.secret = secret or ""
        self.keyset_path = Path(keyset_path) if keyset_path else Path(".runtime/jwks.json")
        self.rotation_enabled = rotation_enabled
        self.rotation_interval_seconds = rotation_interval_seconds
        self.retention_seconds = retention_seconds
        self.rotation_check_interval_seconds = max(rotation_check_interval_seconds, 1)

        if self.algorithm == "HS256" and not self.secret:
            raise ValueError("JWT_SECRET must be configured for HS256 signing")

        self._lock = threading.RLock()
        self._state: Optional[dict[str, Any]] = None
        self._state_mtime: Optional[float] = None
        self._last_rotation_check = 0.0
        self._rotation_task: Optional[asyncio.Task] = None
        self._rotation_shutdown = asyncio.Event()

    def uses_asymmetric_keys(self) -> bool:
        return self.algorithm in ASYMMETRIC_SIGNING_ALGORITHMS

    def ensure_ready(self) -> None:
        if not self.uses_asymmetric_keys():
            return

        with self._lock:
            self._ensure_state_loaded_locked()
            self._maybe_rotate_locked()

    def sign_token(
        self,
        payload: dict[str, Any],
        *,
        headers: Optional[dict[str, Any]] = None,
        algorithm: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> str:
        resolved_algorithm = (algorithm or self.algorithm).upper()
        token_headers = dict(headers or {})

        if resolved_algorithm == "HS256":
            return jwt.encode(
                payload,
                secret_key or self.secret,
                algorithm=resolved_algorithm,
                headers=token_headers,
            )

        if resolved_algorithm != self.algorithm:
            raise ValueError(f"Configured signer uses {self.algorithm}, not {resolved_algorithm}")

        self.ensure_ready()
        with self._lock:
            active_key = self._get_active_key_locked()
            token_headers["kid"] = active_key["kid"]
            return jwt.encode(
                payload,
                active_key["private_pem"],
                algorithm=resolved_algorithm,
                headers=token_headers,
            )

    def decode_token(
        self,
        token: str,
        *,
        audience: Optional[str] = None,
        verify_aud: bool = False,
        options: Optional[dict[str, Any]] = None,
        algorithm: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> dict[str, Any]:
        header = jwt.get_unverified_header(token)
        resolved_algorithm = (algorithm or header.get("alg") or self.algorithm).upper()
        decode_options = {"verify_exp": True, "verify_aud": verify_aud}
        if options:
            decode_options.update(options)

        if resolved_algorithm == "HS256":
            return jwt.decode(
                token,
                secret_key or self.secret,
                algorithms=[resolved_algorithm],
                audience=audience,
                options=decode_options,
            )

        if resolved_algorithm != self.algorithm:
            raise jwt.InvalidAlgorithmError(
                f"Token algorithm {resolved_algorithm} does not match configured signer {self.algorithm}"
            )

        self.ensure_ready()
        kid = header.get("kid")
        with self._lock:
            candidates = self._get_candidate_keys_locked(kid)

        last_error: Optional[Exception] = None
        for candidate in candidates:
            try:
                return jwt.decode(
                    token,
                    candidate["public_pem"],
                    algorithms=[resolved_algorithm],
                    audience=audience,
                    options=decode_options,
                )
            except jwt.InvalidTokenError as exc:
                last_error = exc

        if last_error:
            raise last_error
        raise jwt.InvalidTokenError("No signing keys available for token verification")

    def jwks(self) -> dict[str, list[dict[str, Any]]]:
        if not self.uses_asymmetric_keys():
            return {"keys": []}

        self.ensure_ready()
        with self._lock:
            return {
                "keys": [copy.deepcopy(item["public_jwk"]) for item in self._state["keys"]]
            }

    async def start_rotation_task(self) -> None:
        if not self.uses_asymmetric_keys() or not self.rotation_enabled:
            return
        self.ensure_ready()
        if self._rotation_task and not self._rotation_task.done():
            return
        self._rotation_shutdown = asyncio.Event()
        self._rotation_task = asyncio.create_task(self._rotation_loop())

    async def stop_rotation_task(self) -> None:
        self._rotation_shutdown.set()
        if not self._rotation_task:
            return
        self._rotation_task.cancel()
        try:
            await self._rotation_task
        except asyncio.CancelledError:
            pass
        self._rotation_task = None

    async def _rotation_loop(self) -> None:
        while not self._rotation_shutdown.is_set():
            try:
                self.ensure_ready()
            except Exception:
                pass
            try:
                await asyncio.wait_for(
                    self._rotation_shutdown.wait(),
                    timeout=self.rotation_check_interval_seconds,
                )
            except asyncio.TimeoutError:
                continue

    def _ensure_state_loaded_locked(self) -> None:
        self.keyset_path.parent.mkdir(parents=True, exist_ok=True)
        if self.keyset_path.exists():
            current_mtime = self.keyset_path.stat().st_mtime
            if self._state is None or self._state_mtime != current_mtime:
                self._load_state_from_disk_locked()
            return

        with self._file_lock():
            if self.keyset_path.exists():
                self._load_state_from_disk_locked()
                return
            self._write_state_locked(self._build_initial_state_locked())

    def _load_state_from_disk_locked(self) -> None:
        raw = json.loads(self.keyset_path.read_text(encoding="utf-8"))
        if raw.get("algorithm") != self.algorithm:
            raise ValueError(
                f"Keyset algorithm {raw.get('algorithm')} does not match configured signer {self.algorithm}"
            )
        self._state = raw
        self._state_mtime = self.keyset_path.stat().st_mtime

    def _write_state_locked(self, state: dict[str, Any]) -> None:
        temp_path = self.keyset_path.with_suffix(f"{self.keyset_path.suffix}.tmp")
        temp_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(temp_path, self.keyset_path)
        self._state = state
        self._state_mtime = self.keyset_path.stat().st_mtime

    def _build_initial_state_locked(self) -> dict[str, Any]:
        key_record = self._generate_key_record_locked()
        return {
            "algorithm": self.algorithm,
            "active_kid": key_record["kid"],
            "keys": [key_record],
        }

    def _maybe_rotate_locked(self) -> None:
        if not self.rotation_enabled or self.rotation_interval_seconds <= 0:
            return

        now_monotonic = time.monotonic()
        if (now_monotonic - self._last_rotation_check) < self.rotation_check_interval_seconds:
            return
        self._last_rotation_check = now_monotonic

        active_key = self._get_active_key_locked()
        created_at = _parse_datetime(active_key["created_at"])
        if (_utc_now() - created_at).total_seconds() < self.rotation_interval_seconds:
            return

        with self._file_lock():
            self._load_state_from_disk_locked()
            active_key = self._get_active_key_locked()
            created_at = _parse_datetime(active_key["created_at"])
            if (_utc_now() - created_at).total_seconds() < self.rotation_interval_seconds:
                return

            updated_state = copy.deepcopy(self._state)
            new_key = self._generate_key_record_locked()
            updated_state["active_kid"] = new_key["kid"]
            updated_state["keys"].append(new_key)
            updated_state["keys"] = self._prune_keys(updated_state["keys"], updated_state["active_kid"])
            self._write_state_locked(updated_state)

    def _prune_keys(self, keys: list[dict[str, Any]], active_kid: str) -> list[dict[str, Any]]:
        cutoff = _utc_now().timestamp() - max(self.retention_seconds, 0)
        retained = []
        for item in keys:
            created_at = _parse_datetime(item["created_at"]).timestamp()
            if item["kid"] == active_kid or created_at >= cutoff:
                retained.append(item)
        return retained

    def _get_active_key_locked(self) -> dict[str, Any]:
        active_kid = self._state["active_kid"]
        for item in self._state["keys"]:
            if item["kid"] == active_kid:
                return item
        raise ValueError("Active signing key is missing from keyset")

    def _get_candidate_keys_locked(self, kid: Optional[str]) -> list[dict[str, Any]]:
        if kid:
            matches = [item for item in self._state["keys"] if item["kid"] == kid]
            if matches:
                return matches
        return list(self._state["keys"])

    def _generate_key_record_locked(self) -> dict[str, Any]:
        created_at = _utc_now()
        if self.algorithm == "RS256":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            public_jwk = {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": _base64url_encode(_int_to_bytes(public_numbers.n)),
                "e": _base64url_encode(_int_to_bytes(public_numbers.e)),
            }
        else:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            public_jwk = {
                "kty": "EC",
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": _base64url_encode(_int_to_bytes(public_numbers.x, 32)),
                "y": _base64url_encode(_int_to_bytes(public_numbers.y, 32)),
            }

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        kid = self._build_kid(public_pem)
        public_jwk["kid"] = kid
        return {
            "kid": kid,
            "created_at": _isoformat(created_at),
            "private_pem": private_pem,
            "public_pem": public_pem,
            "public_jwk": public_jwk,
        }

    @staticmethod
    def _build_kid(public_pem: str) -> str:
        digest = hashlib.sha256(public_pem.encode("utf-8")).digest()
        return _base64url_encode(digest[:12])

    @contextmanager
    def _file_lock(self):
        lock_path = Path(f"{self.keyset_path}.lock")
        deadline = time.monotonic() + 10
        lock_fd: Optional[int] = None

        while True:
            try:
                lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
                break
            except FileExistsError:
                if lock_path.exists():
                    age = time.time() - lock_path.stat().st_mtime
                    if age > 30:
                        try:
                            lock_path.unlink()
                            continue
                        except FileNotFoundError:
                            continue
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out waiting for key lock: {lock_path}")
                time.sleep(0.05)

        try:
            os.write(lock_fd, str(os.getpid()).encode("ascii"))
            yield
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


_signing_key_manager = SigningKeyManager(
    algorithm=ALGORITHM,
    secret=JWT_SECRET,
    keyset_path=JWT_KEYSET_PATH,
    rotation_enabled=JWT_KEY_ROTATION_ENABLED,
    rotation_interval_seconds=JWT_KEY_ROTATION_INTERVAL_SECONDS,
    retention_seconds=JWT_KEY_RETENTION_SECONDS,
    rotation_check_interval_seconds=JWT_KEY_ROTATION_CHECK_INTERVAL_SECONDS,
)


def get_signing_key_manager() -> SigningKeyManager:
    return _signing_key_manager


async def init_signing_key_manager(app_state: Any) -> None:
    manager = get_signing_key_manager()
    manager.ensure_ready()
    app_state.signing_key_manager = manager
    await manager.start_rotation_task()


async def shutdown_signing_key_manager() -> None:
    await get_signing_key_manager().stop_rotation_task()

"""Core token model of AnonID.

An *issuer* (for example, the organiser of an event) checks a person's right once
and signs a short token that states only that right ("access to event X until T").
A *verifier* (for example, the entrance terminal) checks the signature, the
expiry time and that the token has not been used before. No name, phone or
passport number is ever placed in the token or sent to the verifier.
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass, asdict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

TOKEN_VERSION = 1
PREFIX = "AID1"


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Claim:
    """What the token proves. Deliberately contains no personal data."""

    scope: str          # e.g. "event:kfu-it-day-2026"
    right: str          # e.g. "entry"
    issued_at: int
    expires_at: int
    token_id: str       # random, unlinkable to the person
    version: int = TOKEN_VERSION

    def to_bytes(self) -> bytes:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True).encode()

    @staticmethod
    def from_bytes(raw: bytes) -> "Claim":
        return Claim(**json.loads(raw))


class TokenError(Exception):
    """Raised when a token cannot be accepted."""


class Issuer:
    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def issue(self, scope: str, right: str = "entry", ttl_seconds: int = 3600,
              now: int | None = None) -> str:
        now = int(time.time()) if now is None else now
        claim = Claim(
            scope=scope,
            right=right,
            issued_at=now,
            expires_at=now + ttl_seconds,
            token_id=_b64e(secrets.token_bytes(16)),
        )
        payload = claim.to_bytes()
        signature = self._key.sign(payload)
        return f"{PREFIX}.{_b64e(payload)}.{_b64e(signature)}"


def parse(token: str) -> tuple[Claim, bytes, bytes]:
    try:
        prefix, payload_b64, sig_b64 = token.strip().split(".")
    except ValueError as exc:
        raise TokenError("malformed token") from exc
    if prefix != PREFIX:
        raise TokenError("unknown token format")
    payload, signature = _b64d(payload_b64), _b64d(sig_b64)
    try:
        claim = Claim.from_bytes(payload)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed payload") from exc
    return claim, payload, signature


class Verifier:
    """Checks tokens offline using only the issuer's public key."""

    def __init__(self, issuer_public_key: Ed25519PublicKey, store, expected_scope: str,
                 clock_skew: int = 30):
        self._pub = issuer_public_key
        self._store = store
        self._scope = expected_scope
        self._skew = clock_skew

    def verify(self, token: str, now: int | None = None) -> Claim:
        now = int(time.time()) if now is None else now
        claim, payload, signature = parse(token)
        try:
            self._pub.verify(signature, payload)
        except InvalidSignature as exc:
            raise TokenError("invalid signature") from exc
        if claim.version != TOKEN_VERSION:
            raise TokenError("unsupported token version")
        if claim.scope != self._scope:
            raise TokenError("token is for another scope")
        if claim.issued_at > now + self._skew:
            raise TokenError("token issued in the future")
        if claim.expires_at < now - self._skew:
            raise TokenError("token expired")
        if self._store.is_revoked(claim.token_id):
            raise TokenError("token revoked")
        if not self._store.mark_used(claim.token_id, now):
            raise TokenError("token already used (replay)")
        return claim

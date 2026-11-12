from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from ..errors import SignatureError, ValidationError
from ..models import SignedEnvelope
from ..util import canonical_json, decode_token, encode_token, parse_time, utc_now


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    key_id: str
    algorithm: str
    failure: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "failure": self.failure,
        }


class LocalKeyring:
    algorithm = "HMAC-SHA256-LOCAL-SIMULATION"

    def __init__(self, keys: Mapping[str, bytes | str] | None = None) -> None:
        self._keys: dict[str, bytes] = {}
        for key_id, secret in (keys or {}).items():
            self.add(key_id, secret)

    def add(self, key_id: str, secret: bytes | str) -> None:
        if not key_id or len(key_id) > 128:
            raise ValidationError("invalid key id")
        material = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(material) < 16:
            raise ValidationError("local signing secret must contain at least 16 bytes")
        self._keys[key_id] = material

    def remove(self, key_id: str) -> bool:
        return self._keys.pop(key_id, None) is not None

    def contains(self, key_id: str) -> bool:
        return key_id in self._keys

    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def sign(self, key_id: str, payload: Mapping[str, Any], *, signed_at: datetime | None = None) -> SignedEnvelope:
        secret = self._keys.get(key_id)
        if secret is None:
            raise SignatureError("unknown signing key", details={"key_id": key_id})
        timestamp = signed_at or utc_now()
        protected = self._protected_payload(key_id, dict(payload), timestamp)
        digest = hmac.new(secret, canonical_json(protected), hashlib.sha256).digest()
        return SignedEnvelope(
            key_id=key_id,
            algorithm=self.algorithm,
            payload=dict(payload),
            signature=encode_token(digest),
            signed_at=timestamp,
        )

    def verify(self, envelope: SignedEnvelope) -> VerificationResult:
        if envelope.algorithm != self.algorithm:
            return VerificationResult(False, envelope.key_id, envelope.algorithm, "unsupported_algorithm")
        secret = self._keys.get(envelope.key_id)
        if secret is None:
            return VerificationResult(False, envelope.key_id, envelope.algorithm, "unknown_key")
        protected = self._protected_payload(envelope.key_id, envelope.payload, envelope.signed_at)
        expected = hmac.new(secret, canonical_json(protected), hashlib.sha256).digest()
        try:
            actual = decode_token(envelope.signature)
        except ValidationError:
            return VerificationResult(False, envelope.key_id, envelope.algorithm, "malformed_signature")
        valid = hmac.compare_digest(expected, actual)
        return VerificationResult(valid, envelope.key_id, envelope.algorithm, None if valid else "signature_mismatch")

    def verify_or_raise(self, envelope: SignedEnvelope) -> None:
        result = self.verify(envelope)
        if not result.valid:
            raise SignatureError(
                "electronic declaration signature could not be verified",
                details=result.as_dict(),
            )

    def parse_envelope(self, value: Mapping[str, Any]) -> SignedEnvelope:
        required = {"key_id", "algorithm", "payload", "signature", "signed_at"}
        missing = sorted(required - set(value))
        if missing:
            raise ValidationError("signed envelope missing fields", details={"missing": missing})
        if not isinstance(value["payload"], Mapping):
            raise ValidationError("signed envelope payload must be an object")
        return SignedEnvelope(
            key_id=str(value["key_id"]),
            algorithm=str(value["algorithm"]),
            payload=dict(value["payload"]),
            signature=str(value["signature"]),
            signed_at=parse_time(value["signed_at"], "signed_at"),
        )

    def rotate(self, old_key_id: str, new_key_id: str, new_secret: bytes | str) -> None:
        if old_key_id not in self._keys:
            raise SignatureError("cannot rotate an unknown key", details={"key_id": old_key_id})
        self.add(new_key_id, new_secret)
        self.remove(old_key_id)

    def fingerprint(self, key_id: str) -> str:
        secret = self._keys.get(key_id)
        if secret is None:
            raise SignatureError("unknown signing key", details={"key_id": key_id})
        return hashlib.sha256(secret).hexdigest()[:24]

    @staticmethod
    def _protected_payload(key_id: str, payload: dict[str, Any], signed_at: datetime) -> dict[str, Any]:
        return {
            "key_id": key_id,
            "algorithm": LocalKeyring.algorithm,
            "signed_at": signed_at.isoformat(),
            "payload": payload,
        }

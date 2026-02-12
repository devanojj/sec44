from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from pydantic import BaseModel

from shared.serialization import canonical_json_bytes

HEADER_ORG = "X-EM-Org"
HEADER_DEVICE = "X-EM-Device"
HEADER_TIMESTAMP = "X-EM-Timestamp"
HEADER_NONCE = "X-EM-Nonce"
HEADER_SIGNATURE = "X-EM-Signature"


class SignatureError(ValueError):
    """Raised when signature verification fails."""


def _body_payload(body: bytes | BaseModel | dict[str, Any] | list[Any]) -> Any:
    if isinstance(body, bytes):
        decoded = body.decode("utf-8")
        parsed = json.loads(decoded)
        if not isinstance(parsed, (dict, list)):
            raise SignatureError("request body must be a JSON object or list")
        return parsed
    if isinstance(body, BaseModel):
        return body.model_dump(mode="json")
    return body


def sign_request(body: bytes | BaseModel | dict[str, Any] | list[Any], api_key: str) -> str:
    payload = _body_payload(body)
    canonical = canonical_json_bytes(payload)
    digest = hmac.new(api_key.encode("utf-8"), canonical, hashlib.sha256)
    return digest.hexdigest()


def build_signed_headers(
    body: bytes | BaseModel | dict[str, Any] | list[Any],
    api_key: str,
    org_id: str,
    device_id: str,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    nonce_value = nonce or secrets.token_hex(16)
    signature = sign_request(body, api_key)
    return {
        HEADER_ORG: org_id,
        HEADER_DEVICE: device_id,
        HEADER_TIMESTAMP: str(ts),
        HEADER_NONCE: nonce_value,
        HEADER_SIGNATURE: signature,
    }


def verify_request(
    body: bytes | BaseModel | dict[str, Any] | list[Any],
    headers: dict[str, str],
    api_key: str,
) -> bool:
    signature = headers.get(HEADER_SIGNATURE, "")
    if not signature:
        raise SignatureError("missing signature")
    if not headers.get(HEADER_TIMESTAMP):
        raise SignatureError("missing timestamp")
    if not headers.get(HEADER_NONCE):
        raise SignatureError("missing nonce")

    expected = sign_request(body, api_key)
    return hmac.compare_digest(signature, expected)

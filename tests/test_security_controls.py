from __future__ import annotations

import json

from shared.signing import HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, sign_request, verify_request


def test_signing_is_stable_for_permuted_keys() -> None:
    payload_a = {"z": 1, "a": {"k": "v", "n": 2}}
    payload_b = {"a": {"n": 2, "k": "v"}, "z": 1}
    api_key = "secret"
    assert sign_request(payload_a, api_key) == sign_request(payload_b, api_key)


def test_verify_rejects_tampered_payload() -> None:
    payload = {"a": 1, "b": 2}
    api_key = "secret"
    signature = sign_request(payload, api_key)
    headers = {
        HEADER_SIGNATURE: signature,
        HEADER_TIMESTAMP: "100",
        HEADER_NONCE: "n" * 32,
    }
    assert verify_request(payload, headers, api_key)

    tampered = json.dumps({"a": 1, "b": 999}).encode("utf-8")
    assert not verify_request(tampered, headers, api_key)

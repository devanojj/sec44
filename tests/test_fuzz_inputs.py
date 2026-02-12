from __future__ import annotations

import random
import string


def _rand_text(n: int) -> str:
    alphabet = string.ascii_letters + string.digits + "{}[],:\"'\\"
    return "".join(random.choice(alphabet) for _ in range(n))


def test_ingest_fuzz_inputs_do_not_500(client, signed_ingest) -> None:
    _, good_headers = signed_ingest("test-api-key", nonce="z" * 32)
    for i in range(20):
        body = _rand_text(random.randint(1, 4096)).encode("utf-8", errors="ignore")
        headers = dict(good_headers)
        headers["X-EM-Nonce"] = f"n{i:02d}".ljust(32, "n")
        response = client.post("/ingest", content=body, headers=headers)
        assert response.status_code in {400, 401, 409, 413, 422}


def test_auth_fuzz_inputs_do_not_500(client) -> None:
    for _ in range(20):
        payload = {
            "org_id": _rand_text(random.randint(0, 20)),
            "username": _rand_text(random.randint(0, 20)),
            "password": _rand_text(random.randint(0, 40)),
        }
        response = client.post("/auth/api/login", json=payload)
        assert response.status_code in {401, 422}

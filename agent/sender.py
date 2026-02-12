from __future__ import annotations

import logging
import secrets
import time
from datetime import UTC, datetime

import httpx

from agent.config import AgentConfig
from agent.spool import SpoolBatch, Spooler
from shared.constants import MAX_PAYLOAD_BYTES
from shared.schemas import IngestRequest, IngestResponse
from shared.serialization import canonical_json_bytes
from shared.signing import build_signed_headers

logger = logging.getLogger("endpoint_agent.sender")


class Sender:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.ingest_url = config.server_url.rstrip("/") + "/ingest"

    def _build_payload(self, batch: SpoolBatch) -> tuple[bytes, dict[str, str]]:
        nonce = secrets.token_hex(16)
        sent_at = datetime.now(UTC)
        req = IngestRequest(
            org_id=self.config.org_id,
            device_id=self.config.device_id,
            agent_version=self.config.agent_version,
            sent_at=sent_at,
            nonce=nonce,
            events=batch.events,
        )
        body = canonical_json_bytes(req)
        if len(body) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload exceeds max payload bytes")
        headers = build_signed_headers(
            body=req,
            api_key=str(self.config.api_key),
            org_id=self.config.org_id,
            device_id=self.config.device_id,
            timestamp=int(time.time()),
            nonce=nonce,
        )
        headers["Content-Type"] = "application/json"
        return body, headers

    def send_due(self, spooler: Spooler, limit: int = 20) -> tuple[int, int]:
        accepted = 0
        failed = 0
        batches = spooler.due_batches(limit=limit)
        if not batches:
            return 0, 0

        if not self.config.tls_verify:
            logger.warning("tls_verify is disabled; this must not be used in production")

        with httpx.Client(timeout=self.config.timeout_seconds, verify=self.config.tls_verify) as client:
            for batch in batches:
                if not batch.events:
                    spooler.mark_sent(batch.batch_id)
                    continue
                try:
                    body, headers = self._build_payload(batch)
                except Exception as exc:
                    logger.warning("dropping malformed spool batch_id=%s reason=%s", batch.batch_id, exc)
                    spooler.mark_sent(batch.batch_id)
                    failed += 1
                    continue
                try:
                    response = client.post(self.ingest_url, content=body, headers=headers)
                except httpx.HTTPError:
                    spooler.mark_failed(batch.batch_id, batch.retry_count + 1)
                    failed += 1
                    continue

                if response.status_code == 200:
                    try:
                        IngestResponse.model_validate(response.json())
                    except Exception:
                        spooler.mark_failed(batch.batch_id, batch.retry_count + 1)
                        failed += 1
                        continue
                    spooler.mark_sent(batch.batch_id)
                    accepted += 1
                else:
                    spooler.mark_failed(batch.batch_id, batch.retry_count + 1)
                    failed += 1
        return accepted, failed

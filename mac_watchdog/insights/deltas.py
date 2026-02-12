from __future__ import annotations

import hashlib
import json
from typing import Any

HIGH_RISK_LEVELS = {"WARN", "HIGH"}


def _stable_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _risk_identity(event: dict[str, Any]) -> dict[str, Any]:
    source = str(event.get("source") or "")
    title = str(event.get("title") or "")
    details = event.get("details") if isinstance(event.get("details"), dict) else {}

    if source == "network":
        return {
            "source": source,
            "title": title,
            "ip": details.get("ip"),
            "port": details.get("port"),
            "process_name": details.get("process_name"),
        }
    if source == "process":
        return {
            "source": source,
            "title": title,
            "name": details.get("name"),
            "exe": details.get("exe"),
            "username": details.get("username"),
        }
    if source in {"login", "auth"}:
        samples = details.get("samples")
        sample = samples[0] if isinstance(samples, list) and samples else None
        return {"source": source, "title": title, "sample": sample}
    if source == "filewatch":
        return {
            "source": source,
            "title": title,
            "src_path": details.get("src_path"),
            "dest_path": details.get("dest_path"),
            "event_type": details.get("event_type"),
        }
    return {"source": source, "title": title}


def _to_delta_record(event: dict[str, Any]) -> dict[str, Any]:
    identity = _risk_identity(event)
    digest = hashlib.sha256(_stable_json(identity).encode("utf-8")).hexdigest()
    return {
        "fingerprint": digest,
        "title": str(event.get("title") or ""),
        "source": str(event.get("source") or "system"),
        "severity": str(event.get("severity") or "WARN"),
        "evidence": identity,
    }


def collect_risk_records(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for event in events:
        if str(event.get("severity") or "") not in HIGH_RISK_LEVELS:
            continue
        record = _to_delta_record(event)
        records[record["fingerprint"]] = record
    return records


def compute_new_resolved(
    today_events: list[dict[str, Any]],
    yesterday_events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    today_records = collect_risk_records(today_events)
    yesterday_records = collect_risk_records(yesterday_events)

    today_keys = set(today_records.keys())
    yesterday_keys = set(yesterday_records.keys())

    new_keys = today_keys - yesterday_keys
    resolved_keys = yesterday_keys - today_keys

    new_risks = [today_records[key] for key in sorted(new_keys)]
    resolved_risks = [yesterday_records[key] for key in sorted(resolved_keys)]
    return new_risks, resolved_risks, today_keys

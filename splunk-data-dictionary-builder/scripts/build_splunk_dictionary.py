#!/usr/bin/env python3
"""Build a lightweight Splunk data dictionary using the management API."""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Splunk data dictionary.")
    parser.add_argument("--base-url", default=os.getenv("SPLUNK_BASE_URL"), help="Splunk management URL, e.g. https://host:8089")
    parser.add_argument("--username", default=os.getenv("SPLUNK_USERNAME"))
    parser.add_argument("--password", default=os.getenv("SPLUNK_PASSWORD"))
    parser.add_argument("--token", default=os.getenv("SPLUNK_TOKEN"))
    parser.add_argument("--verify-ssl", action=argparse.BooleanOptionalAction, default=env_bool("SPLUNK_VERIFY_SSL", True))
    parser.add_argument("--index", action="append", dest="indexes", help="Index to inspect. May be repeated.")
    parser.add_argument("--earliest", default="-24h", help="Earliest time for sampling searches.")
    parser.add_argument("--sample-size", type=int, default=20, help="Events to sample per sourcetype.")
    parser.add_argument("--max-sourcetypes", type=int, default=50, help="Maximum sourcetypes to sample.")
    parser.add_argument("--output", default=os.getenv("SPLUNK_DICTIONARY_OUTPUT", "./out/splunk-data-dictionary.json"))
    return parser.parse_args()


class SplunkClient:
    def __init__(self, base_url: str, token: str | None, username: str | None, password: str | None, verify_ssl: bool) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.username = username
        self.password = password
        self.context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()

    def request(self, path: str, data: dict[str, str] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        encoded_data = None
        if data is not None:
            encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        request = urllib.request.Request(url, data=encoded_data)
        request.add_header("Accept", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        elif self.username and self.password:
            raw = f"{self.username}:{self.password}".encode("utf-8")
            request.add_header("Authorization", f"Basic {base64.b64encode(raw).decode('ascii')}")
        else:
            raise ValueError("Provide SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD.")
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Splunk API error {error.code} for {path}: {body}") from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"Splunk connection error for {path}: {error.reason}") from error

    def get(self, endpoint: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        query = {"output_mode": "json"}
        if params:
            query.update(params)
        return self.request(f"{endpoint}?{urllib.parse.urlencode(query)}")

    def search_oneshot(self, search: str, earliest: str) -> dict[str, Any]:
        return self.request(
            "/services/search/jobs/oneshot",
            {
                "output_mode": "json",
                "search": search,
                "earliest_time": earliest,
            },
        )


def entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return payload.get("entry", [])


def discover_indexes(client: SplunkClient, requested: list[str] | None, warnings: list[str]) -> list[str]:
    if requested:
        return requested
    try:
        payload = client.get("/services/data/indexes", {"count": "0"})
    except RuntimeError as error:
        warnings.append(str(error))
        return []
    names = []
    for entry in entries(payload):
        name = entry.get("name")
        content = entry.get("content", {})
        if name and not content.get("disabled", False):
            names.append(name)
    return sorted(set(names))


def discover_sourcetypes(client: SplunkClient, indexes: list[str], earliest: str, warnings: list[str]) -> list[dict[str, Any]]:
    if not indexes:
        return []
    index_filter = " OR ".join(f"index={index}" for index in indexes)
    search = f"| tstats count where ({index_filter}) by index, sourcetype"
    try:
        payload = client.search_oneshot(search, earliest)
    except RuntimeError as error:
        warnings.append(str(error))
        return []
    return payload.get("results", [])


def sample_fields(client: SplunkClient, index: str, sourcetype: str, earliest: str, sample_size: int, warnings: list[str]) -> dict[str, Any]:
    search = f'search index="{index}" sourcetype="{sourcetype}" | head {sample_size} | fields *'
    try:
        payload = client.search_oneshot(search, earliest)
    except RuntimeError as error:
        warnings.append(str(error))
        return {"index": index, "sourcetype": sourcetype, "fields": {}, "sample_count": 0}

    fields: dict[str, dict[str, Any]] = {}
    results = payload.get("results", [])
    for event in results:
        for key, value in event.items():
            if key.startswith("_") and key not in {"_time", "_raw"}:
                continue
            field = fields.setdefault(key, {"sample_values": [], "observed_types": []})
            values = value if isinstance(value, list) else [value]
            for item in values:
                kind = type(item).__name__
                if kind not in field["observed_types"]:
                    field["observed_types"].append(kind)
                text = str(item)
                if len(text) > 160:
                    text = text[:157] + "..."
                if text not in field["sample_values"] and len(field["sample_values"]) < 5:
                    field["sample_values"].append(text)
    return {"index": index, "sourcetype": sourcetype, "fields": fields, "sample_count": len(results)}


def main() -> int:
    args = parse_args()
    if not args.base_url:
        print("Missing --base-url or SPLUNK_BASE_URL.", file=sys.stderr)
        return 2

    warnings: list[str] = []
    client = SplunkClient(args.base_url, args.token, args.username, args.password, args.verify_ssl)

    indexes = discover_indexes(client, args.indexes, warnings)
    sourcetypes = discover_sourcetypes(client, indexes, args.earliest, warnings)
    samples = []
    for row in sourcetypes[: args.max_sourcetypes]:
        index = row.get("index")
        sourcetype = row.get("sourcetype")
        if index and sourcetype:
            samples.append(sample_fields(client, index, sourcetype, args.earliest, args.sample_size, warnings))

    output = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "splunk_base_url": args.base_url,
        "indexes": indexes,
        "sourcetypes": sourcetypes,
        "field_samples": samples,
        "warnings": warnings,
        "permission_notes": [
            "Missing indexes, sourcetypes, or fields may reflect role permissions rather than true absence."
        ],
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

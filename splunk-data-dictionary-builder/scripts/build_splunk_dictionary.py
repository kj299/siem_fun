#!/usr/bin/env python3
"""Build a lightweight Splunk data dictionary using the management API."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# fullmatch with no anchors: '$' would also match before a trailing newline.
# Hyphens are permitted in Splunk dataset IDs and cannot break out of an
# unquoted SPL token, so they are safe to allow -- but not in the leading
# position, where a bare '-' would read as a malformed option/negative value.
_SAFE_IDENT_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*")

_CREDENTIALS_MESSAGE = "Provide SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD."

_TRUTHY_STRINGS = {"1", "true", "yes", "on"}
_FALSY_STRINGS = {"0", "false", "no", "off", ""}


def parse_bool(value: str, default: bool) -> bool:
    """Parse a boolean-ish string with one canonical truthy/falsy set; unknown values return default."""
    normalized = value.strip().lower()
    if normalized in _TRUTHY_STRINGS:
        return True
    if normalized in _FALSY_STRINGS:
        return False
    return default


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return parse_bool(value, default)


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
    parser.add_argument("--cim-coverage", action=argparse.BooleanOptionalAction, default=True, help="Query live CIM data model coverage by sourcetype.")
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
            # main() validates credentials up front; this guards direct library use.
            raise ValueError(_CREDENTIALS_MESSAGE)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                raw = response.read()
            try:
                body = raw.decode("utf-8")
                return json.loads(body)
            except (UnicodeDecodeError, ValueError) as error:
                preview = raw.decode("utf-8", errors="replace")[:200]
                raise RuntimeError(
                    f"Splunk returned non-JSON for {path} (is this the management port, usually 8089?): {preview}"
                ) from error
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
                # Without count=0 the oneshot endpoint caps output at 100 rows
                # and silently truncates larger result sets.
                "count": "0",
            },
        )


def entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return payload.get("entry", [])


def spl_quote(value: str) -> str:
    """Quote a value for safe interpolation into an SPL search string."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _safe_spl_ident(value: str, context: str, warnings: list[str]) -> str | None:
    """Return value if it is safe as an unquoted SPL data-model identifier, else warn and return None."""
    if _SAFE_IDENT_RE.fullmatch(value):
        return value
    warnings.append(f"Skipping unsafe SPL identifier for {context}: {value!r}")
    return None


def _redact_url_credentials(url: str) -> str:
    """Strip userinfo from a URL so credentials are never written to the output file."""
    try:
        parsed = urllib.parse.urlparse(url)
        if not (parsed.username or parsed.password):
            return url
        host = parsed.hostname or ""
        if ":" in host:
            # urlparse strips the brackets from IPv6 literals; restore them so
            # the rebuilt netloc stays a valid URL.
            host = f"[{host}]"
        netloc = f"{host}:{parsed.port}" if parsed.port else host
        return urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        # Redaction must fail closed: an unparseable URL may still carry
        # credentials, so never fall back to the original string.
        return "<redacted-unparseable-url>"


def _content_flag(value: Any) -> bool:
    """Normalize a REST content boolean that may arrive as bool, int, or the strings '0'/'1'/'true'/'false'."""
    if isinstance(value, str):
        return parse_bool(value, False)
    return bool(value)


def _collect_search_messages(payload: dict[str, Any], context: str, warnings: list[str]) -> None:
    """Surface ERROR/FATAL messages that Splunk returns inside an HTTP 200 search response."""
    for message in payload.get("messages", []):
        if isinstance(message, dict) and message.get("type") in {"ERROR", "FATAL"}:
            warnings.append(f"Splunk search message for {context}: {message.get('text', 'unknown error')}")


def _run_search(client: SplunkClient, search: str, earliest: str, context: str, warnings: list[str]) -> dict[str, Any] | None:
    """Run a oneshot search, recording failures and in-band error messages; None on failure."""
    try:
        payload = client.search_oneshot(search, earliest)
    except RuntimeError as error:
        warnings.append(str(error))
        return None
    _collect_search_messages(payload, context, warnings)
    return payload


# Sourcetype prefixes produced by common Splunkbase add-ons, mapped to the CIM
# data models they are tagged for. These are offline fallback hints only;
# cim_coverage (queried from the live instance) is the ground truth and also
# captures mappings the prefixes cannot express, such as the on-host Windows
# Defender path (XmlWinEventLog matched by source rather than sourcetype).
# Every key here must be documented in cim-vendor-alignment.md; the validator
# enforces that.
CIM_SOURCETYPE_HINTS: dict[str, list[str]] = {
    "zscalernss-web": ["Web"],
    "zscalernss-fw": ["Network_Traffic"],
    "zscalernss-dns": ["Network_Resolution"],
    "zscalerlss-zpa-app": ["Network_Sessions", "Web"],
    "akamaisiem": ["Web", "Intrusion_Detection"],
    "ms:defender:atp:alerts": ["Alerts", "Malware", "Endpoint"],
    "crowdstrike:events:sensor": ["Endpoint"],
    "cloudflare:json": ["Web", "Intrusion_Detection", "Network_Resolution"],
    "proofpoint_tap_siem": ["Email", "Malware"],
    "pps_messagelog": ["Email"],
    "bluecoat:proxysg:access": ["Web"],
    "squid:access": ["Web"],
    "cisco:asa": ["Network_Traffic", "Network_Sessions", "Authentication"],
    "cisco:estreamer:data": ["Intrusion_Detection", "Network_Traffic"],
    "cisco:umbrella:dns": ["Network_Resolution"],
    "cisco:ise:syslog": ["Authentication", "Network_Sessions"],
    "pan:traffic": ["Network_Traffic"],
    "pan:threat": ["Intrusion_Detection", "Malware", "Web"],
    "pan:globalprotect": ["Authentication", "Network_Sessions"],
}


def cim_hints_for_sourcetype(sourcetype: str) -> list[str]:
    key = sourcetype.lower()
    for prefix, models in CIM_SOURCETYPE_HINTS.items():
        # Match the exact sourcetype or a separated variant (pan:threat:custom,
        # bluecoat:proxysg:access:proxy) but not accidental superstrings such
        # as zscalernss-weblogging.
        if key == prefix or (key.startswith(prefix) and key[len(prefix)] in ":-_"):
            return models
    return []


# Parents that mark a dataset as a root dataset in a data model definition.
BASE_DATASET_PARENTS = {"BaseEvent", "BaseTransaction", "BaseSearch"}


def parse_json_attribute(value: Any, warnings: list[str] | None = None, context: str = "") -> dict[str, Any]:
    """Normalize a Splunk REST content attribute that may be a JSON string or a dict."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    if isinstance(value, dict):
        return value
    if value is not None and warnings is not None:
        warnings.append(f"Expected a JSON object for {context!r}, got {type(value).__name__!r}; skipping")
    return {}


def discover_datamodels(client: SplunkClient, warnings: list[str]) -> list[dict[str, Any]]:
    try:
        payload = client.get("/services/datamodel/model", {"count": "0"})
    except RuntimeError as error:
        warnings.append(str(error))
        return []
    models = []
    for entry in entries(payload):
        name = entry.get("name")
        if not name:
            continue
        content = entry.get("content", {})
        acceleration = parse_json_attribute(content.get("acceleration"), warnings=warnings, context="acceleration")
        # The model definition (objects, fields) is carried in the
        # "description" content attribute as a JSON document.
        definition = parse_json_attribute(content.get("description"), warnings=warnings, context="description")
        root_datasets = [
            obj["objectName"]
            for obj in definition.get("objects", [])
            if isinstance(obj, dict)
            and obj.get("objectName")
            and obj.get("parentName") in BASE_DATASET_PARENTS
        ]
        models.append(
            {
                "name": name,
                "accelerated": _content_flag(acceleration.get("enabled", False)),
                "root_datasets": root_datasets,
            }
        )
    return sorted(models, key=lambda model: model["name"])


def discover_cim_coverage(client: SplunkClient, datamodels: list[dict[str, Any]], earliest: str, warnings: list[str]) -> list[dict[str, Any]]:
    """Query which sourcetypes actually feed each data model root dataset."""
    coverage = []
    for model in datamodels:
        summaries = "summariesonly=true " if model["accelerated"] else ""
        for root in model["root_datasets"]:
            model_name = _safe_spl_ident(model["name"], "data model name", warnings)
            root_name = _safe_spl_ident(root, "root dataset", warnings)
            if model_name is None or root_name is None:
                continue
            search = f"| tstats {summaries}count from datamodel={model_name}.{root_name} by sourcetype"
            payload = _run_search(client, search, earliest, f"cim_coverage {model_name}.{root_name}", warnings)
            if payload is None:
                continue
            sourcetypes: dict[str, int] = {}
            for row in payload.get("results", []):
                name = row.get("sourcetype")
                if not name:
                    continue
                try:
                    sourcetypes[name] = int(row.get("count", 0))
                except (TypeError, ValueError):
                    sourcetypes[name] = 0
            coverage.append(
                {
                    "datamodel": model["name"],
                    "root_dataset": root,
                    "sourcetypes": sourcetypes,
                }
            )
    return coverage


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
        if name and not _content_flag(content.get("disabled", False)):
            names.append(name)
    return sorted(set(names))


def discover_sourcetypes(client: SplunkClient, indexes: list[str], earliest: str, warnings: list[str]) -> list[dict[str, Any]]:
    if not indexes:
        return []
    index_filter = " OR ".join(f"index={spl_quote(index)}" for index in indexes)
    # Sort by volume so the full inventory is ordered and the
    # [:max_sourcetypes] sampling slice takes the highest-volume sourcetypes
    # rather than tstats group-by order.
    search = f"| tstats count where ({index_filter}) by index, sourcetype | sort 0 - count"
    payload = _run_search(client, search, earliest, "sourcetype discovery", warnings)
    if payload is None:
        return []
    return payload.get("results", [])


def sample_fields(client: SplunkClient, index: str, sourcetype: str, earliest: str, sample_size: int, warnings: list[str]) -> dict[str, Any]:
    search = f"search index={spl_quote(index)} sourcetype={spl_quote(sourcetype)} | head {sample_size} | fields *"
    payload = _run_search(client, search, earliest, f"field sampling {index}/{sourcetype}", warnings)
    if payload is None:
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
    if not args.token and not (args.username and args.password):
        print(_CREDENTIALS_MESSAGE, file=sys.stderr)
        return 2
    if args.sample_size < 1:
        print("--sample-size must be at least 1.", file=sys.stderr)
        return 2
    if args.max_sourcetypes < 0:
        print("--max-sourcetypes must not be negative.", file=sys.stderr)
        return 2

    warnings: list[str] = []
    client = SplunkClient(args.base_url, args.token, args.username, args.password, args.verify_ssl)

    indexes = discover_indexes(client, args.indexes, warnings)
    sourcetypes = discover_sourcetypes(client, indexes, args.earliest, warnings)
    datamodels = discover_datamodels(client, warnings)
    cim_coverage = discover_cim_coverage(client, datamodels, args.earliest, warnings) if args.cim_coverage else []
    samples = []
    for row in sourcetypes:
        sourcetype = row.get("sourcetype")
        if sourcetype:
            hints = cim_hints_for_sourcetype(sourcetype)
            if hints:
                row["cim_datamodel_hints"] = hints
    for row in sourcetypes[: args.max_sourcetypes]:
        index = row.get("index")
        sourcetype = row.get("sourcetype")
        if index and sourcetype:
            samples.append(sample_fields(client, index, sourcetype, args.earliest, args.sample_size, warnings))

    output = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "splunk_base_url": _redact_url_credentials(args.base_url),
        "indexes": indexes,
        "sourcetypes": sourcetypes,
        "cim_datamodels": datamodels,
        "cim_coverage": cim_coverage,
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

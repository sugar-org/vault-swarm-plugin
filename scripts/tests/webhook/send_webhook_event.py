#!/usr/bin/env python3
"""Send a signed webhook event to the smoke-test plugin listener."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send signed webhook event")
    parser.add_argument("--config", required=True)
    parser.add_argument("--payload-format", choices=("vault", "normalized"), required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--action", default="update")
    parser.add_argument("--secret-name", required=True)
    parser.add_argument("--secret-path", default="")
    parser.add_argument("--app-name", default="")
    parser.add_argument("--event-id", default="smoke-webhook-event")
    return parser.parse_args()


def vault_payload(args: argparse.Namespace) -> dict[str, object]:
    return {
        "resource_id": args.secret_name,
        "resource_name": args.secret_path,
        "event_id": args.event_id,
        "event_action": args.action,
        "event_description": f"{args.action} secret",
        "event_source": "hashicorp.secrets.secret",
        "event_version": "1",
        "event_payload": {
            "app_name": args.app_name,
            "name": args.secret_name,
            "type": "static",
        },
    }


def normalized_payload(args: argparse.Namespace) -> dict[str, object]:
    return {
        "provider": args.provider,
        "action": args.action,
        "secret_name": args.secret_name,
        "secret_path": args.secret_path,
        "event_id": args.event_id,
    }


def main() -> None:
    args = parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))

    payload = vault_payload(args) if args.payload_format == "vault" else normalized_payload(args)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(config["secret"].encode("utf-8"), body, hashlib.sha256).hexdigest()

    webhook_request = request.Request(
        config["url"],
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-HCP-Webhook-Signature": signature,
        },
    )

    try:
        with request.urlopen(webhook_request, timeout=30) as response:
            print(f"webhook response: {response.status}")
            if response.status < 200 or response.status > 299:
                sys.exit(f"unexpected webhook status: {response.status}")
    except HTTPError as err:
        sys.exit(f"webhook request failed: HTTP {err.code} {err.read().decode('utf-8', errors='replace')}")
    except URLError as err:
        sys.exit(f"webhook request failed: {err}")


if __name__ == "__main__":
    main()

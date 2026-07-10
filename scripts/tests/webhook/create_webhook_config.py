#!/usr/bin/env python3
"""Create a webhook config through the local HCP-style UI with Playwright."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create webhook config with Playwright")
    parser.add_argument("--ui-url", required=True)
    parser.add_argument("--webhook-url", required=True)
    parser.add_argument("--webhook-path", default="/webhook")
    parser.add_argument("--webhook-secret", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--name", default="swarm-external-secrets-smoke")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()

        page.goto(f"{args.ui_url.rstrip('/')}/login")
        page.get_by_test_id("email").fill("ci@example.com")
        page.get_by_test_id("password").fill("password")
        page.get_by_test_id("login-submit").click()

        page.get_by_test_id("webhook-name").fill(args.name)
        page.get_by_test_id("webhook-url").fill(args.webhook_url)
        page.get_by_test_id("webhook-path").fill(args.webhook_path)
        page.get_by_test_id("webhook-token").fill(args.webhook_secret)
        page.get_by_test_id("event-secret-create").check()
        page.get_by_test_id("event-secret-update").check()
        page.get_by_test_id("event-secret-rotate").check()
        page.get_by_test_id("webhook-enabled").check()
        page.get_by_test_id("webhook-submit").click()
        expect(page.get_by_test_id("webhook-created")).to_be_visible()

        browser.close()

    config = {
        "name": args.name,
        "url": args.webhook_url,
        "path": args.webhook_path,
        "secret": args.webhook_secret,
        "events": [
            "hashicorp.secrets.secret.create",
            "hashicorp.secrets.secret.update",
            "hashicorp.secrets.secret.rotate",
        ],
        "enabled": True,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"wrote webhook config to {output}")


if __name__ == "__main__":
    main()

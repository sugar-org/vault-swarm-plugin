#!/usr/bin/env python3
"""Small local HCP-style webhook UI used by smoke tests."""

from __future__ import annotations

import argparse
import html
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs


class WebhookUIHandler(BaseHTTPRequestHandler):
    server_version = "MockHCPWebhookUI/1.0"

    def do_GET(self) -> None:
        if self.path in {"/", "/login"}:
            self._write_html(self._login_page())
            return
        if self.path == "/webhooks/new":
            self._write_html(self._webhook_form())
            return
        if self.path == "/health":
            self._write_json({"status": "ok"})
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        form = self._read_form()
        if self.path == "/login":
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/webhooks/new")
            self.end_headers()
            return
        if self.path == "/webhooks":
            config = {
                "name": form.get("name", ["smoke-webhook"])[0],
                "url": form.get("url", [""])[0],
                "path": form.get("path", ["/webhook"])[0],
                "secret": form.get("secret", [""])[0],
                "events": form.get("events", []),
                "enabled": "enabled" in form,
            }
            output_path = Path(self.server.output_path)  # type: ignore[attr-defined]
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
            self._write_html(self._success_page(config))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _read_form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        return parse_qs(body)

    def _write_html(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _write_json(self, body: dict[str, str]) -> None:
        payload = (json.dumps(body) + "\n").encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    @staticmethod
    def _login_page() -> str:
        return """<!doctype html>
<html>
  <body>
    <h1>HCP Login</h1>
    <form method="post" action="/login">
      <label>Email <input data-testid="email" name="email" value="ci@example.com"></label>
      <label>Password <input data-testid="password" name="password" type="password" value="password"></label>
      <button data-testid="login-submit" type="submit">Log in</button>
    </form>
  </body>
</html>
"""

    @staticmethod
    def _webhook_form() -> str:
        return """<!doctype html>
<html>
  <body>
    <h1>Create webhook</h1>
    <form method="post" action="/webhooks">
      <label>Name <input data-testid="webhook-name" name="name"></label>
      <label>Webhook URL <input data-testid="webhook-url" name="url"></label>
      <label>Path <input data-testid="webhook-path" name="path"></label>
      <label>Token <input data-testid="webhook-token" name="secret" type="password"></label>
      <label><input data-testid="event-secret-create" type="checkbox" name="events" value="hashicorp.secrets.secret.create"> Secret create</label>
      <label><input data-testid="event-secret-update" type="checkbox" name="events" value="hashicorp.secrets.secret.update"> Secret update</label>
      <label><input data-testid="event-secret-rotate" type="checkbox" name="events" value="hashicorp.secrets.secret.rotate"> Secret rotate</label>
      <label><input data-testid="webhook-enabled" type="checkbox" name="enabled" value="true"> Enable webhook</label>
      <button data-testid="webhook-submit" type="submit">Create webhook</button>
    </form>
  </body>
</html>
"""

    @staticmethod
    def _success_page(config: dict[str, object]) -> str:
        name = html.escape(str(config["name"]))
        return f"""<!doctype html>
<html>
  <body>
    <h1 data-testid="webhook-created">Webhook created</h1>
    <p>Created webhook: {name}</p>
  </body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local HCP-style webhook UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), WebhookUIHandler)
    server.output_path = args.output
    print(f"mock HCP webhook UI listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

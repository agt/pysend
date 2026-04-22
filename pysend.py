#!/usr/bin/env python3
"""pysend — bulk-email sender via Gmail API with OAuth 2.0 mail-merge."""

import argparse
import base64
import csv
import json
import os
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from jinja2 import Environment, StrictUndefined, TemplateSyntaxError, UndefinedError
    from google.auth.exceptions import RefreshError
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError as exc:
    print(f"Missing dependency: {exc}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(1)


SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
DEFAULT_TOKEN_FILE = Path.home() / ".config" / "pysend" / "tokens.json"
REDIRECT_URI = "http://localhost:8080"


# ---------------------------------------------------------------------------
# OAuth2 helpers
# ---------------------------------------------------------------------------

def _get_client_config(args):
    """Return an OAuth2 client config dict from file, CLI flags, or env vars."""
    if args.credentials:
        path = Path(args.credentials)
        if not path.exists():
            _die(f"Credentials file not found: {args.credentials}")
        data = json.loads(path.read_text())
        # Accept Google's standard credentials.json format (installed / web key)
        if "installed" in data or "web" in data:
            return data
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")
    else:
        client_id = args.client_id or os.environ.get("GMAIL_CLIENT_ID")
        client_secret = args.client_secret or os.environ.get("GMAIL_CLIENT_SECRET")

    if not client_id or not client_secret:
        _die(
            "Gmail OAuth2 credentials are required.\n"
            "Supply them via one of:\n"
            "  --credentials credentials.json\n"
            "  --client-id / --client-secret flags\n"
            "  GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET environment variables\n\n"
            "To create credentials:\n"
            "  1. Go to https://console.cloud.google.com/\n"
            "  2. APIs & Services > Credentials > Create Credentials > OAuth client ID\n"
            "  3. Application type: Desktop app\n"
            "  4. Enable the Gmail API for your project."
        )

    return {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": [REDIRECT_URI],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }


def _save_credentials(creds, token_file: Path):
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(
        json.dumps({
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": list(creds.scopes or []),
            "expiry": creds.expiry.isoformat() if creds.expiry else None,
        })
    )
    token_file.chmod(0o600)


def authorize(args):
    """Return valid Gmail OAuth2 credentials, prompting the user if needed."""
    token_file = Path(args.token_file)
    creds = None

    if not args.reauth and token_file.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_file), SCOPES)
        except Exception:
            pass

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _save_credentials(creds, token_file)
            return creds
        except RefreshError:
            creds = None

    if creds and creds.valid:
        return creds

    # Full interactive OAuth flow
    client_config = _get_client_config(args)
    flow = Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _state = flow.authorization_url(access_type="offline", prompt="consent")

    print()
    print("=" * 60)
    print("  Gmail Authorization Required")
    print("=" * 60)
    print()
    print("Step 1 — Open this URL in your browser:")
    print()
    print(f"  {auth_url}")
    print()
    print("Step 2 — Sign in and grant access.")
    print()
    print("Step 3 — Your browser will redirect to a localhost URL that")
    print("  fails to load. Copy that URL from the address bar and")
    print("  paste it below (or paste just the 'code=...' value).")
    print()

    pasted = input("Paste redirect URL or auth code: ").strip()
    if not pasted:
        _die("No input provided.")

    if pasted.startswith("http"):
        params = parse_qs(urlparse(pasted).query)
        code = (params.get("code") or [None])[0]
        if not code:
            _die("No 'code' parameter found in the pasted URL.")
    else:
        code = pasted

    try:
        flow.fetch_token(code=code)
    except Exception as exc:
        _die(f"Token exchange failed: {exc}")

    creds = flow.credentials
    _save_credentials(creds, token_file)
    print(f"Credentials saved to {token_file}")
    return creds


# ---------------------------------------------------------------------------
# Mail-merge helpers
# ---------------------------------------------------------------------------

_jinja_env = Environment(undefined=StrictUndefined, autoescape=False)


def _render(template_str, context, label):
    """Render a Jinja2 template string; exit with a clear error on failure."""
    try:
        return _jinja_env.from_string(template_str).render(**context)
    except UndefinedError as exc:
        _die(f"Undefined variable in {label}: {exc}")
    except TemplateSyntaxError as exc:
        _die(f"Template syntax error in {label}: {exc}")


def _build_message(row: dict, args, body_template: str):
    """
    Return (MIMEMultipart, bcc_str_or_None) for one CSV row.

    CSV columns named 'to', 'cc', 'bcc' take precedence over CLI templates.
    CLI --to/--cc/--bcc values are themselves Jinja2 templates rendered with
    the row's data.
    """
    ctx = dict(row)

    def resolve(field, cli_val):
        # CSV column wins; fall back to rendered CLI template
        csv_val = ctx.get(field, "").strip()
        if csv_val:
            return csv_val
        if cli_val:
            return _render(cli_val, ctx, f"--{field}")
        return ""

    to_addr  = resolve("to",  args.to)
    cc_addr  = resolve("cc",  args.cc)
    bcc_addr = resolve("bcc", args.bcc)

    if not to_addr and not cc_addr and not bcc_addr:
        raise ValueError(
            "No recipient address for this row. "
            "Use --to/--cc/--bcc or add a 'to'/'cc'/'bcc' column in the CSV."
        )

    subject   = _render(args.subject, ctx, "--subject")
    body_html = _render(body_template, ctx, "--body")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    if to_addr:
        msg["To"] = to_addr
    if cc_addr:
        msg["Cc"] = cc_addr
    # Include Bcc header in the raw message; Gmail strips it before delivery
    # but uses it to route the message to the BCC recipient(s).
    if bcc_addr:
        msg["Bcc"] = bcc_addr
    if args.sender:
        msg["From"] = args.sender

    msg.attach(MIMEText(body_html, "html", "utf-8"))
    return msg, bcc_addr or None


def _send_via_api(service, msg):
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return service.users().messages().send(userId="me", body={"raw": raw}).execute()


def _preview(index, total, msg, bcc):
    print(f"\n{'─' * 50}")
    print(f"  Email {index}/{total}")
    print(f"{'─' * 50}")
    print(f"  To:      {msg.get('To') or '—'}")
    if msg.get("Cc"):
        print(f"  Cc:      {msg['Cc']}")
    if bcc:
        print(f"  Bcc:     {bcc}")
    print(f"  Subject: {msg['Subject']}")
    payload = msg.get_payload()
    part = payload[0] if isinstance(payload, list) else msg
    # get_payload(decode=True) handles base64/quoted-printable transparently
    raw_bytes = part.get_payload(decode=True)
    body_text = raw_bytes.decode(part.get_content_charset("utf-8") or "utf-8") if raw_bytes else ""
    snippet = body_text[:200].replace("\n", " ").strip()
    ellipsis = "…" if len(body_text) > 200 else ""
    print(f"  Body:    {snippet}{ellipsis}")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _die(message: str):
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(1)


def _load_csv(path: str):
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
    except FileNotFoundError:
        _die(f"CSV file not found: {path}")
    if not rows:
        _die(f"CSV file is empty: {path}")
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser():
    parser = argparse.ArgumentParser(
        prog="pysend",
        description="Send bulk email via Gmail with OAuth2 mail-merge.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MAIL MERGE
  All --to/--cc/--bcc/--subject values and the HTML body file are Jinja2
  templates rendered once per CSV row.  CSV columns named 'to', 'cc', or
  'bcc' take precedence over the corresponding CLI flag for that row.

  Example CSV (list.csv):
    email,first_name,last_name
    alice@example.com,Alice,Smith
    bob@example.com,Bob,Jones

  Example invocation:
    pysend \\
      --to "{{ email }}" \\
      --subject "Hello {{ first_name }}!" \\
      --body template.html \\
      --data list.csv

  Example template.html:
    <p>Hi {{ first_name }} {{ last_name }},</p>
    <p>Welcome!</p>

CREDENTIALS
  Create OAuth2 credentials at https://console.cloud.google.com/ :
    APIs & Services > Credentials > Create Credentials > OAuth client ID
    Application type: Desktop app
  Then enable the Gmail API for your project.

  Supply credentials via (highest priority first):
    --credentials credentials.json   (Google-format file)
    --client-id / --client-secret    (CLI flags)
    GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET  (environment variables)

RATE LIMITS
  Free Gmail: ~500 messages/day.  Google Workspace: up to 10,000/day.
  Use --delay to throttle sends (default: 1.0 s between messages).
""",
    )

    r = parser.add_argument_group("recipients (at least one required)")
    r.add_argument("--to",  metavar="TEMPLATE", help="To: header (Jinja2 template)")
    r.add_argument("--cc",  metavar="TEMPLATE", help="Cc: header (Jinja2 template)")
    r.add_argument("--bcc", metavar="TEMPLATE", help="Bcc: header (Jinja2 template)")

    m = parser.add_argument_group("message")
    m.add_argument("--subject", required=True, metavar="TEMPLATE",
                   help="Subject line (Jinja2 template)")
    m.add_argument("--body", required=True, metavar="FILE",
                   help="HTML file for message body (Jinja2 template)")
    m.add_argument("--from", dest="sender", metavar="ADDRESS",
                   help="From address / display name (defaults to authenticated account)")

    d = parser.add_argument_group("data")
    d.add_argument("--data", required=True, metavar="FILE",
                   help="CSV file supplying mail-merge variables")

    a = parser.add_argument_group("authentication")
    a.add_argument("--credentials", metavar="FILE",
                   help="Google OAuth2 credentials JSON file")
    a.add_argument("--client-id", metavar="ID",
                   help="OAuth2 client ID (or set GMAIL_CLIENT_ID)")
    a.add_argument("--client-secret", metavar="SECRET",
                   help="OAuth2 client secret (or set GMAIL_CLIENT_SECRET)")
    a.add_argument("--token-file", metavar="FILE", default=str(DEFAULT_TOKEN_FILE),
                   help=f"Token cache path (default: {DEFAULT_TOKEN_FILE})")
    a.add_argument("--reauth", action="store_true",
                   help="Ignore cached tokens and re-authenticate")

    s = parser.add_argument_group("send options")
    s.add_argument("--delay", type=float, default=1.0, metavar="SECONDS",
                   help="Pause between emails in seconds (default: 1.0)")
    s.add_argument("--dry-run", action="store_true",
                   help="Render and preview all emails without sending")
    s.add_argument("--yes", "-y", action="store_true",
                   help="Skip the send-confirmation prompt")

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if not args.to and not args.cc and not args.bcc:
        parser.error(
            "At least one of --to, --cc, or --bcc is required "
            "(unless every CSV row has its own to/cc/bcc column)."
        )

    body_path = Path(args.body)
    if not body_path.exists():
        _die(f"Body file not found: {args.body}")
    body_template = body_path.read_text(encoding="utf-8")

    rows = _load_csv(args.data)

    # Build every message up-front so template errors surface before auth/send.
    print(f"Rendering {len(rows)} message(s)…")
    messages = []
    for i, row in enumerate(rows, 1):
        try:
            msg, bcc = _build_message(row, args, body_template)
            messages.append((msg, bcc))
        except ValueError as exc:
            _die(f"Row {i}: {exc}")

    if args.dry_run:
        for i, (msg, bcc) in enumerate(messages, 1):
            _preview(i, len(messages), msg, bcc)
        print(f"\n[dry-run] {len(messages)} email(s) rendered. Remove --dry-run to send.")
        return

    # Show a preview and ask for confirmation before authenticating.
    print(f"\nReady to send {len(messages)} email(s).")
    if not args.yes:
        _preview(1, len(messages), messages[0][0], messages[0][1])
        if len(messages) > 1:
            print(f"\n  … and {len(messages) - 1} more.")
        answer = input("\nSend all emails? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return

    print("\nAuthenticating with Gmail…")
    creds = authorize(args)
    service = build("gmail", "v1", credentials=creds)

    sent = failed = 0
    for i, (msg, bcc) in enumerate(messages, 1):
        recipient = msg.get("To") or msg.get("Cc") or bcc or "?"
        try:
            _send_via_api(service, msg)
            print(f"[{i}/{len(messages)}] Sent  → {recipient}")
            sent += 1
        except HttpError as exc:
            print(f"[{i}/{len(messages)}] FAIL  → {recipient}: {exc}", file=sys.stderr)
            failed += 1

        if i < len(messages) and args.delay > 0:
            time.sleep(args.delay)

    print(f"\nDone — {sent} sent, {failed} failed.")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()

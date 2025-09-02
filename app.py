import os
import io
import json
import requests
import logging
from flask import Flask, request, jsonify
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

# ----- Dest (your Jira: clictestdummy) -----
DEST_SITE   = os.getenv("DEST_SITE")        # e.g. "clictestdummy.atlassian.net" (NO scheme)
DEST_EMAIL  = os.getenv("DEST_EMAIL")       # your Jira email (destination)
DEST_TOKEN  = os.getenv("DEST_TOKEN")       # your API token (destination)
DEST_PROJECT= os.getenv("DEST_PROJECT")     # e.g. "KAN"
CF_LATCHA_ID= os.getenv("CF_LATCHA_ID")     # e.g. "customfield_12345" (optional)
CF_LATCHA_CREATED = os.getenv("CF_LATCHA_CREATED")  # optional

# ----- Source (client Jira: clictell) -----
SRC_SITE    = os.getenv("SRC_SITE")         # e.g. "clictell.atlassian.net" (NO scheme)
SRC_EMAIL   = os.getenv("SRC_EMAIL")        # your Jira email (source side)
SRC_TOKEN   = os.getenv("SRC_TOKEN")        # your API token (source side)

# ----- Security -----
# You previously used the secret's literal text as the *env var name*. Keep that,
# but also allow a normal SHARED_SECRET env var as a fallback.
SHARED_SECRET = os.getenv("LatchaSync_2025_Secret9876") or os.getenv("SHARED_SECRET")
TIMEOUT = 40

def _host(h: str) -> str:
    """Ensure we only have the host (no scheme)."""
    if not h:
        return ""
    return h.replace("https://", "").replace("http://", "").strip().strip("/")

DEST_SITE = _host(DEST_SITE)
SRC_SITE  = _host(SRC_SITE)

def dest_auth():
    return HTTPBasicAuth(DEST_EMAIL, DEST_TOKEN)

def src_auth():
    return HTTPBasicAuth(SRC_EMAIL, SRC_TOKEN)

def dest_url(path: str) -> str:
    return f"https://{DEST_SITE}{path}"

def src_url(path: str) -> str:
    return f"https://{SRC_SITE}{path}"

def jql_escape(val: str) -> str:
    return (val or "").replace('"', '\\"')

def find_existing_issue_by_latcha_id(latcha_key: str):
    """Optional de-dup: if CF_LATCHA_ID is set, search by it; else search by summary prefix."""
    try:
        if CF_LATCHA_ID:
            jql = f'project = "{DEST_PROJECT}" AND "{CF_LATCHA_ID}" ~ "{jql_escape(latcha_key)}"'
        else:
            jql = f'project = "{DEST_PROJECT}" AND summary ~ "[Latcha {jql_escape(latcha_key)}]"'
        r = requests.get(
            dest_url("/rest/api/3/search"),
            params={"jql": jql, "maxResults": 1, "fields": "key"},
            auth=dest_auth(), timeout=TIMEOUT
        )
        r.raise_for_status()
        issues = r.json().get("issues", []) or []
        return issues[0]["key"] if issues else None
    except Exception:
        return None

def _make_adf_from_text(plain_text: str):
    """
    Convert plain text (with newlines) into valid ADF.
    Each newline becomes a 'hardBreak'.
    """
    if not plain_text:
        plain_text = "No description provided."

    # Split into lines, preserve line breaks
    content = []
    for idx, line in enumerate(plain_text.splitlines()):
        if idx > 0:  # insert a line break before new line
            content.append({"type": "hardBreak"})
        if line:  # non-empty line
            content.append({"type": "text", "text": line})

    if not content:  # handle edge case
        content = [{"type": "text", "text": ""}]

    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": content
            }
        ]
    }


def normalize_description_to_adf(description: str):
    """
    Convert plain text (with newlines, tabs, etc.) into valid Jira ADF description.
    Handles multiline safely using paragraphs + hardBreak.
    """
    if not description or description.strip() == "":
        description = "No description provided."

    paragraphs = []
    for block in description.split("\n"):
        if block.strip() == "":
            # preserve blank lines as empty paragraphs
            paragraphs.append({
                "type": "paragraph",
                "content": []
            })
        else:
            paragraphs.append({
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": block
                    }
                ]
            })

    return {
        "type": "doc",
        "version": 1,
        "content": paragraphs
    }


def create_dest_issue(latcha_key, summary, description, due_date, latcha_created, priority=None, attachments=None):
    # Normalize description into ADF
    adf_description = normalize_description_to_adf(description, latcha_key)

    fields = {
        "project": {"key": DEST_PROJECT},
        "issuetype": {"name": "Task"},
        "summary": f"[Latcha {latcha_key}] {summary or '(no summary)'}",
        "description": adf_description,
        "labels": ["LatchaSync"]
    }

    if due_date:
        fields["duedate"] = due_date
    if CF_LATCHA_ID:
        fields[CF_LATCHA_ID] = latcha_key
    if CF_LATCHA_CREATED and latcha_created:
        fields[CF_LATCHA_CREATED] = latcha_created
    if priority:
        pname = get_priority_name(priority)
        if pname:
            fields["priority"] = {"name": pname}

    # Debugging: log the JSON before sending
    logging.debug("Payload to Jira: %s", json.dumps({"fields": fields}, indent=2))

    r = requests.post(
        dest_url("/rest/api/3/issue"),
        auth=dest_auth(),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={"fields": fields},
        timeout=TIMEOUT
    )
    r.raise_for_status()
    new_key = r.json()["key"]

    # Handle attachments
    if attachments:
        try:
            copy_attachments_to_dest(new_key, attachments)
        except Exception as e:
            logging.warning("Attachments failed for %s: %s", new_key, e)

    return new_key

def fetch_attachments_from_source(latcha_key):
    """Fetch attachment metadata from clictell."""
    r = requests.get(
        src_url(f"/rest/api/3/issue/{latcha_key}"),
        params={"fields": "attachment"},
        auth=src_auth(), timeout=TIMEOUT
    )
    r.raise_for_status()
    fields = r.json().get("fields", {}) or {}
    atts = fields.get("attachment") or []
    # Jira Cloud provides absolute content URLs already.
    return [{"filename": a.get("filename"), "content": a.get("content")} for a in atts]

def copy_attachments_to_dest(new_issue_key, attachments):
    """Download each attachment from clictell and upload to clictestdummy."""
    for a in attachments:
        content_url = a.get("content")
        filename = a.get("filename") or "file"
        if not content_url:
            continue

        # Download from source
        with requests.get(content_url, auth=src_auth(), stream=True, timeout=TIMEOUT) as dl:
            dl.raise_for_status()
            file_bytes = io.BytesIO(dl.content)

        # Upload to destination
        up = requests.post(
            dest_url(f"/rest/api/3/issue/{new_issue_key}/attachments"),
            auth=dest_auth(),
            headers={"X-Atlassian-Token": "no-check"},
            files={"file": (filename, file_bytes)},
            timeout=TIMEOUT
        )
        if up.status_code not in (200, 201):
            # Log but don't fail the whole request
            logging.warning("[warn] upload failed %s: %s %s", filename, up.status_code, up.text)

def _get_shared_secret_from_request(req) -> str:
    """Pull secret from header or query param; header name tolerant to case."""
    # Header (preferred)
    for k, v in req.headers.items():
        if k.lower() == "x-shared-secret":
            return v
    # Fallback: query param ?secret=...
    return req.args.get("secret")

@app.route("/webhook", methods=["POST", "GET"])
def webhook():
    try:
        # Debug logs
        logging.debug("Headers: %s", dict(request.headers))
        logging.debug("Raw body: %s", request.get_data(as_text=True))

        # Basic shared-secret gate (only if configured)
        if SHARED_SECRET:
            incoming_secret = _get_shared_secret_from_request(request)
            if incoming_secret != SHARED_SECRET:
                logging.warning("Forbidden: bad shared secret (got %r)", incoming_secret)
                return jsonify({"error": "forbidden"}), 403

        # Be tolerant: try Flask JSON first, then manual parse
        data = request.get_json(silent=True)
        if data is None:
            raw = request.get_data(as_text=True) or ""
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                logging.error("Invalid JSON body")
                return jsonify({"error": "Invalid JSON"}), 400

        logging.debug("Parsed JSON: %s", data)

        # Expect minimal payload from Automation
        latcha_key = data.get("key")
        summary = data.get("summary")
        description = data.get("description")
        due_date = data.get("duedate")        # e.g. "2025-08-28"
        latcha_created = data.get("created")  # ISO-8601 (Automation provides ISO)

        if not latcha_key:
            logging.error("Missing key in payload")
            return jsonify({"error": "missing key"}), 400

        # De-dup if re-sent
        existing = find_existing_issue_by_latcha_id(latcha_key)
        if existing:
            logging.info("Issue already exists: %s", existing)
            return jsonify({"status": "exists", "issue": existing}), 200

        # Create mirror
        new_key = create_dest_issue(latcha_key, summary, description, due_date, latcha_created)
        logging.info("Created mirrored issue %s for source %s", new_key, latcha_key)

        # Attachments (fetched directly from source to avoid brittle templating)
        try:
            atts = fetch_attachments_from_source(latcha_key)
            if atts:
                copy_attachments_to_dest(new_key, atts)
                logging.info("Copied %d attachments to %s", len(atts), new_key)
        except Exception as e:
            logging.warning("Attachments failed for %s: %s", latcha_key, e)

        return jsonify({"status": "ok", "new_issue": new_key}), 200

    except Exception as e:
        logging.exception("Webhook handler crashed")
        return jsonify({"error": str(e)}), 500

@app.route("/", methods=["POST","GET"])
def health():
    return "OK", 200

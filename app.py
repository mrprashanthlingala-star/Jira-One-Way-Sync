import os
import io
import json
import time
import requests
import logging
from flask import Flask, request, jsonify
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

# ----- Dest (your Jira: clictestdummy) -----
DEST_SITE   = os.getenv("DEST_SITE")       # e.g. "https://clictestdummy.atlassian.net"
DEST_EMAIL  = os.getenv("DEST_EMAIL")      # your Jira email (destination)
DEST_TOKEN  = os.getenv("DEST_TOKEN")      # your API token (destination)
DEST_PROJECT= os.getenv("DEST_PROJECT")    # e.g. "KAN"
CF_LATCHA_ID= os.getenv("CF_LATCHA_ID")    # e.g. "customfield_12345" (optional)
CF_LATCHA_CREATED = os.getenv("CF_LATCHA_CREATED")  # optional

# ----- Source (client Jira: clictell) -----
SRC_SITE    = os.getenv("SRC_SITE")        # e.g. "https://clictell.atlassian.net"
SRC_EMAIL   = os.getenv("SRC_EMAIL")       # your Jira email (source side)
SRC_TOKEN   = os.getenv("SRC_TOKEN")       # your API token (source side)

# ----- Security -----
SHARED_SECRET = os.getenv("LatchaSync_2025_Secret9876")     # simple HMAC-like shared secret
TIMEOUT = 40

def dest_auth():
    return HTTPBasicAuth(DEST_EMAIL, DEST_TOKEN)

def src_auth():
    return HTTPBasicAuth(SRC_EMAIL, SRC_TOKEN)

def dest_url(path):
    return f"https://{DEST_SITE}{path}"

def src_url(path):
    return f"https://{SRC_SITE}{path}"

def jql_escape(val: str) -> str:
    return val.replace('"', '\\"')

def find_existing_issue_by_latcha_id(latcha_key: str):
    """Optional de-dup: if CF_LATCHA_ID is set, search by it; else search by summary prefix."""
    try:
        if CF_LATCHA_ID:
            jql = f'project = "{DEST_PROJECT}" AND "{CF_LATCHA_ID}" ~ "{jql_escape(latcha_key)}"'
        else:
            jql = f'project = "{DEST_PROJECT}" AND summary ~ "[Latcha {jql_escape(latcha_key)}]"'
        r = requests.get(
            dest_url(f"/rest/api/3/search"),
            params={"jql": jql, "maxResults": 1, "fields": "key"},
            auth=dest_auth(), timeout=TIMEOUT
        )
        r.raise_for_status()
        issues = r.json().get("issues", [])
        return issues[0]["key"] if issues else None
    except Exception:
        return None

def create_dest_issue(latcha_key, summary, description, due_date, latcha_created):
    fields = {
        "project": {"key": DEST_PROJECT},
        "issuetype": {"name": "Task"},
        "summary": f"[Latcha {latcha_key}] {summary or ''}",
        "description": (description or "")
            + f"\n\n---\nOriginal ticket: https://{SRC_SITE}/browse/{latcha_key}",
        "labels": ["LatchaSync"]
    }
    if due_date:
        fields["duedate"] = due_date
    if CF_LATCHA_ID:
        fields[CF_LATCHA_ID] = latcha_key
    if CF_LATCHA_CREATED and latcha_created:
        fields[CF_LATCHA_CREATED] = latcha_created  # must be ISO-8601

    r = requests.post(
        dest_url("/rest/api/3/issue"),
        auth=dest_auth(),
        headers={"Accept":"application/json","Content-Type":"application/json"},
        json={"fields": fields}, timeout=TIMEOUT
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Create issue failed: {r.status_code} {r.text}")
    return r.json()["key"]

def fetch_attachments_from_source(latcha_key):
    """Fetch attachment metadata from clictell."""
    r = requests.get(
        src_url(f"/rest/api/3/issue/{latcha_key}"),
        params={"fields":"attachment"},
        auth=src_auth(), timeout=TIMEOUT
    )
    r.raise_for_status()
    fields = r.json().get("fields", {}) or {}
    atts = fields.get("attachment") or []
    return [{"filename": a.get("filename"), "content": a.get("content")} for a in atts]

def copy_attachments_to_dest(new_issue_key, attachments):
    """Download each attachment from clictell and upload to clictestdummy."""
    for a in attachments:
        if not a.get("content"): 
            continue
        # stream download from source
        with requests.get(a["content"], auth=src_auth(), stream=True, timeout=TIMEOUT) as dl:
            dl.raise_for_status()
            file_bytes = io.BytesIO(dl.content)
        # upload to dest
        up = requests.post(
            dest_url(f"/rest/api/3/issue/{new_issue_key}/attachments"),
            auth=dest_auth(),
            headers={"X-Atlassian-Token":"no-check"},
            files={"file": (a["filename"] or "file", file_bytes)},
            timeout=TIMEOUT
        )
        if up.status_code not in (200, 201):
            # log but do not fail whole request
            print(f"[warn] upload failed {a['filename']}: {up.status_code} {up.text}")

@app.route("/webhook", methods=["POST", "GET"])
def webhook():
    try:
        # Debug logs
        logging.debug("Headers: %s", dict(request.headers))
        logging.debug("Raw body: %s", request.get_data(as_text=True))

        # Basic shared-secret gate
        if SHARED_SECRET:
            if request.headers.get("X-Shared-Secret") != SHARED_SECRET:
                logging.warning("Forbidden: bad shared secret")
                return jsonify({"error": "forbidden"}), 403

        data = request.get_json(force=True) or {}
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

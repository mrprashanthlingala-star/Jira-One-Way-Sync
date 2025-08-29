import os
import io
import requests
import logging
from flask import Flask, request, jsonify
from requests.auth import HTTPBasicAuth
import re

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

# ----- Dest (your Jira: clictestdummy) -----
DEST_SITE   = os.getenv("DEST_SITE")       # e.g. "clictestdummy.atlassian.net"
DEST_EMAIL  = os.getenv("DEST_EMAIL")      
DEST_TOKEN  = os.getenv("DEST_TOKEN")      
DEST_PROJECT= os.getenv("DEST_PROJECT")    
CF_LATCHA_ID= os.getenv("CF_LATCHA_ID")    
CF_LATCHA_CREATED = os.getenv("CF_LATCHA_CREATED")

# ----- Source (client Jira: clictell) -----
SRC_SITE    = os.getenv("SRC_SITE")        
SRC_EMAIL   = os.getenv("SRC_EMAIL")       
SRC_TOKEN   = os.getenv("SRC_TOKEN")       

# ----- Security -----
SHARED_SECRET = os.getenv("SHARED_SECRET")   # fixed
TIMEOUT = 40

PRIORITY_MAP = {}

# ----------------- Helpers -----------------
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

# ----------------- Priority -----------------
def get_priority_name(priority_id):
    global PRIORITY_MAP
    if not PRIORITY_MAP:
        try:
            r = requests.get(dest_url("/rest/api/3/priority"), auth=dest_auth(), timeout=TIMEOUT)
            r.raise_for_status()
            for p in r.json():
                PRIORITY_MAP[p["id"]] = p["name"]
        except Exception as e:
            logging.error(f"Failed to fetch priorities: {e}")
            return None
    return PRIORITY_MAP.get(str(priority_id))

# ----------------- Attachments -----------------
def fetch_attachments_from_source(issue_key):
    """Fetch attachment metadata cleanly from source Jira."""
    logging.debug("Fetching attachments for %s", issue_key)
    r = requests.get(
        src_url(f"/rest/api/3/issue/{issue_key}?fields=attachment"),
        auth=src_auth(), timeout=TIMEOUT
    )
    r.raise_for_status()
    atts = r.json().get("fields", {}).get("attachment", [])
    return [{"id": a["id"], "filename": a["filename"], "content": a["content"]} for a in atts]

def copy_attachments_to_dest(new_issue_key, attachments):
    """Download each attachment from source Jira and upload to destination Jira."""
    logging.debug("Copying %d attachments to %s", len(attachments), new_issue_key)

    for a in attachments:
        filename = a.get("filename") or "file"
        content_url = a.get("content")
        if not content_url:
            continue

        try:
            with requests.get(content_url, auth=src_auth(), stream=True, timeout=TIMEOUT) as dl:
                dl.raise_for_status()
                file_bytes = io.BytesIO(dl.content)
        except Exception as e:
            logging.warning("Failed to download %s: %s", filename, e)
            continue

        try:
            up = requests.post(
                dest_url(f"/rest/api/3/issue/{new_issue_key}/attachments"),
                auth=dest_auth(),
                headers={"X-Atlassian-Token": "no-check"},
                files={"file": (filename, file_bytes)},
                timeout=TIMEOUT
            )
            if up.status_code not in (200, 201):
                logging.warning("Upload failed for %s: %s %s", filename, up.status_code, up.text)
        except Exception as e:
            logging.warning("Failed to upload %s: %s", filename, e)

# ----------------- Issue Handling -----------------
def find_existing_issue_by_latcha_id(latcha_key: str):
    try:
        if CF_LATCHA_ID:
            jql = f'project = "{DEST_PROJECT}" AND "{CF_LATCHA_ID}" ~ "{jql_escape(latcha_key)}"'
        else:
            jql = f'project = "{DEST_PROJECT}" AND summary ~ "[Latcha {jql_escape(latcha_key)}]"'
        r = requests.get(dest_url("/rest/api/3/search"),
                         params={"jql": jql, "maxResults": 1, "fields": "key"},
                         auth=dest_auth(), timeout=TIMEOUT)
        r.raise_for_status()
        issues = r.json().get("issues", [])
        return issues[0]["key"] if issues else None
    except Exception:
        return None

def create_dest_issue(latcha_key, summary, description, due_date, latcha_created, priority, attachments):
    adf_description = {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": description or "No description"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": f"---\nOriginal ticket: https://{SRC_SITE}/browse/{latcha_key}"}]}
        ]
    }

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

    r = requests.post(dest_url("/rest/api/3/issue"),
                      auth=dest_auth(),
                      headers={"Accept": "application/json", "Content-Type": "application/json"},
                      json={"fields": fields}, timeout=TIMEOUT)
    r.raise_for_status()
    new_key = r.json()["key"]

    if attachments:
        copy_attachments_to_dest(new_key, attachments)

    return new_key

def update_dest_issue(issue_key, summary, description, due_date, latcha_created, status, priority, attachments):
    new_fields = {}
    if summary:
        new_fields["summary"] = summary
    if description:
        new_fields["description"] = {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": description}]},
                {"type": "paragraph", "content": [{"type": "text", "text": f"---\nOriginal: https://{SRC_SITE}/browse/{issue_key}"}]}
            ]
        }
    if due_date:
        new_fields["duedate"] = due_date
    if latcha_created:
        new_fields[CF_LATCHA_CREATED] = latcha_created
    if priority:
        pname = get_priority_name(priority)
        if pname:
            new_fields["priority"] = {"name": pname}

    if new_fields:
        requests.put(dest_url(f"/rest/api/3/issue/{issue_key}"),
                     auth=dest_auth(),
                     headers={"Accept": "application/json", "Content-Type": "application/json"},
                     json={"fields": new_fields}, timeout=TIMEOUT)

    # Status transition
    if status:
        transitions = requests.get(dest_url(f"/rest/api/3/issue/{issue_key}/transitions"),
                                   auth=dest_auth(), timeout=TIMEOUT).json().get("transitions", [])
        tid = next((t["id"] for t in transitions if t["name"].lower() == status.lower()), None)
        if tid:
            requests.post(dest_url(f"/rest/api/3/issue/{issue_key}/transitions"),
                          auth=dest_auth(),
                          headers={"Content-Type": "application/json"},
                          json={"transition": {"id": tid}}, timeout=TIMEOUT)

    if attachments:
        copy_attachments_to_dest(issue_key, attachments)

# ----------------- Webhook -----------------
@app.route("/webhook", methods=["POST"])
def webhook():
    if SHARED_SECRET and request.headers.get("X-Shared-Secret") != SHARED_SECRET:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(force=True)
    latcha_key = data.get("key")
    summary = data.get("summary")
    description = data.get("description")
    due_date = data.get("duedate")
    latcha_created = data.get("created")
    priority = data.get("priority")
    status = data.get("status")

    # Always fetch attachments fresh from source
    attachments = fetch_attachments_from_source(latcha_key)

    existing = find_existing_issue_by_latcha_id(latcha_key)
    if existing:
        update_dest_issue(existing, summary, description, due_date, latcha_created, status, priority, attachments)
        return jsonify({"status": "updated", "issue": existing})
    else:
        new_key = create_dest_issue(latcha_key, summary, description, due_date, latcha_created, priority, attachments)
        update_dest_issue(new_key, None, None, None, None, status, None, None)
        return jsonify({"status": "created", "issue": new_key})

@app.route("/", methods=["GET"])
def health():
    return "OK", 200

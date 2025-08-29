import os
import io
import json
import time
import requests
import logging
from flask import Flask, request, jsonify
from requests.auth import HTTPBasicAuth
import re

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

PRIORITY_MAP = {}

def get_priority_name(priority_id):
    global PRIORITY_MAP
    if not PRIORITY_MAP:
        try:
            r = requests.get(
                dest_url("/rest/api/3/priority"),
                auth=dest_auth(), timeout=TIMEOUT
            )
            r.raise_for_status()
            priorities = r.json()
            for p in priorities:
                PRIORITY_MAP[p["id"]] = p["name"]
        except Exception as e:
            logging.error(f"Failed to fetch priorities: {e}")
            return None

    return PRIORITY_MAP.get(str(priority_id))

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

def create_dest_issue(latcha_key, summary, description, due_date, latcha_created, priority, attachments):
    # Build description in Atlassian Document Format (ADF)
    adf_description = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": description or "No description provided."
                    }
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": f"---\nOriginal ticket: https://{SRC_SITE}/browse/{latcha_key}"
                    }
                ]
            }
        ]
    }

    fields = {
        "project": {"key": DEST_PROJECT},
        "issuetype": {"name": "Task"},
        "summary": f"[Latcha {latcha_key}] {summary or '(no summary)'}",
        "description": adf_description,
        "labels": ["LatchaSync"]
    }

    # Add optional fields if present
    if due_date:
        fields["duedate"] = due_date
    if CF_LATCHA_ID:
        fields[CF_LATCHA_ID] = latcha_key
    if CF_LATCHA_CREATED and latcha_created:
        fields[CF_LATCHA_CREATED] = latcha_created  # must be ISO-8601
    if priority:
        priority_name = get_priority_name(priority)
        if priority_name:
            fields["priority"] = {"name": priority_name}
        else:
            logging.warning(f"Could not map priority ID {priority} to a name.")

    r = requests.post(
        dest_url("/rest/api/3/issue"),
        auth=dest_auth(),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={"fields": fields}, timeout=TIMEOUT
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Create issue failed: {r.status_code} {r.text}")
    new_issue_key = r.json()["key"]

    # Handle attachments for newly created issue
    if attachments:
        try:
            copy_attachments_to_dest(new_issue_key, attachments)
            logging.info("Copied %d attachments to %s", len(attachments), new_issue_key)
        except Exception as e:
            logging.warning("Attachments failed for %s: %s", new_issue_key, e)

    return new_issue_key


def fetch_attachments_from_source(latcha_key):
    """Fetch attachment metadata from clictell."""
    logging.debug("Fetching attachments for %s", latcha_key)
    r = requests.get(
        src_url(f"/rest/api/3/issue/{latcha_key}?fields=attachment"),
        auth=src_auth(), timeout=TIMEOUT
    )
    r.raise_for_status()
    atts = r.json()["fields"]["attachment"]

    # Ensure content URL is absolute for download
    for a in atts:
        a["content"] = src_url(a["content"])

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

def update_dest_issue(issue_key, summary, description, due_date, latcha_created, status, priority, attachments):
    """Update an existing issue with new data."""
    try:
        # Fetch current issue details
        r = requests.get(
            dest_url(f"/rest/api/3/issue/{issue_key}"),
            auth=dest_auth(), timeout=TIMEOUT
        )
        r.raise_for_status()
        current_fields = r.json().get("fields", {})

        # Build new fields
        new_fields = {}
        if summary:
            new_fields["summary"] = f"[Latcha {issue_key}] {summary}"
        if description:
            # Build description in Atlassian Document Format (ADF)
            adf_description = {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": description
                            }
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": f"---\nOriginal ticket: https://{SRC_SITE}/browse/{issue_key}"
                            }
                        ]
                    }
                ]
            }
            new_fields["description"] = adf_description

        if due_date:
            new_fields["duedate"] = due_date
        if latcha_created:
            new_fields[CF_LATCHA_CREATED] = latcha_created
        if status and current_fields.get("status", {}).get("name") != status:
            # Handle status transition
            try:
                transitions_resp = requests.get(
                    dest_url(f"/rest/api/3/issue/{issue_key}/transitions"),
                    auth=dest_auth(), timeout=TIMEOUT
                )
                transitions_resp.raise_for_status()
                transitions = transitions_resp.json().get("transitions", [])

                transition_id = None
                for t in transitions:
                    if t["name"].lower() == status.lower():
                        transition_id = t["id"]
                        break

                if transition_id:
                    transition_resp = requests.post(
                        dest_url(f"/rest/api/3/issue/{issue_key}/transitions"),
                        auth=dest_auth(),
                        headers={"Accept": "application/json", "Content-Type": "application/json"},
                        json={
                            "transition": {
                                "id": transition_id
                            }
                        },
                        timeout=TIMEOUT
                    )
                    transition_resp.raise_for_status()
                    logging.info(f"Transitioned issue {issue_key} to status {status}")
                else:
                    logging.warning(f"No transition found for status {status} in issue {issue_key}")
            except Exception as e:
                logging.warning(f"Failed to transition status for issue {issue_key}: {e}")

        if priority:
            priority_name = get_priority_name(priority)
            if priority_name:
                new_fields["priority"] = {"name": priority_name}
            else:
                logging.warning(f"Could not map priority ID {priority} to a name during update.")

        # Handle attachments
        if attachments:
            # Fetch existing attachments
            r_atts = requests.get(
                dest_url(f"/rest/api/3/issue/{issue_key}/attachments"),
                auth=dest_auth(), timeout=TIMEOUT
            )
            r_atts.raise_for_status()
            existing_attachments = r_atts.json()

            # Prepare new attachments for upload
            new_attachments_to_upload = []
            for a in attachments:
                if not a.get("content"):
                    continue
                # Check if attachment already exists
                found = False
                for existing_att in existing_attachments:
                    if existing_att["filename"] == a["filename"]:
                        found = True
                        break
                if not found:
                    # stream download from source
                    with requests.get(a["content"], auth=src_auth(), stream=True, timeout=TIMEOUT) as dl:
                        dl.raise_for_status()
                        file_bytes = io.BytesIO(dl.content)
                    new_attachments_to_upload.append((a["filename"], file_bytes))

            # Upload new attachments
            if new_attachments_to_upload:
                up_data = []
                for filename, file_bytes in new_attachments_to_upload:
                    up_data.append(("file", (filename, file_bytes)))

                r_upload = requests.post(
                    dest_url(f"/rest/api/3/issue/{issue_key}/attachments"),
                    auth=dest_auth(),
                    headers={"X-Atlassian-Token":"no-check"},
                    files=up_data,
                    timeout=TIMEOUT
                )
                if r_upload.status_code not in (200, 201):
                    logging.warning(f"Failed to upload attachment {filename}: {r_upload.status_code} {r_upload.text}")

        # Update issue
        r_update = requests.put(
            dest_url(f"/rest/api/3/issue/{issue_key}"),
            auth=dest_auth(),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={"fields": new_fields}, timeout=TIMEOUT
        )
        if r_update.status_code not in (200, 201):
            raise RuntimeError(f"Update issue failed: {r_update.status_code} {r_update.text}")
        logging.info(f"Updated issue {issue_key} with new data.")
    except Exception as e:
        logging.exception(f"Error updating issue {issue_key}: {e}")


def parse_attachments_string(attachments_string):
    if not attachments_string: # Handle empty string or None
        return []
    
    # Regex to find each AttachmentBean block
    bean_pattern = re.compile(r"AttachmentBean\{.*?\}")
    # Regex to find filename and content URL within an AttachmentBean block
    detail_pattern = re.compile(r"filename='([^']+)',.*?content='([^']+)'")
    
    parsed_attachments = []
    for bean_match in bean_pattern.finditer(attachments_string):
        bean_block = bean_match.group(0)
        detail_match = detail_pattern.search(bean_block)
        if detail_match:
            filename = detail_match.group(1)
            content_url = detail_match.group(2)
            parsed_attachments.append({"filename": filename, "content": content_url})
        
    return parsed_attachments


@app.route("/webhook", methods=["POST", "GET"])
def webhook():
    print("Headers:", dict(request.headers))
    print("Raw body:", request.data.decode("utf-8"))

    try:
        # Debug logs
        logging.debug("Headers: %s", dict(request.headers))
        logging.debug("Raw body: %s", request.get_data(as_text=True))

        # Basic shared-secret gate
        if SHARED_SECRET:
            if request.headers.get("X-Shared-Secret") != SHARED_SECRET:
                logging.warning("Forbidden: bad shared secret")
                return jsonify({"error": "forbidden"}), 403

        try:
            data = request.get_json(force=True, silent=False)
        except Exception as e:
            print("JSON parse error:", e)
            return jsonify({"error": "Invalid JSON"}), 400

        logging.debug("Parsed JSON: %s", data)

        # Expect minimal payload from Automation
        latcha_key = data.get("key")
        summary = data.get("summary")
        description = data.get("description")
        due_date = data.get("duedate")        # e.g. "2025-08-28"
        latcha_created = data.get("created")  # ISO-8601 (Automation provides ISO)
        priority = data.get("priority")
        status = data.get("status")
        attachments_string = data.get("attachments")
        parsed_attachments = parse_attachments_string(attachments_string)

        if not latcha_key:
            logging.error("Missing key in payload")
            return jsonify({"error": "missing key"}), 400

        # De-dup if re-sent
        existing = find_existing_issue_by_latcha_id(latcha_key)
        if existing:
            logging.info("Issue already exists: %s - updating", existing)
            update_dest_issue(existing, summary, description, due_date, latcha_created, status, priority, parsed_attachments)
            return jsonify({"status": "updated", "issue": existing}), 200

        # Create mirror
        new_key = create_dest_issue(latcha_key, summary, description, due_date, latcha_created, priority, parsed_attachments)
        logging.info("Created mirrored issue %s for source %s", new_key, latcha_key)

        # After creation, if a specific status was requested, attempt to transition to it.
        if status:
            issue_key = new_key # for status transition
            try:
                transitions_resp = requests.get(
                    dest_url(f"/rest/api/3/issue/{issue_key}/transitions"),
                    auth=dest_auth(), timeout=TIMEOUT
                )
                transitions_resp.raise_for_status()
                transitions = transitions_resp.json().get("transitions", [])

                transition_id = None
                for t in transitions:
                    if t["name"].lower() == status.lower():
                        transition_id = t["id"]
                        break

                if transition_id:
                    transition_resp = requests.post(
                        dest_url(f"/rest/api/3/issue/{issue_key}/transitions"),
                        auth=dest_auth(),
                        headers={"Accept": "application/json", "Content-Type": "application/json"},
                        json={
                            "transition": {
                                "id": transition_id
                            }
                        },
                        timeout=TIMEOUT
                    )
                    transition_resp.raise_for_status()
                    logging.info(f"Transitioned newly created issue {issue_key} to status {status}")
                else:
                    logging.warning(f"No transition found for status {status} for newly created issue {issue_key}")
            except Exception as e:
                logging.warning(f"Failed to transition status for newly created issue {issue_key}: {e}")

        return jsonify({"status": "ok", "new_issue": new_key}), 200

    except Exception as e:
        logging.exception("Webhook handler crashed")
        return jsonify({"error": str(e)}), 500

@app.route("/", methods=["POST","GET"])
def health():
    return "OK", 200

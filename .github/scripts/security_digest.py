import os
import json
import urllib.request
import urllib.error
import time

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
REPO_NAME = os.getenv("GITHUB_REPOSITORY", "").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def make_request(url, method="GET", data=None, headers=None):
    if headers is None: headers = {}
    if "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    if "Accept" not in headers:
        headers["Accept"] = "application/vnd.github.v3+json"
    if "User-Agent" not in headers:
        headers["User-Agent"] = "GHAS-SAST-Digest"

    encoded_data = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, method=method, data=encoded_data, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"  [Error] {url}: {e}")
        return None

def send_to_slack(notifications, title="SAST Alerts"):
    if not notifications or not SLACK_WEBHOOK_URL: return
    
    CHUNK_SIZE = 40
    total_count = len(notifications)
    print(f"Sending {total_count} SAST alerts to Slack...")

    for i in range(0, total_count, CHUNK_SIZE):
        chunk = notifications[i : i + CHUNK_SIZE]
        current_page = (i // CHUNK_SIZE) + 1
        total_pages = (total_count + CHUNK_SIZE - 1) // CHUNK_SIZE
        
        header_text = f"🛡️ {title} ({current_page}/{total_pages})"
        
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": header_text}},
            {"type": "divider"}
        ]
        for note in chunk:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": note}})
            
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=json.dumps({"blocks": blocks}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req): pass
        except Exception as e: print(f"  Slack error: {e}")
        time.sleep(1)

def run():
    print(f"Starting SAST digest for {REPO_OWNER}/{REPO_NAME}...")
    notifications = []
    
    sast_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/code-scanning/alerts?state=open&per_page=50&severity=critical,high"
    sast_alerts = make_request(sast_url)
    
    if sast_alerts:
        print(f"  Found {len(sast_alerts)} SAST entries (Critical/High).")
        for alert in sast_alerts:
            rule = alert.get("rule", {})
            severity = rule.get("security_severity_level", "unknown").upper()
            tool = alert.get("tool", {}).get("name", "Unknown")
            
            instance = alert.get("most_recent_instance", {})
            path = instance.get("location", {}).get("path", "unknown")
            html_url = alert.get("html_url", "")

            if severity in ["CRITICAL", "HIGH"]:
                msg = f"🛡️ *{tool}* ({severity})\nFile: `{path}`\n<{html_url}|View Alert>"
                notifications.append(msg)

    if notifications:
        send_to_slack(notifications, "SAST Security Digest")
    else:
        print("No critical SAST alerts found.")

if __name__ == "__main__":
    run()

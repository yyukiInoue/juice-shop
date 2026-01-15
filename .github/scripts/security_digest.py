import os
import requests
import json

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
REPO_NAME = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# フィルタリング基準
CVSS_THRESHOLD = 7.0
EPSS_THRESHOLD = 0.01

# --- GraphQL Query (SCA / Dependabot 用) ---
QUERY_SCA = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 50) {
      nodes {
        createdAt
        state
        securityVulnerability {
          package { name }
          severity
          advisory {
            cvss { score }
            identifiers { type value }
          }
        }
      }
    }
  }
}
"""

def get_epss_score(cve_id):
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("data"):
                return float(data["data"][0].get("epss", 0))
    except:
        pass
    return 0.0

def run():
    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME}...")
    notifications = []
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # ==========================================
    # 1. SCA (Dependabot) - GraphQL
    # ==========================================
    try:
        print("Fetching SCA (Dependabot) alerts...")
        variables = {"owner": REPO_OWNER, "name": REPO_NAME}
        resp = requests.post(
            "https://api.github.com/graphql",
            json={"query": QUERY_SCA, "variables": variables},
            headers=headers
        )
        data = resp.json()
        
        if data.get("data") and data["data"].get("repository"):
            alerts = data["data"]["repository"].get("vulnerabilityAlerts", {}).get("nodes", [])
            print(f"  Found {len(alerts)} SCA entries.")
            
            for alert in alerts:
                if alert.get("state") != "OPEN":
                    continue

                vuln = alert["securityVulnerability"]
                severity = vuln["severity"]
                pkg_name = vuln["package"]["name"]
                
                cvss = vuln["advisory"]["cvss"]["score"] if vuln["advisory"]["cvss"] else 0
                identifiers = vuln["advisory"].get("identifiers", [])
                cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
                epss = get_epss_score(cve_id) if cve_id else 0

                if (severity == "CRITICAL") or (severity == "HIGH" and epss >= EPSS_THRESHOLD):
                    msg = f"📦 *{pkg_name}* ({severity})\nCVSS: {cvss} | EPSS: {epss:.2%}\nCVE: {cve_id}"
                    notifications.append(msg)
    except Exception as e:
        print(f"  [SCA Error] {e}")

    # ==========================================
    # 2. SAST (Code Scanning) - REST API
    # ==========================================
    try:
        print("Fetching SAST (Code Scanning) alerts...")
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/code-scanning/alerts"
        params = {
            "state": "open",
            "per_page": 50,
            "severity": "critical,high"
        }
        
        resp = requests.get(url, headers=headers, params=params)
        
        if resp.status_code == 200:
            alerts = resp.json()
            print(f"  Found {len(alerts)} SAST entries (Critical/High).")
            
            for alert in alerts:
                rule = alert.get("rule", {})
                severity = rule.get("security_severity_level", "unknown").upper()
                tool = alert.get("tool", {}).get("name", "Unknown")
                
                instance = alert.get("most_recent_instance", {})
                msg_text = instance.get("message", {}).get("text", "No message")
                path = instance.get("location", {}).get("path", "unknown")

                if severity in ["CRITICAL", "HIGH"]:
                    msg = f"🛡️ *{tool}* ({severity})\nFile: `{path}`\nMsg: {msg_text}"
                    notifications.append(msg)
    except Exception as e:
        print(f"  [SAST Error] {e}")

    # ==========================================
    # 3. Secret Scanning - REST API (★新規追加)
    # ==========================================
    try:
        print("Fetching Secret Scanning alerts...")
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/secret-scanning/alerts"
        params = {
            "state": "resolved",
            "per_page": 50
        }
        
        resp = requests.get(url, headers=headers, params=params)
        
        if resp.status_code == 200:
            alerts = resp.json()
            print(f"  Found {len(alerts)} Secret entries.")
            
            for alert in alerts:
                # シークレットの種類（例: "AWS Access Key"）
                secret_type = alert.get("secret_type_display_name") or alert.get("secret_type")
                html_url = alert.get("html_url")
                
                # シークレット漏洩は問答無用でCRITICAL扱いとして通知
                msg = f"🔑 *Secret Detected* (CRITICAL)\nType: `{secret_type}`\nLink: {html_url}"
                notifications.append(msg)
        elif resp.status_code == 404:
            # 機能が無効化されている場合など
            print("  [Secret Info] Feature disabled or not accessible.")
        else:
            print(f"  [Secret Error] Status {resp.status_code}: {resp.text}")

    except Exception as e:
        print(f"  [Secret Error] {e}")

    # ==========================================
    # 4. Slack通知
    # ==========================================
    if notifications:
        print(f"Sending {len(notifications)} alerts to Slack...")
        slack_payload = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "🚨 Security Daily Digest (All in One)"}},
                {"type": "divider"}
            ]
        }
        for note in notifications[:45]: # 少し枠を増やしました
            slack_payload["blocks"].append({
                "type": "section", "text": {"type": "mrkdwn", "text": note}
            })
        
        requests.post(SLACK_WEBHOOK_URL, json=slack_payload)
        print("Notification sent successfully!")
    else:
        print("No critical alerts found (Clean).")

if __name__ == "__main__":
    run()

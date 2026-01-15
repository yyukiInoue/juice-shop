import os
import requests
import json

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
REPO_NAME = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# フィルタリング基準
CVSS_THRESHOLD = 7.0      # これ以上のスコアを対象
EPSS_THRESHOLD = 0.01     # 1%以上の悪用確率なら対象 (0.01)

# --- GraphQL Query 1: SCA (Dependabot) 専用 ---
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

# --- GraphQL Query 2: SAST (Code Scanning) 専用 ---
QUERY_SAST = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    codeScanningAlerts(first: 50) {
      nodes {
        createdAt
        state
        rule {
          securitySeverityLevel
        }
        mostRecentInstance {
          message { text }
          location { path }
        }
        tool { name }
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
    variables = {"owner": REPO_OWNER, "name": REPO_NAME}

    # ==========================================
    # 1. SCA (Dependabot) の取得
    # ==========================================
    try:
        print("Fetching SCA (Dependabot) alerts...")
        resp = requests.post(
            "https://api.github.com/graphql",
            json={"query": QUERY_SCA, "variables": variables},
            headers=headers
        )
        
        data = resp.json()
        if "errors" in data:
            print("  [SCA Warning] GitHub returned errors (skipping SCA):")
            print(json.dumps(data["errors"], indent=2))
        
        elif data.get("data") and data["data"].get("repository"):
            alerts = data["data"]["repository"].get("vulnerabilityAlerts", {}).get("nodes", [])
            print(f"  Found {len(alerts)} SCA entries. Filtering...")
            
            for alert in alerts:
                # OPEN以外は無視
                if alert.get("state") != "OPEN":
                    continue

                vuln = alert["securityVulnerability"]
                severity = vuln["severity"]
                pkg_name = vuln["package"]["name"]
                
                # CVSS & CVE
                cvss = vuln["advisory"]["cvss"]["score"] if vuln["advisory"]["cvss"] else 0
                identifiers = vuln["advisory"].get("identifiers", [])
                cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
                
                # EPSS
                epss = get_epss_score(cve_id) if cve_id else 0

                # 判定
                if (severity == "CRITICAL") or (severity == "HIGH" and epss >= EPSS_THRESHOLD):
                    msg = f"📦 *{pkg_name}* ({severity})\nCVSS: {cvss} | EPSS: {epss:.2%}\nCVE: {cve_id}"
                    notifications.append(msg)
        else:
            print("  [SCA Info] No data returned.")

    except Exception as e:
        print(f"  [SCA Error] {e}")

    # ==========================================
    # 2. SAST (Code Scanning) の取得
    # ==========================================
    try:
        print("Fetching SAST (Code Scanning) alerts...")
        resp = requests.post(
            "https://api.github.com/graphql",
            json={"query": QUERY_SAST, "variables": variables},
            headers=headers
        )
        
        data = resp.json()
        
        # エラー（機能が無効など）があっても、SCAが取れていればOKとする
        if "errors" in data:
            print("  [SAST Info] Code Scanning not ready or disabled. Skipping.")
            # エラーログはあえて出さない（ノイズになるため）
        
        elif data.get("data") and data["data"].get("repository"):
            alerts = data["data"]["repository"].get("codeScanningAlerts", {}).get("nodes", [])
            print(f"  Found {len(alerts)} SAST entries. Filtering...")

            for alert in alerts:
                if alert.get("state") != "OPEN":
                    continue
                
                rule_sev = alert["rule"]["securitySeverityLevel"]
                tool = alert["tool"]["name"]
                path = alert["mostRecentInstance"]["location"]["path"]
                msg_text = alert["mostRecentInstance"]["message"]["text"]

                if rule_sev in ["CRITICAL", "HIGH"]:
                    msg = f"🛡️ *{tool}* ({rule_sev})\nFile: `{path}`\nMsg: {msg_text}"
                    notifications.append(msg)

    except Exception as e:
        print(f"  [SAST Error] {e}")

    # ==========================================
    # 3. Slack通知
    # ==========================================
    if notifications:
        print(f"Sending {len(notifications)} alerts to Slack...")
        slack_payload = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "🚨 Security Daily Digest"}},
                {"type": "divider"}
            ]
        }
        for note in notifications[:10]:
            slack_payload["blocks"].append({
                "type": "section", "text": {"type": "mrkdwn", "text": note}
            })
        
        requests.post(SLACK_WEBHOOK_URL, json=slack_payload)
        print("Notification sent successfully!")
    else:
        print("No critical alerts found (Clean).")

if __name__ == "__main__":
    run()

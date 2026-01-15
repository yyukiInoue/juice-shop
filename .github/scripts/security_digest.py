import os
import requests
import json
from datetime import datetime

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
REPO_NAME = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# フィルタリング基準
CVSS_THRESHOLD = 7.0      # これ以上のスコアを対象
EPSS_THRESHOLD = 0.01     # 1%以上の悪用確率なら対象 (0.01)

# --- GraphQL Query (修正版) ---
# 修正点: vulnerabilityAlerts の引数から state: OPEN を削除し、取得フィールドに state を追加
QUERY = """
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
            summary
          }
        }
      }
    }
    codeScanningAlerts(first: 50, state: OPEN) {
      nodes {
        createdAt
        rule {
          id
          securitySeverityLevel
          description
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
    """EPSS APIを叩いて悪用確率を取得する"""
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("data"):
                return float(data["data"][0].get("epss", 0))
    except Exception as e:
        print(f"EPSS Warning: {e}")
        pass
    return 0.0

def run():
    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME}...")

    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN is missing.")
        return
    if not SLACK_WEBHOOK_URL:
        print("Error: SLACK_WEBHOOK_URL is missing.")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    variables = {"owner": REPO_OWNER, "name": REPO_NAME}
    
    # 1. GitHub APIからデータ取得
    try:
        resp = requests.post(
            "https://api.github.com/graphql",
            json={"query": QUERY, "variables": variables},
            headers=headers
        )
    except Exception as e:
        print(f"Connection Error: {e}")
        return

    if resp.status_code != 200:
        print(f"API Error (Status {resp.status_code}): {resp.text}")
        return
        
    data = resp.json()
    
    # エラーの詳細ログ
    if "errors" in data:
        print("GraphQL Errors found:")
        print(json.dumps(data["errors"], indent=2))
        # エラーがあっても、Code Scanningが取れないだけでSCAは取れている場合があるので続行を試みる

    if not data.get("data") or not data["data"].get("repository"):
        print("Error: No repository data returned. Check permissions or repository name.")
        return

    repo_data = data["data"]["repository"]
    notifications = []

    # 2. SCA (Dependabot) のフィルタリング
    if repo_data.get("vulnerabilityAlerts") and repo_data["vulnerabilityAlerts"].get("nodes"):
        for alert in repo_data["vulnerabilityAlerts"]["nodes"]:
            try:
                # 【修正点】ここでステータスがOPENかチェックする
                if alert.get("state") != "OPEN":
                    continue

                vuln = alert["securityVulnerability"]
                pkg_name = vuln["package"]["name"]
                severity = vuln["severity"]
                
                # CVSS取得
                cvss_data = vuln["advisory"].get("cvss")
                cvss = cvss_data["score"] if cvss_data else 0
                
                identifiers = vuln["advisory"].get("identifiers", [])
                cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
                
                epss = get_epss_score(cve_id) if cve_id else 0

                # 判定ロジック
                is_dangerous = (severity == "CRITICAL") or \
                               (severity == "HIGH" and epss >= EPSS_THRESHOLD)

                if is_dangerous:
                    msg = f"📦 *{pkg_name}* ({severity})\nCVSS: {cvss} | EPSS: {epss:.2%}\nCVE: {cve_id}"
                    notifications.append(msg)
            except Exception as e:
                print(f"Error processing SCA alert: {e}")
                continue
    else:
        print("Info: No SCA alerts found or Dependabot is disabled.")

    # 3. SAST (Code Scanning) のフィルタリング
    if repo_data.get("codeScanningAlerts") and repo_data["codeScanningAlerts"].get("nodes"):
        for alert in repo_data["codeScanningAlerts"]["nodes"]:
            try:
                if not alert.get("rule") or not alert.get("mostRecentInstance"):
                    continue

                rule_sev = alert["rule"]["securitySeverityLevel"]
                tool = alert["tool"]["name"]
                
                msg_obj = alert["mostRecentInstance"].get("message", {})
                msg_text = msg_obj.get("text", "No description")
                
                loc_obj = alert["mostRecentInstance"].get("location", {})
                path = loc_obj.get("path", "unknown")

                if rule_sev in ["CRITICAL", "HIGH"]:
                    msg = f"🛡️ *{tool}* ({rule_sev})\nFile: `{path}`\nMsg: {msg_text}"
                    notifications.append(msg)
            except Exception as e:
                print(f"Error processing SAST alert: {e}")
                continue
    else:
        # Code Scanningのエラーが出ていても、ここがNoneになるだけでスクリプトは落ちない
        print("Info: No Code Scanning alerts found or feature is disabled/not ready.")

    # 4. Slack通知
    if notifications:
        print(f"Sending {len(notifications)} alerts to Slack...")
        slack_payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🚨 Security Daily Digest (Priority Only)"}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "以下の優先対応が必要です："}
                },
                {"type": "divider"}
            ]
        }
        
        for note in notifications[:10]:
            slack_payload["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": note}
            })
        
        if len(notifications) > 10:
             slack_payload["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"...他 {len(notifications)-10} 件のアラートがあります。GitHubを確認してください。"}
            })

        try:
            res = requests.post(SLACK_WEBHOOK_URL, json=slack_payload)
            if res.status_code == 200:
                print("Notification sent successfully!")
            else:
                print(f"Slack Error {res.status_code}: {res.text}")
        except Exception as e:
            print(f"Slack Connection Error: {e}")
    else:
        print("No critical alerts found (Clean).")

if __name__ == "__main__":
    run()

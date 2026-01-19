import os
import json
import urllib.request
import urllib.error
import time

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
REPO_NAME = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# フィルタリング基準
CVSS_THRESHOLD = 7.0
EPSS_THRESHOLD = 0.01

# --- GraphQL Query (SCA / Dependabot) ---
# 【変更】number (アラート番号) を追加してURLを作れるようにしました
QUERY_SCA = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 50, states: OPEN) {
      nodes {
        createdAt
        number
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

def make_request(url, method="GET", data=None, headers=None):
    """urllibを使用した汎用リクエスト関数"""
    if headers is None:
        headers = {}
    
    if "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    if "Accept" not in headers:
        headers["Accept"] = "application/vnd.github.v3+json"
    if "User-Agent" not in headers:
        headers["User-Agent"] = "GHAS-Security-Digest"

    encoded_data = json.dumps(data).encode("utf-8") if data else None
    
    req = urllib.request.Request(url, method=method, data=encoded_data, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  [HTTP Error] {url}: {e.code} {e.reason}")
        return None
    except Exception as e:
        print(f"  [Connection Error] {url}: {e}")
        return None

def get_epss_score(cve_id):
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GHAS-Digest"})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("data"):
                return float(data["data"][0].get("epss", 0))
    except:
        pass
    return 0.0

def run():
    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME}...")
    notifications = []

    # ==========================================
    # 1. SCA (Dependabot) - GraphQL
    # ==========================================
    print("Fetching SCA (Dependabot) alerts...")
    variables = {"owner": REPO_OWNER, "name": REPO_NAME}
    
    response = make_request(
        "https://api.github.com/graphql", 
        method="POST", 
        data={"query": QUERY_SCA, "variables": variables}
    )

    if response and response.get("data", {}).get("repository"):
        alerts = response["data"]["repository"].get("vulnerabilityAlerts", {}).get("nodes", [])
        print(f"  Found {len(alerts)} SCA entries.")

        for alert in alerts:
            vuln = alert["securityVulnerability"]
            severity = vuln["severity"]
            pkg_name = vuln["package"]["name"]
            
            # 詳細URLを生成
            alert_number = alert.get("number")
            alert_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/security/dependabot/{alert_number}"
            
            advisory = vuln["advisory"]
            cvss = advisory["cvss"]["score"] if advisory["cvss"] else 0
            identifiers = advisory.get("identifiers", [])
            cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
            
            epss = get_epss_score(cve_id) if cve_id else 0

            is_critical = severity == "CRITICAL"
            is_high_risk = severity == "HIGH" and epss >= EPSS_THRESHOLD
            
            if is_critical or is_high_risk:
                # 【変更】URLリンクを追加
                msg = f"📦 *{pkg_name}* ({severity})\nCVSS: {cvss} | EPSS: {epss:.2%}\n<{alert_url}|View Alert>"
                notifications.append(msg)

    # ==========================================
    # 2. SAST (Code Scanning) - REST API
    # ==========================================
    print("Fetching SAST (Code Scanning) alerts...")
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
            
            # 【変更】メッセージ本文(msg_text)を削除し、詳細URLのみにする
            html_url = alert.get("html_url", "") # これがGitHubの詳細画面URL

            if severity in ["CRITICAL", "HIGH"]:
                msg = f"🛡️ *{tool}* ({severity})\nFile: `{path}`\n<{html_url}|View Alert>"
                notifications.append(msg)

    # ==========================================
    # 3. Secret Scanning - REST API
    # ==========================================
    print("Fetching Secret Scanning alerts...")
    secret_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/secret-scanning/alerts?state=open&per_page=50"
    
    secret_alerts = make_request(secret_url)
    
    if secret_alerts is not None and isinstance(secret_alerts, list):
        print(f"  Found {len(secret_alerts)} Secret entries.")
        for alert in secret_alerts:
            secret_type = alert.get("secret_type_display_name") or alert.get("secret_type")
            html_url = alert.get("html_url")
            
            # ここもフォーマットを統一
            msg = f"🔑 *Secret Detected* (CRITICAL)\nType: `{secret_type}`\n<{html_url}|View Alert>"
            notifications.append(msg)

    # ==========================================
    # 4. Slack通知 (分割送信対応版)
    # ==========================================
    if notifications and SLACK_WEBHOOK_URL:
        total_count = len(notifications)
        print(f"Sending {total_count} alerts to Slack...")
        
        # 1通あたりに載せる件数 (ヘッダー分を考慮して40件程度が安全)
        CHUNK_SIZE = 40
        
        # リストを CHUNK_SIZE ずつ切り出してループ処理
        for i in range(0, total_count, CHUNK_SIZE):
            # 今回送る分 (例: 0~40件目, 40~80件目...)
            chunk = notifications[i : i + CHUNK_SIZE]
            
            # ページ番号 (例: 1/3)
            current_page = (i // CHUNK_SIZE) + 1
            total_pages = (total_count + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            header_text = f"🚨 Security Alert ({current_page}/{total_pages})"
            if total_pages > 1:
                header_text += f" - showing {i+1} to {min(i+len(chunk), total_count)} of {total_count}"

            slack_payload = {
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": header_text}},
                    {"type": "divider"}
                ]
            }
            
            for note in chunk:
                slack_payload["blocks"].append({
                    "type": "section", "text": {"type": "mrkdwn", "text": note}
                })

            # 送信処理
            req = urllib.request.Request(
                SLACK_WEBHOOK_URL,
                data=json.dumps(slack_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            
            try:
                with urllib.request.urlopen(req) as res:
                    print(f"  Batch {current_page} sent successfully.")
            except urllib.error.HTTPError as e:
                print(f"  [Slack Error] Batch {current_page} failed: {e.code} {e.read().decode('utf-8')}")
            except Exception as e:
                print(f"  [Slack Error] Batch {current_page} error: {e}")
            
            # 【重要】連投でSlack側に拒否されないよう、少し待機する
            time.sleep(3)

    else:
        print("No critical alerts found or Webhook URL missing.")

if __name__ == "__main__":
    run()

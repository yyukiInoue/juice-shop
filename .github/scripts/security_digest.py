import os
import json
import urllib.request
import urllib.error
import time

# --- 設定 ---
# GitHub Appで取得したトークンを受け取る
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
# GITHUB_REPOSITORY は "owner/repo" の形式なので分割
REPO_NAME = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# フィルタリング基準
CVSS_THRESHOLD = 7.0
EPSS_THRESHOLD = 0.01

# --- GraphQL Query (SCA / Dependabot) ---
QUERY_SCA = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 50, states: OPEN) {
      nodes {
        createdAt
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
    
    # デフォルトヘッダー
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
    # 外部APIなので認証ヘッダーを除外してコール
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
    
    # GraphQLはPOSTで送信
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
            severity = vuln["severity"] # CRITICAL, HIGH, MODERATE, LOW
            pkg_name = vuln["package"]["name"]
            
            advisory = vuln["advisory"]
            cvss = advisory["cvss"]["score"] if advisory["cvss"] else 0
            identifiers = advisory.get("identifiers", [])
            cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
            
            # EPSS取得 (APIレート制限考慮で少し待機しても良いが今回は直列実行)
            epss = get_epss_score(cve_id) if cve_id else 0

            # フィルタリングロジック
            is_critical = severity == "CRITICAL"
            is_high_risk = severity == "HIGH" and epss >= EPSS_THRESHOLD
            
            if is_critical or is_high_risk:
                msg = f"📦 *{pkg_name}* ({severity})\nCVSS: {cvss} | EPSS: {epss:.2%}\nCVE: {cve_id}"
                notifications.append(msg)

    # ==========================================
    # 2. SAST (Code Scanning) - REST API
    # ==========================================
    print("Fetching SAST (Code Scanning) alerts...")
    # URLパラメータを手動構築
    sast_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/code-scanning/alerts?state=open&per_page=50&severity=critical,high"
    
    sast_alerts = make_request(sast_url)
    if sast_alerts:
        print(f"  Found {len(sast_alerts)} SAST entries (Critical/High).")
        for alert in sast_alerts:
            rule = alert.get("rule", {})
            severity = rule.get("security_severity_level", "unknown").upper()
            tool = alert.get("tool", {}).get("name", "Unknown")
            
            instance = alert.get("most_recent_instance", {})
            msg_text = instance.get("message", {}).get("text", "No message")
            path = instance.get("location", {}).get("path", "unknown")

            if severity in ["CRITICAL", "HIGH"]:
                msg = f"🛡️ *{tool}* ({severity})\nFile: `{path}`\nMsg: {msg_text}"
                notifications.append(msg)

    # ==========================================
    # 3. Secret Scanning - REST API
    # ==========================================
    print("Fetching Secret Scanning alerts...")
    secret_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/secret-scanning/alerts?state=open&per_page=50"
    
    secret_alerts = make_request(secret_url)
    
    # Secret Scanningが無効な場合は404が返るためNoneチェック
    if secret_alerts is not None:
        # エラー時はdictが返ることもあるのでリストか確認
        if isinstance(secret_alerts, list):
            print(f"  Found {len(secret_alerts)} Secret entries.")
            for alert in secret_alerts:
                secret_type = alert.get("secret_type_display_name") or alert.get("secret_type")
                html_url = alert.get("html_url")
                
                msg = f"🔑 *Secret Detected* (CRITICAL)\nType: `{secret_type}`\nLink: {html_url}"
                notifications.append(msg)
        else:
            print(f"  [Secret Info] API returned unexpected format (Likely disabled).")

# ==========================================
    # 4. Slack通知
    # ==========================================
    if notifications and SLACK_WEBHOOK_URL:
        print(f"Sending {len(notifications)} alerts to Slack...")
        
        slack_payload = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "🚨 Security Daily Digest"}},
                {"type": "divider"}
            ]
        }
        
        # 【修正】区切り線を削除したため、上限ギリギリの45件まで表示可能です
        # (Header 1 + Divider 1 + Alerts 45 = 47 blocks < 50 limit)
        for note in notifications[:45]:
            slack_payload["blocks"].append({
                "type": "section", "text": {"type": "mrkdwn", "text": note}
            })
            # 削除: slack_payload["blocks"].append({"type": "divider"}) 

        # もし45件を超える場合、末尾にリンクなどを付けると親切です（任意）
        if len(notifications) > 45:
             slack_payload["blocks"].append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"⚠️ ...and {len(notifications) - 45} more alerts. Check GitHub Security tab."}]
            })

        # WebhookへPOST
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=json.dumps(slack_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req) as res:
                print("Notification sent successfully!")
        except urllib.error.HTTPError as e:
             # エラーの詳細を出力してデバッグしやすくする
            print(f"  [Slack Error] {e.code}: {e.read().decode('utf-8')}")
        except Exception as e:
            print(f"  [Slack Error] {e}")
    else:
        print("No critical alerts found or Webhook URL missing.")

if __name__ == "__main__":
    run()

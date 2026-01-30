import os
import json
import urllib.request
import urllib.error
import urllib.parse
import time
from collections import Counter

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
# リポジトリ情報の取得
repo_env = os.getenv("GITHUB_REPOSITORY")
if repo_env and "/" in repo_env:
    REPO_OWNER, REPO_NAME = repo_env.split("/")
else:
    REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
    REPO_NAME = "unknown-repo"

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# --- ヘルパー関数: HTTPリクエスト ---
def http_request(url, method="GET", headers=None, data=None, params=None):
    if headers is None:
        headers = {}
    
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"
    
    req = urllib.request.Request(url, headers=headers, method=method)
    
    if data:
        json_data = json.dumps(data).encode("utf-8")
        req.data = json_data
        req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            response_body = res.read().decode("utf-8")
            if response_body:
                return json.loads(response_body)
            return {}
    except urllib.error.HTTPError as e:
        print(f"  [HTTP Error] {e.code}: {e.reason} (URL: {url})")
        return None
    except Exception as e:
        print(f"  [Connection Error] {e}")
        return None

# --- 関数: SASTアラートの全件取得 (Pagination対応) ---
def get_all_sast_alerts(headers):
    base_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/code-scanning/alerts"
    
    all_alerts = []
    page = 1
    per_page = 100
    
    print(f"Fetching ALL SAST (CodeQL) alerts for {REPO_OWNER}/{REPO_NAME}...")
    
    while True:
        # 修正: severity指定を削除し、全レベルのアラートを取得
        params = {
            "state": "open",
            "per_page": per_page,
            "page": page
        }
        
        print(f"  Requesting page {page}...")
        data = http_request(base_url, headers=headers, params=params)
        
        if not data or not isinstance(data, list) or len(data) == 0:
            break
            
        all_alerts.extend(data)
        
        if len(data) < per_page:
            break
            
        page += 1
        time.sleep(0.5)
        
    return all_alerts

def run():
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN is not set.")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SAST-Summary-Notifier"
    }

    # 1. 全件取得
    alerts = get_all_sast_alerts(headers)

    if not alerts:
        print("Clean (No SAST alerts found).")
        # アラート0件でも「0件です」という通知を送りたい場合はここで処理を分岐してください
        return

    print(f"  Total Found: {len(alerts)} SAST entries. Aggregating...")

    # 2. 集計処理
    severity_counts = Counter()
    rule_counts = Counter()

    for alert in alerts:
        rule_info = alert.get("rule", {})
        
        # Severityの判定 (security_severity_level を優先、無ければ severity)
        # GitHub APIは severity(error/warning) と security_severity_level(critical/high/...) を返します
        sev = rule_info.get("security_severity_level")
        if not sev:
            sev = rule_info.get("severity", "unknown")
        
        # 表記揺れ統一のために小文字化
        sev_key = str(sev).lower()
        severity_counts[sev_key] += 1

        # ルール名（脆弱性名称）の集計
        rule_desc = rule_info.get("description", "No description")
        rule_counts[rule_desc] += 1

    # 3. Slack通知用メッセージの作成 (Block Kit)
    
    # 緊急度の表示順序定義
    sev_order = ["critical", "high", "medium", "low", "warning", "note", "error"]
    sev_emoji = {
        "critical": "🚨", "high": "🔥", "medium": "🟠", 
        "low": "⚪", "warning": "⚠️", "note": "📝", "error": "❌"
    }

    # 緊急度別サマリーのテキスト作成
    severity_text_lines = []
    for sev in sev_order:
        count = severity_counts.get(sev, 0)
        if count > 0:
            icon = sev_emoji.get(sev, "❓")
            severity_text_lines.append(f"{icon} *{sev.upper()}:* {count}")
    
    # 上記の定義に含まれないその他のSeverityがあれば追加
    for sev, count in severity_counts.items():
        if sev not in sev_order:
            severity_text_lines.append(f"❓ *{sev.upper()}:* {count}")

    severity_block_text = "\n".join(severity_text_lines)

    # 脆弱性名称別ランキング (件数多い順)
    top_rules_text_lines = []
    # 全部出すとSlackの上限を超える可能性があるため、上位20件に絞る（必要に応じて調整）
    for rank, (name, count) in enumerate(rule_counts.most_common(20), 1):
        top_rules_text_lines.append(f"{rank}. {name}: *{count}*")
    
    rule_block_text = "\n".join(top_rules_text_lines)
    if len(rule_counts) > 20:
        rule_block_text += f"\n... and {len(rule_counts) - 20} more rules."

    # GitHub Securityタブへのリンク
    security_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/security/code-scanning"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"📊 Weekly SAST Summary: {REPO_NAME}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Total Alerts:*\n{len(alerts)}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Repository:*\n<{security_url}|{REPO_OWNER}/{REPO_NAME}>"
                }
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*By Severity (緊急度別):*\n" + severity_block_text
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Top Vulnerabilities (検知名称別):*\n" + rule_block_text
            }
        }
    ]

    # --- Slack送信 ---
    print("Sending Summary to Slack...")
    if SLACK_WEBHOOK_URL:
        payload = {"blocks": blocks}
        http_request(SLACK_WEBHOOK_URL, method="POST", data=payload)
        print("Done.")
    else:
        print("Skipped Slack notification (URL not set).")

if __name__ == "__main__":
    run()

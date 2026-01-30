import os
import json
import urllib.request
import urllib.error
import urllib.parse
import time

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
def get_all_sast_critical_alerts(headers):
    base_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/code-scanning/alerts"
    
    all_alerts = []
    page = 1
    per_page = 100  # APIの1ページあたりの最大取得数
    
    print(f"Fetching ALL SAST (CodeQL) Critical alerts for {REPO_OWNER}/{REPO_NAME}...")
    
    while True:
        # API側で厳密に Critical のみを要求しています
        params = {
            "state": "open",
            "severity": "critical",
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
        "User-Agent": "SAST-Critical-Notifier"
    }

    notifications = []
    
    # 全件取得
    alerts = get_all_sast_critical_alerts(headers)

    if alerts:
        print(f"  Total Found: {len(alerts)} SAST Critical entries.")
        
        for alert in alerts:
            # 【修正】以前ここで rule_severity != "critical" を弾いていましたが削除しました。
            # APIが返してきた時点でCriticalレベル（Security Severity High/Critical）であると信頼します。

            rule_desc = alert.get("rule", {}).get("description", "No description")
            rule_id = alert.get("rule", {}).get("id", "unknown-rule")
            tool_name = alert.get("tool", {}).get("name", "CodeQL")
            
            # 深刻度の表示用ラベル取得
            # rule.security_severity_level があればそれを使い、なければ rule.severity を使う
            rule_info = alert.get("rule", {})
            severity_label = rule_info.get("security_severity_level", rule_info.get("severity", "CRITICAL"))
            
            html_url = alert.get("html_url", "#")
            
            location = alert.get("most_recent_instance", {}).get("location", {})
            file_path = location.get("path", "Unknown file")
            start_line = location.get("start_line", "?")
            
            msg_text = f"""🚨 *SAST Critical Alert Found!*
*Tool:* {tool_name}
*Rule:* {rule_desc} (`{rule_id}`)
────────────────
• *File:* `{file_path}` (Line: {start_line})
• *Severity:* `{str(severity_label).upper()}`
🔗 <{html_url}|Check Alert on GitHub>"""

            msg = {
                "text": msg_text
            }
            notifications.append(msg)
    else:
        print("  No SAST data found.")

    # --- Slack通知 (分割送信) ---
    if notifications:
        total_count = len(notifications)
        print(f"Sending {total_count} SAST alerts to Slack...")
        
        BATCH_SIZE = 20
        
        if SLACK_WEBHOOK_URL:
            for i in range(0, total_count, BATCH_SIZE):
                batch = notifications[i : i + BATCH_SIZE]
                current_start = i + 1
                current_end = i + len(batch)
                
                blocks = [
                    {
                        "type": "header", 
                        "text": {
                            "type": "plain_text", 
                            "text": f"🛡️ SAST Critical Digest ({current_start}-{current_end}/{total_count})"
                        }
                    },
                    {"type": "divider"}
                ]
                
                for note in batch:
                    blocks.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": note['text']
                        }
                    })
                    blocks.append({"type": "divider"})

                payload = {"blocks": blocks}
                
                http_request(SLACK_WEBHOOK_URL, method="POST", data=payload)
                print(f"  Sent batch {current_start}-{current_end}")
                time.sleep(1)
                
            print("Done.")
        else:
            print("Skipped Slack notification (URL not set).")
    else:
        print("Clean (No Critical SAST alerts found).")

if __name__ == "__main__":
    run()

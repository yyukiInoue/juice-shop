import os
import json
import urllib.request
import urllib.error
import urllib.parse
import time

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
repo_env = os.getenv("GITHUB_REPOSITORY")
if repo_env and "/" in repo_env:
    REPO_OWNER, REPO_NAME = repo_env.split("/")
else:
    REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
    REPO_NAME = "unknown-repo"

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# 閾値設定
CVSS_THRESHOLD = 7.0
EPSS_THRESHOLD = 0.01  # 1%

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

# --- 関数: CISA KEVリストの取得 ---
def get_cisa_kev_cves():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print("Fetching CISA KEV Catalog...")
    data = http_request(url)
    if data:
        kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
        print(f"  Loaded {len(kev_set)} KEV entries.")
        return kev_set
    return set()

# --- 関数: EPSSスコアの取得 ---
def get_epss_score(cve_id):
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    url = "https://api.first.org/data/v1/epss"
    params = {"cve": cve_id}
    time.sleep(0.1)
    data = http_request(url, params=params)
    if data and data.get("data"):
        try:
            return float(data["data"][0].get("epss", 0))
        except (IndexError, ValueError):
            pass
    return 0.0

# --- 優先度レベル判定ロジック ---
def calculate_priority(is_kev, scope, vector_string, severity, epss, has_fix):
    is_network = "AV:N" in (vector_string or "")
    is_runtime = (scope == "RUNTIME")

    # Lv.1: CISA KEV掲載 (最優先)
    if is_kev:
        return "🚨 Lv.1 Emergency (即時)", "danger", 1

    # Lv.2: Runtime × Network × (EPSS高 or Critical)
    if is_runtime and is_network and (epss >= EPSS_THRESHOLD):
        return "🔥 Lv.2 Danger (即時)", "danger", 2

    # Lv.3: Runtime × Network × (Critical OR High)
    if is_runtime and is_network and severity in ["CRITICAL", "HIGH"]:
        return "⚠️ Lv.3 Warning (月次)", "warning", 3

    # Lv.4: Medium Severity (Runtime)
    if is_runtime and severity == "MEDIUM":
        return "🟠 Lv.4 Medium (中程度)", "warning", 4

    # Lv.5: Development環境 または Low/Local
    if scope == "DEVELOPMENT":
        return "🛠 Lv.5 Dev Dependency (開発環境)", "#439FE0", 5
    
    # Lv.6: その他
    return "⚪ Lv.6 Low/Info (低リスク)", "#808080", 6

# --- GraphQL Query (ページネーション対応) ---
# 変更点: nodes に 'number' を追加してアラートIDを取得できるように修正
QUERY_SCA = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 100, after: $after) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        number
        createdAt
        state
        dependencyScope
        securityVulnerability {
          package { name }
          severity
          firstPatchedVersion { identifier }
          advisory {
            cvss { score vectorString }
            identifiers { type value }
          }
        }
      }
    }
  }
}
"""

def get_all_sca_alerts(headers):
    all_alerts = []
    hasNextPage = True
    end_cursor = None
    
    print("Fetching SCA (Dependabot) alerts...")

    while hasNextPage:
        variables = {"owner": REPO_OWNER, "name": REPO_NAME, "after": end_cursor}
        
        data = http_request(
            "https://api.github.com/graphql",
            method="POST",
            headers=headers,
            data={"query": QUERY_SCA, "variables": variables}
        )
        
        if not data or "data" not in data or not data["data"].get("repository"):
            print("  Error: Invalid GraphQL response or no repository found.")
            break

        alerts_data = data["data"]["repository"]["vulnerabilityAlerts"]
        nodes = alerts_data.get("nodes", [])
        all_alerts.extend(nodes)
        
        page_info = alerts_data.get("pageInfo", {})
        hasNextPage = page_info.get("hasNextPage", False)
        end_cursor = page_info.get("endCursor")
        
        print(f"  Fetched {len(nodes)} alerts... (Total: {len(all_alerts)})")
        
        if hasNextPage:
            time.sleep(0.5) # レート制限対策

    return all_alerts

def run():
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN is not set.")
        return

    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME}...")
    notifications = []
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Security-Digest-Script"
    }
    
    kev_cves = get_cisa_kev_cves()

    # ==========================================
    # 1. SCA (Dependabot) Processing (全件取得)
    # ==========================================
    alerts = get_all_sca_alerts(headers)
    
    if alerts:
        print(f"  Processing {len(alerts)} SCA entries...")
        
        for alert in alerts:
            if alert.get("state") != "OPEN":
                continue

            vuln = alert["securityVulnerability"]
            pkg_name = vuln["package"]["name"]
            severity = vuln["severity"]
            
            # アラート番号とURLの生成 (追加)
            alert_number = alert.get("number")
            alert_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/security/dependabot/{alert_number}"

            raw_scope = alert.get("dependencyScope", "UNKNOWN")
            scope_display = "🚀 Runtime (本番)" if raw_scope == "RUNTIME" else "🛠 Dev (開発)"
            
            patched_ver = vuln.get("firstPatchedVersion")
            has_fix = True if patched_ver else False
            fix_display = f"✅ Fix: `{patched_ver['identifier']}`" if has_fix else "🚫 No Fix (パッチなし)"

            advisory = vuln["advisory"]
            cvss_score = advisory["cvss"]["score"] if advisory["cvss"] else 0
            vector_string = advisory["cvss"]["vectorString"] if advisory["cvss"] else ""
            
            identifiers = advisory.get("identifiers", [])
            cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
            
            epss = get_epss_score(cve_id) if cve_id else 0
            is_in_kev = cve_id in kev_cves

            # 判定ロジックの呼び出し
            priority_label, color_style, level_id = calculate_priority(
                is_in_kev, raw_scope, vector_string, severity, epss, has_fix
            )
            
            # --- フィルタリング処理 ---
            # Lv.1 (Emergency) か Lv.2 (Danger) の場合のみ通知リストに追加
            if level_id > 2:
                continue
            
            # Network Attack有無の判定と表示 ---
            is_network = "AV:N" in (vector_string or "")
            network_display = "🌐 YES (Network)" if is_network else "🔒 NO (Local/Phys)"
            
            # CISA KEV掲載有無の表示 ---
            kev_display = "💀 YES (Listed)" if is_in_kev else "🛡️ NO"

            # メッセージ作成 (GitHubリンクを追加)
            msg_text = f"""{priority_label}
📦 {pkg_name} ({severity})
────────────────
• Scope: {scope_display}
• Network Attack: {network_display}
• CISA KEV: {kev_display}
• Status: {fix_display}
📊 EPSS: {epss:.2%} / CVSS: {cvss_score}
 {cve_id}
🔗<{alert_url}|View Alert #{alert_number} on GitHub>"""

            msg = {
                "color": color_style,
                "text": msg_text
            }
            notifications.append(msg)
    else:
        print("  No SCA data found.")

    # ==========================================
    # 2. Slack通知 (分割送信対応)
    # ==========================================
    if notifications:
        total_count = len(notifications)
        print(f"Sending {total_count} HIGH-PRIORITY alerts to Slack...")
        
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
                            "text": f"🛡️ Security Alert Digest [Daily] ({current_start}-{current_end}/{total_count})"
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
        print("Clean (No Lv.1 or Lv.2 alerts found).")

if __name__ == "__main__":
    run()

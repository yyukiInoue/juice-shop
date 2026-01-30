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

# 閾値設定（優先度判定に使用）
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
        with urllib.request.urlopen(req, timeout=10) as res:
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

# --- 【修正】優先度レベル判定ロジック（全レベル対応版） ---
def calculate_priority(is_kev, scope, vector_string, severity, epss, has_fix):
    is_network = "AV:N" in (vector_string or "")
    is_runtime = (scope == "RUNTIME")

    # Lv.1: CISA KEV掲載 (最優先)
    if is_kev:
        return "🚨 Lv.1 Emergency (即時)", "danger"

    # Lv.2: Runtime × Network × (EPSS高 or Critical)
    if is_runtime and is_network and (epss >= EPSS_THRESHOLD):
        return "🔥 Lv.2 Danger (即時)", "danger"

    # Lv.3: Runtime × Network × (Critical OR High)
    if is_runtime and is_network and severity in ["CRITICAL", "HIGH"]:
        return "⚠️ Lv.3 Warning (月次)", "warning"

    # --- 以下を追加: Medium/Low/Dev を明確にラベル付け ---

    # Lv.4: Medium Severity (Runtime)
    if is_runtime and severity == "MEDIUM":
        return "🟠 Lv.4 Medium (中程度)", "warning" # 黄色

    # Lv.5: Development環境 または Low/Local
    if scope == "DEVELOPMENT":
        return "🛠 Lv.5 Dev Dependency (開発環境)", "#439FE0" # 青
    
    # Lv.6: その他 (Lowなど)
    return "⚪ Lv.6 Low/Info (低リスク)", "#808080" # グレー

# --- GraphQL Query ---
QUERY_SCA = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 50) {
      nodes {
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

def run():
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN is not set.")
        return

    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME} (All Levels)...")
    notifications = []
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Security-Digest-Script"
    }
    
    kev_cves = get_cisa_kev_cves()

    # ==========================================
    # 1. SCA (Dependabot) Processing
    # ==========================================
    print("Fetching SCA (Dependabot) alerts...")
    variables = {"owner": REPO_OWNER, "name": REPO_NAME}
    
    data = http_request(
        "https://api.github.com/graphql",
        method="POST",
        headers=headers,
        data={"query": QUERY_SCA, "variables": variables}
    )
    
    if data and data.get("data") and data["data"].get("repository"):
        alerts = data["data"]["repository"].get("vulnerabilityAlerts", {}).get("nodes", [])
        print(f"  Found {len(alerts)} SCA entries.")
        
        for alert in alerts:
            if alert.get("state") != "OPEN":
                continue

            vuln = alert["securityVulnerability"]
            pkg_name = vuln["package"]["name"]
            severity = vuln["severity"]
            
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

            priority_label, color_style = calculate_priority(
                is_in_kev, raw_scope, vector_string, severity, epss, has_fix
            )

            # ---------------------------------------------------------
            # 【修正】以前の if (...) でのフィルタリングを削除しました。
            # 無条件ですべて通知リストに追加します。
            # ---------------------------------------------------------
            
            if is_in_kev:
                kev_display = "💀 Yes (悪用確認済)"
            else:
                kev_display = "🛡️ No (未掲載)"
            
            kev_header_info = " | 💀 CISA KEV" if is_in_kev else ""

            msg_text = f"""{priority_label}
📦 {pkg_name} ({severity}){kev_header_info}
────────────────
• Scope: {scope_display}
• Status: {fix_display}
📊 EPSS: {epss:.2%} / CVSS: {cvss_score}
🔗 {cve_id}"""

            msg = {
                "color": color_style,
                "text": msg_text
            }
            notifications.append(msg)
    else:
        # データが取れなかった場合のデバッグ用
        print("  No SCA data found. (Check permissions if count is 0 unexpectedly)")

    # ==========================================
    # 2. Slack通知 (分割送信対応)
    # ==========================================
    if notifications:
        total_count = len(notifications)
        print(f"Sending {total_count} alerts to Slack...")
        
        BATCH_SIZE = 40
        
        if SLACK_WEBHOOK_URL:
            for i in range(0, total_count, BATCH_SIZE):
                batch = notifications[i : i + BATCH_SIZE]
                current_batch_num = (i // BATCH_SIZE) + 1
                total_batches = (total_count + BATCH_SIZE - 1) // BATCH_SIZE
                
                blocks = [
                    {
                        "type": "header", 
                        "text": {
                            "type": "plain_text", 
                            "text": f"🛡️ Security Digest ({i+1}-{i+len(batch)}/{total_count})"
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
                print(f"  Sent batch {current_batch_num}/{total_batches}")
                time.sleep(1)
                
            print("Done.")
        else:
            print("Skipped Slack notification (URL not set).")
    else:
        print("Clean (No alerts found).")

if __name__ == "__main__":
    run()

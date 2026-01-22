import os
import requests
import json

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
REPO_NAME = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# 閾値設定
CVSS_THRESHOLD = 1.0
EPSS_THRESHOLD = 0.01  # 1%

# --- 関数: CISA KEVリストの取得 ---
def get_cisa_kev_cves():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print("Fetching CISA KEV Catalog...")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
            print(f"  Loaded {len(kev_set)} KEV entries.")
            return kev_set
    except Exception as e:
        print(f"  [KEV Error] Could not fetch KEV list: {e}")
    return set()

# --- 関数: EPSSスコアの取得 ---
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

# --- 関数: 優先度レベル判定ロジック ---
def calculate_priority(is_kev, scope, vector_string, severity, epss, has_fix):
    is_network = "AV:N" in vector_string
    
    # Lv.1: CISA KEV掲載
    if is_kev:
        return "🚨 *Lv.1 Emergency* (即時対応)", "danger"

    # Lv.2: Runtime × Network × (EPSS高 or Critical)
    is_runtime = (scope == "RUNTIME")
    
    if is_runtime and is_network and (epss >= EPSS_THRESHOLD):
        return "🔥 *Lv.2 Danger* (当日〜翌日)", "danger"
    
    # Lv.3: Runtime × Network × Critical (EPSS低)
    if is_runtime and is_network and severity == "CRITICAL":
        return "⚠️ *Lv.3 Warning* (週次監視)", "warning"

    # Lv.4: Dev環境 or Local攻撃
    if scope == "DEVELOPMENT" or not is_network:
        return "☕ *Lv.4 Periodic* (月次対応)", "good"
    
    return "👀 *Check Needed*", "default"

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
    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME}...")
    notifications = []
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    kev_cves = get_cisa_kev_cves()

    # ==========================================
    # 1. SCA (Dependabot) Processing
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
                pkg_name = vuln["package"]["name"]
                severity = vuln["severity"]
                
                # --- Scope (Runtime/Dev) ---
                raw_scope = alert.get("dependencyScope", "UNKNOWN")
                scope_display = "🚀 Runtime (本番)" if raw_scope == "RUNTIME" else "🛠 Dev (開発)"
                
                # --- Patch Status ---
                patched_ver = vuln.get("firstPatchedVersion")
                has_fix = True if patched_ver else False
                fix_display = f"✅ Fix: `{patched_ver['identifier']}`" if has_fix else "🚫 No Fix (パッチなし)"

                # --- CVSS & Vector ---
                advisory = vuln["advisory"]
                cvss_score = advisory["cvss"]["score"] if advisory["cvss"] else 0
                vector_string = advisory["cvss"]["vectorString"] if advisory["cvss"] else ""
                
                # --- Path (Attack Vector) ★ここを修正 ---
                # AV:N (Network) なら「地球儀(危険)」、それ以外なら「鍵(安全)」
                if "AV:N" in vector_string:
                    path_display = "🌐 Network (外部から攻撃可)"
                else:
                    path_display = "🔒 Local (内部のみ/安全)"

                # --- CVE & EPSS ---
                identifiers = advisory.get("identifiers", [])
                cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
                epss = get_epss_score(cve_id) if cve_id else 0
                is_in_kev = cve_id in kev_cves

                # --- 優先度判定 ---
                priority_label, color_style = calculate_priority(
                    is_in_kev, raw_scope, vector_string, severity, epss, has_fix
                )

                # 通知対象フィルタ
                if (priority_label.startswith("🚨") or 
                    priority_label.startswith("🔥") or 
                    priority_label.startswith("⚠️") or
                    severity in ["CRITICAL", "HIGH"]):
                    
                    kev_info = "\n💀 *CISA KEV (悪用事実あり)*" if is_in_kev else ""
                    
                    # ★ メッセージを見やすく整形 (改行と箇条書き) ★
                    msg_text = (
                        f"*{priority_label}*\n"
                        f"📦 *{pkg_name}* ({severity}){kev_info}\n"
                        f"────────────────\n"
                        f"• *Scope:* {scope_display}\n"
                        f"• *Path:* {path_display}\n"
                        f"• *Status:* {fix_display}\n"
                        f"\n"
                        f"📊 *Scores:*\n"
                        f"• EPSS: `{epss:.2%}`\n"
                        f"• CVSS: `{cvss_score}`\n"
                        f"🔗 {cve_id}"
                    )

                    msg = {
                        "color": color_style,
                        "text": msg_text
                    }
                    notifications.append(msg)

    except Exception as e:
        print(f"  [SCA Error] {e}")

    # ==========================================
    # 2. Slack通知 (Block Kit送信)
    # ==========================================
    if notifications:
        print(f"Sending {len(notifications)} alerts to Slack...")
        
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🛡️ Security Triage Digest"}},
            {"type": "divider"}
        ]
        
        for note in notifications[:40]: 
            # サイドカラーを示す絵文字
            color_emoji = "🔴" if note["color"] == "danger" else "🟡" if note["color"] == "warning" else "🔵"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{color_emoji} {note['text']}"
                }
            })
            blocks.append({"type": "divider"})

        payload = {"blocks": blocks}
        requests.post(SLACK_WEBHOOK_URL, json=payload)
        print("Done.")
    else:
        print("Clean.")

if __name__ == "__main__":
    run()

import os
import json
import urllib.request
import urllib.error
import urllib.parse
import time
from datetime import datetime

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# 実行モード: "immediate" (Lv1,2のみ) or "weekly" (全集計)
REPORT_MODE = os.getenv("REPORT_MODE", "immediate")

# 対象リポジトリ (カンマ区切り)
TARGET_REPOS_ENV = os.getenv("TARGET_REPOSITORIES", "")

# 閾値
CVSS_THRESHOLD = 7.0
EPSS_THRESHOLD = 0.01

# --- ヘルパー関数: HTTPリクエスト ---
def http_request(url, method="GET", headers=None, data=None, params=None):
    if headers is None: headers = {}
    if params: url = f"{url}?{urllib.parse.urlencode(params)}"
    
    req = urllib.request.Request(url, headers=headers, method=method)
    if data:
        req.data = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            body = res.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        print(f"  [HTTP Error] {e.code}: {e.reason} (URL: {url})")
        return None
    except Exception as e:
        print(f"  [Error] {e}")
        return None

# --- データ取得系関数 ---
def get_cisa_kev_cves():
    print("Fetching CISA KEV Catalog...")
    data = http_request("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    return {v["cveID"] for v in data.get("vulnerabilities", [])} if data else set()

def get_epss_score(cve_id):
    if not cve_id or not cve_id.startswith("CVE-"): return 0.0
    time.sleep(0.05)
    data = http_request("https://api.first.org/data/v1/epss", params={"cve": cve_id})
    try: return float(data["data"][0].get("epss", 0))
    except: return 0.0

# --- 優先度判定ロジック (統合版) ---
def calculate_priority(alert_type, severity, context=None):
    """
    alert_type: 'SCA', 'SAST', 'SECRET'
    severity: 'CRITICAL', 'HIGH', etc.
    context: dict (SCA用のKEV/EPSS情報など)
    """
    # 1. Secret Scanning -> Lv.1 (Emergency)
    if alert_type == 'SECRET':
        return "🚨 Lv.1 Emergency", "danger", 1

    # 2. SCA (Dependabot)
    if alert_type == 'SCA' and context:
        is_kev = context.get('is_kev', False)
        epss = context.get('epss', 0.0)
        is_runtime = context.get('scope') == 'RUNTIME'
        is_network = "AV:N" in (context.get('vector', "") or "")

        if is_kev:
            return "🚨 Lv.1 Emergency", "danger", 1
        if is_runtime and is_network and (epss >= EPSS_THRESHOLD):
            return "🔥 Lv.2 Danger", "danger", 2
        if is_runtime and is_network and severity in ["CRITICAL", "HIGH"]:
            return "⚠️ Lv.3 Warning", "warning", 3
        if context.get('scope') == "DEVELOPMENT" or not is_network:
            return "☕ Lv.4 Periodic", "good", 4
        return "👀 Check Needed", "default", 5

    # 3. SAST (Code Scanning)
    if alert_type == 'SAST':
        # ★修正: Critical -> Lv.1
        if severity == "CRITICAL":
            return "🚨 Lv.1 Emergency", "danger", 1
        # ★修正: High -> Lv.2
        if severity == "HIGH":
            return "🔥 Lv.2 Danger", "danger", 2
        
        # Medium以下
        return "☕ Lv.4 Periodic", "good", 4

    return "👀 Check Needed", "default", 5

# --- GraphQL Query (SCA/SAST/Secret 一括取得) ---
QUERY_ALL_ALERTS = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    # 1. SCA (Dependabot)
    vulnerabilityAlerts(first: 50, states: OPEN) { 
      nodes {
        createdAt
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
    # 2. SAST (Code Scanning)
    codeScanningAlerts(first: 50, state: OPEN) {
      nodes {
        createdAt
        url
        rule {
          securitySeverityLevel
          description
        }
        tool { name }
        mostRecentInstance {
          location { path }
        }
      }
    }
    # 3. Secret Scanning
    secretScanningAlerts(first: 50, state: OPEN) {
      nodes {
        createdAt
        url
        secretType
      }
    }
  }
}
"""

def check_repository(repo_full_name, headers, kev_cves):
    print(f"\nChecking {repo_full_name} ...")
    if "/" not in repo_full_name: return [], {"Lv.1":0, "Lv.2":0, "Lv.3":0, "Lv.4":0, "Other":0}
    
    owner, name = repo_full_name.split("/")
    repo_stats = {"Lv.1": 0, "Lv.2": 0, "Lv.3": 0, "Lv.4": 0, "Other": 0}
    immediate_alerts = []

    # GraphQL Request
    variables = {"owner": owner, "name": name}
    data = http_request("https://api.github.com/graphql", method="POST", headers=headers, 
                       data={"query": QUERY_ALL_ALERTS, "variables": variables})

    if not data or "errors" in data or not data.get("data", {}).get("repository"):
        print(f"  [Error] Failed to fetch data for {repo_full_name}")
        if "errors" in data: print(data["errors"])
        return [], repo_stats

    repo_data = data["data"]["repository"]

    # --- 1. SCA Processing ---
    sca_nodes = repo_data.get("vulnerabilityAlerts", {}).get("nodes", [])
    print(f"  Found {len(sca_nodes)} SCA alerts.")
    for item in sca_nodes:
        vuln = item["securityVulnerability"]
        advisory = vuln["advisory"]
        
        # Context作成
        identifiers = advisory.get("identifiers", [])
        cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
        epss = get_epss_score(cve_id)
        
        context = {
            "is_kev": cve_id in kev_cves,
            "epss": epss,
            "scope": item.get("dependencyScope", "UNKNOWN"),
            "vector": advisory["cvss"]["vectorString"] if advisory["cvss"] else ""
        }
        
        severity = vuln["severity"] # CRITICAL, HIGH...
        label, color, lv = calculate_priority("SCA", severity, context)
        
        # 集計
        key = f"Lv.{lv}" if lv <= 4 else "Other"
        repo_stats[key] += 1
        
        # 即時通知判定 (Lv.1, Lv.2)
        if REPORT_MODE == "immediate" and lv in [1, 2]:
            pkg = vuln["package"]["name"]
            fix = vuln["firstPatchedVersion"]["identifier"] if vuln["firstPatchedVersion"] else "No Fix"
            kev_mark = " | 💀 KEV" if context["is_kev"] else ""
            msg = f"📦 *SCA: {pkg}* ({severity}){kev_mark}\n📊 EPSS: {epss:.2%} | Fix: {fix}\n🔗 {cve_id}"
            immediate_alerts.append({"repo": repo_full_name, "color": color, "text": f"*{label}*\n{msg}"})

    # --- 2. SAST Processing ---
    sast_nodes = repo_data.get("codeScanningAlerts", {}).get("nodes", [])
    print(f"  Found {len(sast_nodes)} SAST alerts.")
    for item in sast_nodes:
        rule = item.get("rule", {})
        severity = rule.get("securitySeverityLevel", "UNKNOWN") # CRITICAL, HIGH...
        
        label, color, lv = calculate_priority("SAST", severity)
        
        # 集計
        key = f"Lv.{lv}" if lv <= 4 else "Other"
        repo_stats[key] += 1
        
        # 即時通知判定 (Lv.1, Lv.2)
        if REPORT_MODE == "immediate" and lv in [1, 2]:
            tool = item["tool"]["name"]
            path = item["mostRecentInstance"]["location"]["path"]
            desc = rule.get("description", "No description")
            url = item["url"]
            msg = f"🛡️ *SAST: {tool}* ({severity})\nFile: `{path}`\n📝 {desc}\n<{url}|View Alert>"
            immediate_alerts.append({"repo": repo_full_name, "color": color, "text": f"*{label}*\n{msg}"})

    # --- 3. Secret Processing ---
    secret_nodes = repo_data.get("secretScanningAlerts", {}).get("nodes", [])
    print(f"  Found {len(secret_nodes)} Secret alerts.")
    for item in secret_nodes:
        # Secretは常にLv.1
        label, color, lv = calculate_priority("SECRET", "CRITICAL")
        
        # 集計
        key = f"Lv.{lv}" if lv <= 4 else "Other"
        repo_stats[key] += 1
        
        # 即時通知判定
        if REPORT_MODE == "immediate" and lv in [1, 2]:
            s_type = item["secretType"]
            url = item["url"]
            msg = f"🔑 *Secret Detected* (CRITICAL)\nType: `{s_type}`\n<{url}|View Alert>"
            immediate_alerts.append({"repo": repo_full_name, "color": color, "text": f"*{label}*\n{msg}"})

    return immediate_alerts, repo_stats


def run():
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN is not set.")
        return

    # リポジトリリストの取得
    target_repos = [r.strip() for r in TARGET_REPOS_ENV.split(",") if r.strip()]
    if not target_repos:
        print("Error: TARGET_REPOSITORIES env is empty.")
        return

    print(f"Starting [{REPORT_MODE.upper()}] for {len(target_repos)} repos...")

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Security-Digest-Script"
    }

    kev_cves = get_cisa_kev_cves()
    
    all_immediate_alerts = []
    total_stats = {"Lv.1": 0, "Lv.2": 0, "Lv.3": 0, "Lv.4": 0, "Other": 0}

    # 各リポジトリをループ処理
    for repo in target_repos:
        alerts, stats = check_repository(repo, headers, kev_cves)
        
        all_immediate_alerts.extend(alerts)
        for k, v in stats.items():
            total_stats[k] += v
        
        time.sleep(1) # API負荷軽減

    # === 通知送信 ===
    if not SLACK_WEBHOOK_URL:
        print("Skipped Slack (No URL).")
        return

    # 1. Immediate Mode (Lv.1/Lv.2詳細)
    if REPORT_MODE == "immediate":
        if all_immediate_alerts:
            print(f"Sending {len(all_immediate_alerts)} urgent alerts...")
            BATCH_SIZE = 20
            for i in range(0, len(all_immediate_alerts), BATCH_SIZE):
                batch = all_immediate_alerts[i : i + BATCH_SIZE]
                blocks = [
                    {"type": "header", "text": {"type": "plain_text", "text": "🚨 Security Alert Digest (Lv.1/Lv.2)"}},
                    {"type": "divider"}
                ]
                for note in batch:
                    # リポジトリ名 + 内容
                    text = f"📂 *{note['repo']}*\n{note['text']}"
                    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
                    blocks.append({"type": "divider"})
                
                http_request(SLACK_WEBHOOK_URL, method="POST", data={"blocks": blocks})
                time.sleep(1)
        else:
            print("No active Lv.1/Lv.2 alerts found.")

    # 2. Weekly Mode (件数集計)
    elif REPORT_MODE == "weekly":
        total_count = sum(total_stats.values())
        print("Sending weekly summary...")
        
        summary_text = f"""*🛡️ Weekly Organization Security Report*
対象リポジトリ: {len(target_repos)}個
未解決アラート総数: {total_count}件

🚨 *Lv.1 Emergency:* {total_stats['Lv.1']}件 (Secrets / KEV / SAST Crit)
🔥 *Lv.2 Danger:* {total_stats['Lv.2']}件 (SAST High / High Risk SCA)
⚠️ *Lv.3 Warning:* {total_stats['Lv.3']}件
☕ *Lv.4 Periodic:* {total_stats['Lv.4']}件
"""
        color = "danger" if (total_stats['Lv.1'] > 0 or total_stats['Lv.2'] > 0) else "good"
        http_request(SLACK_WEBHOOK_URL, method="POST", data={"attachments": [{"color": color, "text": summary_text}]})

if __name__ == "__main__":
    run()

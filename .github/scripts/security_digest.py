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

# 実行モード
REPORT_MODE = os.getenv("REPORT_MODE", "immediate")

# 対象リポジトリ
TARGET_REPOS_ENV = os.getenv("TARGET_REPOSITORIES")
if not TARGET_REPOS_ENV:
    TARGET_REPOS_ENV = os.getenv("GITHUB_REPOSITORY")

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
        # タイムアウトを少し長めに設定
        with urllib.request.urlopen(req, timeout=30) as res:
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
    time.sleep(0.02) # 少しウェイトを入れる
    data = http_request("https://api.first.org/data/v1/epss", params={"cve": cve_id})
    try: return float(data["data"][0].get("epss", 0))
    except: return 0.0

# --- 優先度判定ロジック ---
def calculate_priority(alert_type, severity, context=None):
    # 1. Secret Scanning -> Lv.1
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
        if severity == "CRITICAL": return "🚨 Lv.1 Emergency", "danger", 1
        if severity == "HIGH": return "🔥 Lv.2 Danger", "danger", 2
        return "☕ Lv.4 Periodic", "good", 4

    return "👀 Check Needed", "default", 5

# --- GraphQL Queries (ページネーション対応のため分割) ---

# 1. SCA (Dependabot)
QUERY_SCA = """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 50, states: OPEN, after: $cursor) { 
      pageInfo { hasNextPage endCursor }
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
  }
}
"""

# 2. SAST
QUERY_SAST = """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    codeScanningAlerts(first: 50, state: OPEN, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        createdAt
        url
        rule { securitySeverityLevel description }
        tool { name }
        mostRecentInstance { location { path } }
      }
    }
  }
}
"""

# 3. Secret
QUERY_SECRET = """
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    secretScanningAlerts(first: 50, state: OPEN, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        createdAt
        url
        secretType
      }
    }
  }
}
"""

# --- Fetch Functions with Pagination ---
def fetch_paginated_data(query, owner, name, headers, extract_func):
    """汎用的なページネーション取得関数"""
    items = []
    cursor = None
    has_next = True
    
    while has_next:
        variables = {"owner": owner, "name": name, "cursor": cursor}
        data = http_request("https://api.github.com/graphql", method="POST", headers=headers, 
                           data={"query": query, "variables": variables})
        
        if not data or "errors" in data or not data.get("data", {}).get("repository"):
            if "errors" in data: print(f"    [GraphQL Error] {data['errors'][0]['message']}")
            break
            
        repo_data = data["data"]["repository"]
        # extract_funcを使って対象のデータを抜き出す (例: vulnerabilityAlerts)
        target_data = extract_func(repo_data)
        
        if not target_data: break
        
        # データを追加
        items.extend(target_data.get("nodes", []))
        
        # ページネーション情報の更新
        page_info = target_data.get("pageInfo", {})
        has_next = page_info.get("hasNextPage", False)
        cursor = page_info.get("endCursor")
        
        # API負荷軽減のため少し待つ
        if has_next: time.sleep(0.5)
        
    return items

def check_repository(repo_full_name, headers, kev_cves):
    print(f"\nChecking {repo_full_name} ...")
    if "/" not in repo_full_name: return [], {"Lv.1":0, "Lv.2":0, "Lv.3":0, "Lv.4":0, "Other":0}
    
    owner, name = repo_full_name.split("/")
    repo_stats = {"Lv.1": 0, "Lv.2": 0, "Lv.3": 0, "Lv.4": 0, "Other": 0}
    immediate_alerts = []

    # --- 1. SCA Processing ---
    print("  Fetching SCA...")
    sca_nodes = fetch_paginated_data(QUERY_SCA, owner, name, headers, lambda r: r.get("vulnerabilityAlerts"))
    print(f"    Total SCA alerts: {len(sca_nodes)}")
    
    for item in sca_nodes:
        vuln = item["securityVulnerability"]
        advisory = vuln["advisory"]
        identifiers = advisory.get("identifiers", [])
        cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
        
        # Context作成
        context = {
            "is_kev": cve_id in kev_cves,
            "epss": get_epss_score(cve_id),
            "scope": item.get("dependencyScope", "UNKNOWN"),
            "vector": advisory["cvss"]["vectorString"] if advisory["cvss"] else ""
        }
        severity = vuln["severity"]
        label, color, lv = calculate_priority("SCA", severity, context)
        
        key = f"Lv.{lv}" if lv <= 4 else "Other"
        repo_stats[key] += 1
        
        if REPORT_MODE == "immediate" and lv in [1, 2]:
            pkg = vuln["package"]["name"]
            fix = vuln["firstPatchedVersion"]["identifier"] if vuln["firstPatchedVersion"] else "No Fix"
            kev_mark = " | 💀 KEV" if context["is_kev"] else ""
            msg = f"📦 *SCA: {pkg}* ({severity}){kev_mark}\n📊 EPSS: {context['epss']:.2%} | Fix: {fix}\n🔗 {cve_id}"
            immediate_alerts.append({"repo": repo_full_name, "color": color, "text": f"*{label}*\n{msg}"})

    # --- 2. SAST Processing ---
    print("  Fetching SAST...")
    sast_nodes = fetch_paginated_data(QUERY_SAST, owner, name, headers, lambda r: r.get("codeScanningAlerts"))
    print(f"    Total SAST alerts: {len(sast_nodes)}")
    
    for item in sast_nodes:
        rule = item.get("rule", {})
        severity = rule.get("securitySeverityLevel", "UNKNOWN")
        label, color, lv = calculate_priority("SAST", severity)
        
        key = f"Lv.{lv}" if lv <= 4 else "Other"
        repo_stats[key] += 1
        
        if REPORT_MODE == "immediate" and lv in [1, 2]:
            tool = item["tool"]["name"]
            path = item["mostRecentInstance"]["location"]["path"]
            desc = rule.get("description", "No description")
            url = item["url"]
            msg = f"🛡️ *SAST: {tool}* ({severity})\nFile: `{path}`\n📝 {desc}\n<{url}|View Alert>"
            immediate_alerts.append({"repo": repo_full_name, "color": color, "text": f"*{label}*\n{msg}"})

    # --- 3. Secret Processing ---
    print("  Fetching Secrets...")
    secret_nodes = fetch_paginated_data(QUERY_SECRET, owner, name, headers, lambda r: r.get("secretScanningAlerts"))
    print(f"    Total Secret alerts: {len(secret_nodes)}")
    
    for item in secret_nodes:
        label, color, lv = calculate_priority("SECRET", "CRITICAL")
        key = f"Lv.{lv}" if lv <= 4 else "Other"
        repo_stats[key] += 1
        
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

    target_repos = [r.strip() for r in TARGET_REPOS_ENV.split(",") if r.strip()]
    if not target_repos:
        print("Error: No target repositories found.")
        return

    print(f"Starting [{REPORT_MODE.upper()}] for {len(target_repos)} repos...")

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Security-Digest-Script"
    }

    kev_cves = get_cisa_kev_cves()
    
    all_immediate_alerts = []
    total_stats

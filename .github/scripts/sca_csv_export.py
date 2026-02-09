import os
import json
import urllib.request
import urllib.error
import urllib.parse
import time
import csv
from datetime import datetime

# --- 設定 ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
# GITHUB_REPOSITORY環境変数からリポジトリ情報を取得
repo_env = os.getenv("GITHUB_REPOSITORY")
if repo_env and "/" in repo_env:
    REPO_OWNER, REPO_NAME = repo_env.split("/")
else:
    # 環境変数が取れない場合のフォールバック（必要に応じて調整）
    REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
    REPO_NAME = "unknown-repo"

# 閾値設定 (CSV出力用にはフィルタリングせず全件出力する場合が多いですが、ここでは元のロジックを尊重しつつ必要なら調整してください)
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

# --- GraphQL Query (ページネーション対応) ---
QUERY_SCA = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 100, after: $after) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        createdAt
        state
        dependencyScope
        number
        securityVulnerability {
          package { name }
          severity
          firstPatchedVersion { identifier }
          advisory {
            cvss { score vectorString }
            identifiers { type value }
            description
          }
        }
      }
    }
  }
}
"""

def get_all_sca_alerts(headers):
    all_alerts = []
    has_next_page = True
    end_cursor = None
    
    print(f"Fetching SCA (Dependabot) alerts for {REPO_OWNER}/{REPO_NAME}...")

    while has_next_page:
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
        has_next_page = page_info.get("hasNextPage", False)
        end_cursor = page_info.get("endCursor")
        
        print(f"  Fetched {len(nodes)} alerts... (Total: {len(all_alerts)})")
        
        if has_next_page:
            time.sleep(0.5) # レート制限対策

    return all_alerts

def run():
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN is not set.")
        return

    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME}...")
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Security-Digest-Script"
    }
    
    kev_cves = get_cisa_kev_cves()

    # 1. SCA (Dependabot) Processing (全件取得)
    alerts = get_all_sca_alerts(headers)
    
    # CSV出力用のリスト
    csv_rows = []
    today_str = datetime.now().strftime("%Y-%m-%d")

    if alerts:
        print(f"  Processing {len(alerts)} SCA entries...")
        
        for alert in alerts:
            # OPENなアラートのみ対象
            if alert.get("state") != "OPEN":
                continue

            vuln = alert["securityVulnerability"]
            pkg_name = vuln["package"]["name"]
            severity = vuln["severity"] # CRITICAL, HIGH, MEDIUM, LOW
            
            raw_scope = alert.get("dependencyScope", "UNKNOWN")
            
            patched_ver = vuln.get("firstPatchedVersion")
            has_fix = True if patched_ver else False
            
            advisory = vuln["advisory"]
            
            identifiers = advisory.get("identifiers", [])
            cve_id = next((i["value"] for i in identifiers if i["type"] == "CVE"), "")
            
            # 詳細情報の取得 (Descriptionなど)
            description = advisory.get("description", "")
            # タイトルとしてパッケージ名とCVEを使う
            title = f"{pkg_name} ({cve_id})" if cve_id else f"{pkg_name} ({severity})"

            # リンクの生成 (GitHub Security Tabへのリンク)
            alert_number = alert.get("number")
            alert_link = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/security/dependabot/{alert_number}"

            # ソース情報
            source = f"{REPO_OWNER}/{REPO_NAME}"

            # CSV行データの作成 (A列〜H列に対応)
            # A:Date, B:Status, C:Tool, D:Severity, E:Source, F:Title/Description, G:Link, H:Note
            csv_rows.append([
                today_str,          # Date
                "OPEN",             # Status
                "GHAS-SCA",         # Tool
                severity,           # Severity
                source,             # Source
                title,              # Title/Description
                alert_link,         # Link
                ""                  # Note (空欄)
            ])
            
            # APIレート制限考慮のためのsleep (大量にある場合は調整)
            # time.sleep(0.1) 
    else:
        print("  No SCA data found.")

    # CSVファイルへの書き出し
    output_filename = "sca_report.csv"
    
    # utf-8-sig を指定することで、Excelで開いた時の文字化けを防ぐ
    with open(output_filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        
        # ヘッダー書き込み (スプレッドシートの1行目と同じにする)
        writer.writerow(["Date", "Status", "Tool", "Severity", "Source", "Title/Description", "Link", "Note"])
        
        # データ書き込み
        writer.writerows(csv_rows)

    print(f"\n[Success] Report generated: {output_filename}")

if __name__ == "__main__":
    run()

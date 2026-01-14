import os
import requests
import json

# --- 設定 ---
# 取得するアラートの上限数
LIMIT = 100 
# EPSSスコアの閾値（0.01 = 1%。これ以上なら通知対象）
EPSS_THRESHOLD = 0.01 

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPOSITORY_OWNER")
REPO_NAME = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# --- GraphQL Query ---
QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 100, state: OPEN) {
      nodes {
        createdAt
        securityVulnerability {
          package { name }
          severity
          advisory {
            cvss { score }
            identifiers { type value }
            summary
          }
        }
      }
    }
    codeScanningAlerts(first: 100, state: OPEN) {
      nodes {
        createdAt
        rule {
          id
          securitySeverityLevel
          description
        }
        mostRecentInstance {
          location { path startLine }
        }
        tool { name }
        htmlUrl
      }
    }
  }
}
"""

def get_epss_score(cve_id):
    """CVE IDからEPSS(悪用確率)を取得する"""
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data"):
                return float(data["data"][0].get("epss", 0))
    except Exception as e:
        print(f"EPSS check failed for {cve_id}: {e}")
    return 0.0

def run():
    print(f"Starting security digest for {REPO_OWNER}/{REPO_NAME}...")
    
    if not SLACK_WEBHOOK_URL:
        print("Error: SLACK_WEBHOOK_URL is not set.")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # 1. GitHubからアラート取得
    resp = requests.post(
        "https://api.github.com/graphql",
        json={"query": QUERY, "variables": {"owner": REPO_OWNER, "name": REPO_NAME}},
        headers=headers
    )
    
    if resp.status_code != 200:
        print(f"GitHub API Error: {resp.text}")
        return

    data = resp.json()
    repo = data.get("data", {}).get("repository")
    
    if not repo:
        print("No repository data found or permission denied.")
        return

    messages = []

    # --- SCA (Dependabot) の処理 ---
    if "vulnerabilityAlerts" in repo:
        alerts_sca = repo["vulnerabilityAlerts"]["nodes"]
        for alert in alerts_sca:
            vuln = alert["securityVulnerability"]
            severity = vuln["severity"] # CRITICAL, HIGH, MODERATE, LOW
            
            # CVE IDを探す
            cve_id = next((i["value"] for i in vuln["advisory"]["identifiers"] if i["type"] == "CVE"), None)
            
            # EPSSスコア確認
            epss = get_epss_score(cve_id) if cve_id else 0
            
            # ★フィルタリング条件★
            # 「Critical」 または 「High かつ EPSSが1%以上」
            is_priority = (severity == "CRITICAL") or (severity == "HIGH" and epss >= EPSS_THRESHOLD)
            
            if is_priority:
                pkg = vuln["package"]["name"]
                score_txt = f"{epss*100:.2f}%" if epss > 0 else "N/A"
                summary = vuln['advisory']['summary']
                msg = f"📦 *{pkg}* ({severity})\n> CVE: {cve_id} | 悪用確率(EPSS): *{score_txt}*\n> 概要: {summary}"
                messages.append(msg)

    # --- SAST (Code Scanning) の処理 ---
    if "codeScanningAlerts" in repo:
        alerts_sast = repo["codeScanningAlerts"]["nodes"]
        for alert in alerts_sast:
            # ルールによってはsecuritySeverityLevelがない場合があるのでガード
            if not alert.get("rule") or not alert["rule"].get("securitySeverityLevel"):
                continue

            severity = alert["rule"]["securitySeverityLevel"] # CRITICAL, HIGH, etc.
            
            # ★フィルタリング条件★
            # Critical と High のみ通知
            if severity in ["CRITICAL", "HIGH"]:
                tool = alert["tool"]["name"]
                desc = alert["rule"]["description"]
                path = alert["mostRecentInstance"]["location"]["path"]
                line = alert["mostRecentInstance"]["location"]["startLine"]
                url = alert["htmlUrl"]
                
                msg = f"🛡️ *{tool}* ({severity})\n> File: `{path}:{line}`\n> 内容: <{url}|{desc}>"
                messages.append(msg)

    # --- Slack通知 ---
    if messages:
        print(f"Found {len(messages)} priority alerts.")
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 Security Digest: {REPO_NAME}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "担当者様、以下の優先アラートを確認・修正してください。"}
            },
            {"type": "divider"}
        ]
        
        # Slackは見やすさのため上位15件に制限
        for msg in messages[:15]:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": msg}
            })
            
        if len(messages) > 15:
             blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"...他 {len(messages)-15} 件のアラートがあります。GitHubを確認してください。"}
            })

        payload = {"blocks": blocks}
        requests.post(SLACK_WEBHOOK_URL, json=payload)
        print("Sent to Slack.")
    else:
        print("No priority alerts found. Good job!")

if __name__ == "__main__":
    run()

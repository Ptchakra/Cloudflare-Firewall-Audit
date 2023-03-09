from rich import print
import requests
import json
from datetime import datetime, timedelta

cookie = "REPLACE_WITH_YOUR_COOKIE"
account_id = "REPLACE_WITH_YOUR_ACCOUNT_ID"
api_token = "REPLACE_WITH_YOUR_TOKEN (permission: Zone Firewall service read)"


def rule_analyst(zone_id, rule_id, cookie, account_id):
    print("start rule analyst")
    url = "https://dash.cloudflare.com/api/v4/graphql"
    now = datetime.now()
    last_month = now - timedelta(days=30)
    now = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    last_month = last_month.strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = json.dumps(
        {
            "operationName": "GetFirewallAnalyticsTopNs",
            "variables": {
                "accountTag": account_id,
                "zoneTag": zone_id,
                "topN": 15,
                "filter": {
                    "AND": [
                        {
                            "datetime_geq": last_month,
                            "datetime_leq": now,
                        },
                        {"ruleId": rule_id},
                        {
                            "AND": [
                                {"action_neq": "challenge_solved"},
                                {"action_neq": "challenge_failed"},
                                {"action_neq": "challenge_bypassed"},
                                {"action_neq": "jschallenge_solved"},
                                {"action_neq": "jschallenge_failed"},
                                {"action_neq": "jschallenge_bypassed"},
                                {"action_neq": "managed_challenge_skipped"},
                                {
                                    "action_neq": "managed_challenge_non_interactive_solved"
                                },
                                {"action_neq": "managed_challenge_interactive_solved"},
                                {"action_neq": "managed_challenge_bypassed"},
                                {"action_neq": "managed_challenge_failed"},
                                {
                                    "OR": [
                                        {"ruleId_like": "999___"},
                                        {"ruleId_like": "900___"},
                                        {"ruleId": "981176"},
                                        {
                                            "AND": [
                                                {"ruleId_notlike": "9_____"},
                                                {"ruleId_notlike": "uri-9_____"},
                                            ]
                                        },
                                    ]
                                },
                            ]
                        },
                    ]
                },
            },
            "query": "query GetFirewallAnalyticsTopNs($zoneTag: string, $filter: FirewallEventsAdaptiveGroupsFilter_InputObject, $topN: int64!) {\n  viewer {\n    scope: zones(filter: {zoneTag: $zoneTag}) {\n      total: firewallEventsAdaptiveGroups(limit: 1, filter: $filter) {\n        count\n      }\n    }\n  }\n}\n",
        }
    )

    headers = {
        "authority": "dash.cloudflare.com",
        "accept": "*/*",
        "accept-language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "cookie": cookie,
        "origin": "https://dash.cloudflare.com",
        "pragma": "no-cache",
        "referer": "https://dash.cloudflare.com/",
        "sec-ch-ua": '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "x-atok": "1678333905-ATOK50c320e19e49c85c179ba9df969fd8f2d94ab0ff77a99b45",
        "x-cross-site-security": "dash",
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    print("rule analyst response", response)
    data = response.json()
    print("rule analyst result", data)

    if data.get("data").get("viewer").get("scope")[0].get("total"):
        return (
            data.get("data").get("viewer").get("scope")[0].get("total")[0].get("count")
        )
    return 0


def list_rule(zone_id: str, api_token: str):
    print("list rule", zone_id)
    page = 1
    rules = []
    while True:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules?per_page=100&page={page}"
        page += 1
        payload = {}
        headers = {
            "Authorization": f"Bearer {api_token}",
        }

        response = requests.request("GET", url, headers=headers, data=payload)
        print("list rule response", response)
        data = response.json()
        if data.get("result"):
            rules += data.get("result")
        else:
            break
    print(f"Total rules: {len(rules)}")
    return rules


if __name__ == "__main__":
    with open("./zones.json", "r") as f:
        zones = json.load(f)
    for zone in zones:
        print("zone", zone.get("name"))
        rules = list_rule(zone.get("id"), api_token)
        with open(f"./{zone.get('name')}_rules.json", "w") as f:
            json.dump(rules, f, indent=2)

        # analytics(zone.get("id"))
        rule_event_analytics = []
        for rule in rules:
            event_count = rule_analyst(
                zone.get("id"), rule.get("id"), cookie, account_id
            )
            rule[
                "link"
            ] = f"https://dash.cloudflare.com/e43e16e4aee1109ea4ef0ba80a7e015e/{zone.get('name')}/security/waf/firewall-rules/{rule.get('id')}"
            rule["count"] = event_count
            rule["filter"] = rule.get("filter").get("expression")
            rule_event_analytics.append(rule)

        with open(f"./{zone.get('name')}_rule_event_analytics.json", "w") as f:
            json.dump(rule_event_analytics, f, indent=2)

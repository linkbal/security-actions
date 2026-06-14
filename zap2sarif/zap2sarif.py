#!/usr/bin/env python3
"""Convert OWASP ZAP JSON report to SARIF 2.1.0."""
import json
import sys
from urllib.parse import urlparse


def url_to_relative_uri(url: str) -> str:
    """Convert URL to a relative URI path (strips scheme to avoid SARIF upload rejection)."""
    parsed = urlparse(url)
    # e.g. https://alb.machicon.jp/path -> alb.machicon.jp/path
    path = parsed.path.lstrip("/") or ""
    return f"{parsed.netloc}/{path}" if parsed.netloc else url

RISK_TO_LEVEL = {
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "none",
}

# Maps to GitHub Code Scanning severity: Critical(9+) High(7-8.9) Medium(4-6.9) Low(0.1-3.9)
RISK_TO_SECURITY_SEVERITY = {
    "High": "8.0",
    "Medium": "5.0",
    "Low": "2.0",
    "Informational": "0.0",
}


def convert(zap: dict) -> dict:
    rules = []
    results = []
    seen_rules: set[str] = set()

    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            rid = alert["pluginid"]
            if rid not in seen_rules:
                seen_rules.add(rid)
                risk_word = alert.get("riskdesc", "").split(" ")[0]
                level = RISK_TO_LEVEL.get(risk_word, "warning")
                rules.append({
                    "id": rid,
                    "name": alert["alert"],
                    "shortDescription": {"text": alert["alert"]},
                    "fullDescription": {"text": alert.get("desc", "")},
                    "defaultConfiguration": {"level": level},
                    "helpUri": alert.get("reference", ""),
                    "properties": {
                        "security-severity": RISK_TO_SECURITY_SEVERITY.get(risk_word, "0.0"),
                        "tags": ["security"],
                    },
                })

            instances = alert.get("instances") or [{"uri": site["@name"]}]
            for inst in instances:
                results.append({
                    "ruleId": rid,
                    "message": {"text": alert.get("desc", "")[:512]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": url_to_relative_uri(inst.get("uri", ""))},
                            "region": {"startLine": 1},
                        }
                    }],
                })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "OWASP ZAP",
                "informationUri": "https://www.zaproxy.org/",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else "report_json.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "zap-results.sarif"

    with open(input_file) as f:
        zap = json.load(f)

    sarif = convert(zap)

    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)

    n_results = len(sarif["runs"][0]["results"])
    n_rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])
    print(f"Converted: {n_results} results, {n_rules} rules -> {output_file}")


if __name__ == "__main__":
    main()

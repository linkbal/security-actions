#!/usr/bin/env python3
"""Convert nmap XML output (with vulners script) to SARIF 2.1.0."""
import json
import sys
import xml.etree.ElementTree as ET


def parse_vulners(script_elem):
    """Extract CVE entries from vulners script output."""
    cves = []
    for table in script_elem.findall("table"):
        for entry in table.findall("table"):
            elems = {e.get("key"): e.text for e in entry.findall("elem")}
            cve_id = elems.get("id", "")
            if cve_id.startswith("CVE-"):
                cves.append({
                    "id": cve_id,
                    "cvss": float(elems.get("cvss", "0")),
                })
    return cves


def convert(xml_file: str) -> dict:
    tree = ET.parse(xml_file)
    root = tree.getroot()

    rules = []
    results = []
    seen_rules: set[str] = set()

    for host in root.findall("host"):
        addr = host.find("address").get("addr", "unknown")
        for port_elem in host.findall("ports/port"):
            portid = port_elem.get("portid")
            proto = port_elem.get("protocol", "tcp")
            service = port_elem.find("service")
            svc_name = service.get("name", "") if service is not None else ""
            svc_product = service.get("product", "") if service is not None else ""
            svc_version = service.get("version", "") if service is not None else ""
            svc_label = f"{svc_product} {svc_version}".strip() or svc_name

            script = port_elem.find("script[@id='vulners']")
            if script is None:
                continue

            cves = parse_vulners(script)
            for cve in cves:
                rid = cve["id"]
                cvss = cve["cvss"]

                if rid not in seen_rules:
                    seen_rules.add(rid)
                    if cvss >= 7.0:
                        level = "error"
                    elif cvss >= 4.0:
                        level = "warning"
                    else:
                        level = "note"
                    rules.append({
                        "id": rid,
                        "name": rid,
                        "shortDescription": {"text": f"{rid} ({svc_label})"},
                        "defaultConfiguration": {"level": level},
                        "helpUri": f"https://nvd.nist.gov/vuln/detail/{rid}",
                        "properties": {
                            "security-severity": str(cvss),
                            "tags": ["security"],
                        },
                    })

                results.append({
                    "ruleId": rid,
                    "message": {"text": f"{rid} (CVSS {cvss}) on {addr}:{portid}/{proto} ({svc_label})"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"{addr}/{proto}/{portid}"},
                            "region": {"startLine": 1},
                        }
                    }],
                })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "nmap",
                "informationUri": "https://nmap.org/",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def main():
    xml_file = sys.argv[1] if len(sys.argv) > 1 else "nmap-results.xml"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "nmap-results.sarif"

    sarif = convert(xml_file)

    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)

    n_results = len(sarif["runs"][0]["results"])
    n_rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])
    print(f"Converted: {n_results} results, {n_rules} rules -> {output_file}")


if __name__ == "__main__":
    main()

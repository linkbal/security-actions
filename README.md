# zap2sarif

Convert [OWASP ZAP](https://www.zaproxy.org/) JSON report to SARIF 2.1.0 and upload to GitHub Code Scanning.

## Usage

```yaml
- name: Run ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.15.0
  with:
    target: https://example.com
    allow_issue_writing: false
    fail_action: false

- name: Upload ZAP results to Code Scanning
  uses: linkbal/zap2sarif@main
  with:
    category: zap-example.com  # distinguish multiple targets
```

## Inputs

| Input | Description | Default |
|---|---|---|
| `json_report` | Path to ZAP JSON report | `report_json.json` |
| `sarif_output` | Path for SARIF output file | `zap-results.sarif` |
| `category` | Category for Code Scanning | `zap` |

## Notes

- Requires `security-events: write` permission.
- When scanning multiple targets, set a unique `category` per target to avoid results overwriting each other.

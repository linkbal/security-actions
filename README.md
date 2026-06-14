# security-actions

Security scan result converters for GitHub Code Scanning.

## Actions

### zap2sarif

Convert OWASP ZAP JSON report to SARIF.

```yaml
- uses: linkbal/security-actions/zap2sarif@v1
  with:
    category: zap-scan
```

### nmap2sarif

Convert nmap XML output (with `--script vulners`) to SARIF.

```yaml
- uses: linkbal/security-actions/nmap2sarif@v1
  with:
    category: nmap-scan
```

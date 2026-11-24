# Splunk: Rapid7 VM CVE Response

- `rapid7_vm_cve/` the Splunk app source (install guide and test plan: `rapid7_vm_cve/README.md`)
- `dist/rapid7_vm_cve-1.1.0.tgz` the installable package
- `tests/` unit and end-to-end tests (simulated Rapid7 console and splunkd)

Build and test:

```bash
python3 -m unittest discover -s splunk/tests -v
cd splunk && tar --exclude="__pycache__" --exclude="local" -czf dist/rapid7_vm_cve-1.1.0.tgz rapid7_vm_cve
```

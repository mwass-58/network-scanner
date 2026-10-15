import glob
import json
import os
import sys
from datetime import datetime

# port -> (severity, advice)
RISKS = {
    21: ("High", "FTP sends passwords in clear text. Use SFTP instead."),
    23: ("High", "Telnet is unencrypted. Use SSH instead."),
    445: ("High", "SMB file sharing is a common attack target. Restrict access."),
    139: ("Medium", "NetBIOS exposes system information. Disable it if unused."),
    110: ("Medium", "POP3 sends mail logins in clear text. Use POP3S."),
    143: ("Medium", "IMAP can send logins in clear text. Use IMAPS."),
    3389: ("Medium", "Remote Desktop should not be open to the network."),
    3306: ("Medium", "Database port is reachable. Allow only the app server."),
    5432: ("Medium", "Database port is reachable. Allow only the app server."),
    80: ("Low", "HTTP is not encrypted. Consider HTTPS (port 443)."),
    8000: ("Low", "Alternative web port. Check that it is meant to be open."),
    8080: ("Low", "Alternative web port. Check that it is meant to be open."),
    22: ("Info", "SSH is encrypted. Use strong passwords or key login."),
    53: ("Info", "DNS service. Expected on a router or DNS server."),
}
ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def latest_json():
    """Find the newest scan file in the results folder."""
    files = sorted(glob.glob("results/scan_*.json"))
    return files[-1] if files else None


def find_issues(hosts):
    """Check every open port and collect the findings."""
    issues = []
    for h in hosts:
        for s in h["services"]:
            if s["port"] in RISKS:
                level, advice = RISKS[s["port"]]
                issues.append((level, h["host"], s["port"], s["service"], advice))
            if any(ch.isdigit() for ch in s["banner"]):
                note = (f"Banner shows the software version ({s['banner']}). "
                        "Attackers use versions to look up known flaws.")
                issues.append(("Low", h["host"], s["port"], s["service"], note))
    issues.sort(key=lambda i: ORDER[i[0]])
    return issues


def build_report(data, source):
    hosts = data["hosts"]
    total_ports = sum(len(h["services"]) for h in hosts)
    issues = find_issues(hosts)

    lines = []
    lines.append("=" * 60)
    lines.append("NETWORK SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Target:        {data['target']}")
    lines.append(f"Scanned at:    {data['scanned_at']}")
    lines.append(f"Report made:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Source file:   {source}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 60)
    lines.append(f"Live hosts found:  {len(hosts)}")
    lines.append(f"Open ports found:  {total_ports}")
    for level in ("High", "Medium", "Low", "Info"):
        count = sum(1 for i in issues if i[0] == level)
        lines.append(f"{level + ' findings:':<19}{count}")
    lines.append("")
    lines.append("HOSTS AND SERVICES")
    lines.append("-" * 60)
    for h in hosts:
        lines.append(h["host"])
        if not h["services"]:
            lines.append("  no open ports")
        for s in h["services"]:
            lines.append(f"  {s['port']:<7}{s['service']:<11}{s['banner']}")
        lines.append("")
    lines.append("FINDINGS (most serious first)")
    lines.append("-" * 60)
    if not issues:
        lines.append("No findings.")
    for level, host, port, service, advice in issues:
        lines.append(f"[{level}] {host} port {port} ({service})")
        lines.append(f"       {advice}")
    lines.append("")
    return lines


if __name__ == "__main__":
    source = sys.argv[1] if len(sys.argv) > 1 else latest_json()
    if not source or not os.path.exists(source):
        print("No scan file found. Run scanner.py first.")
        sys.exit(1)

    with open(source) as f:
        data = json.load(f)

    lines = build_report(data, source)
    text = "\n".join(lines)
    print(text)

    report_path = source.replace("scan_", "report_").replace(".json", ".txt")
    with open(report_path, "w") as f:
        f.write(text)
    print(f"Report saved to {report_path}")

import json
from collections import Counter, defaultdict
from datetime import datetime

LOGFILE = "honeypot_log.jsonl"
REPORT = "auto_incident_report.md"
PRIVILEGED = {"root", "admin", "administrator"}
LEVELS = ["LOW", "MEDIUM", "HIGH"]


def load_events():
    events = []
    try:
        with open(LOGFILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # skip broken lines
    except FileNotFoundError:
        print(f"Cannot find {LOGFILE}. Run honeypot.py first.")
    return events


def analyze(events):
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    findings = []
    for ip, items in by_ip.items():
        attempts = len(items)
        users = Counter(e["username"] for e in items)
        passwords = {e["password"] for e in items}
        times = sorted(datetime.strptime(e["time"], "%Y-%m-%d %H:%M:%S") for e in items)
        seconds = (times[-1] - times[0]).total_seconds()
        hit_privileged = any(u.lower() in PRIVILEGED for u in users)

        # Decide what kind of attack this looks like
        if attempts < 5:
            name, mitre = "Suspicious login attempts", "T1110 (Brute Force)"
        elif len(users) >= 3:
            name, mitre = "Password Spraying", "T1110.003"
        else:
            name, mitre = "Password Guessing (Brute Force)", "T1110.001"

        # Severity: more attempts = worse, and targeting root/admin adds one level
        level = 0 if attempts < 5 else 1 if attempts < 20 else 2
        if hit_privileged:
            level = min(level + 1, 2)

        steps = [
            f"Check whether {ip} is a known or expected address",
            "Block the IP at the firewall if it is not trusted",
            "Check logs for any successful login from this IP",
            "Disable password login for SSH and use keys instead",
        ]
        if hit_privileged:
            steps.insert(1, "Make sure root login over SSH is disabled")
        if len(users) >= 3:
            steps.append("Check the other accounts that were tried for weak passwords")

        findings.append({
            "ip": ip, "attempts": attempts, "users": users,
            "unique_passwords": len(passwords), "first": times[0],
            "last": times[-1], "seconds": seconds, "name": name,
            "mitre": mitre, "severity": LEVELS[level], "steps": steps,
        })

    findings.sort(key=lambda f: -f["attempts"])
    return findings


def write_report(findings):
    lines = ["# Automatic Incident Report", ""]
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Sources analysed: {len(findings)}")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"## Incident {i}: {f['name']}")
        lines.append(f"- **Severity:** {f['severity']}")
        lines.append(f"- **MITRE ATT&CK:** {f['mitre']}")
        lines.append(f"- **Source IP:** {f['ip']}")
        lines.append(f"- **Attempts:** {f['attempts']} in {int(f['seconds'])} seconds")
        lines.append(f"- **First seen:** {f['first']}")
        lines.append(f"- **Last seen:** {f['last']}")
        lines.append(f"- **Different passwords tried:** {f['unique_passwords']}")
        top = ", ".join(f"{u} ({c})" for u, c in f["users"].most_common(5))
        lines.append(f"- **Usernames targeted:** {top}")
        lines.append("")
        lines.append("**What to do next:**")
        for s in f["steps"]:
            lines.append(f"- {s}")
        lines.append("")
    lines.append("*Note: passwords are not stored in this report on purpose.*")
    text = "\n".join(lines)
    with open(REPORT, "w") as out:
        out.write(text + "\n")
    return text


def main():
    events = load_events()
    if not events:
        print("No events found.")
        return
    findings = analyze(events)
    print(write_report(findings))
    print(f"\nReport saved to {REPORT}")


if __name__ == "__main__":
    main()

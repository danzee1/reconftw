import json
import os
import sys
from datetime import datetime

def get_file_lines(filepath):
    try:
        if not os.path.exists(filepath):
            return 0
        with open(filepath, 'r') as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0

def get_findings(nuclei_dir):
    findings = []
    severities = ['critical', 'high', 'medium', 'low', 'info']
    if not os.path.exists(nuclei_dir):
        return []
    for sev in severities:
        path = os.path.join(nuclei_dir, f"{sev}.txt")
        if os.path.exists(path):
            with open(path, 'r') as f:
                for line in f:
                    parts = line.strip().split(' ')
                    if len(parts) >= 4:
                        findings.append({
                            "type": parts[0].strip('[]'),
                            "finding": parts[-1],
                            "severity": sev
                        })
    return findings[:20]

def main():
    if len(sys.argv) < 3:
        sys.exit(1)

    domain = sys.argv[1]
    recon_dir = sys.argv[2]
    template_path = sys.argv[3]

    stats = {
        "subdomains": get_file_lines(os.path.join(recon_dir, "subdomains/subdomains.txt")),
        "webs": get_file_lines(os.path.join(recon_dir, "webs/webs_all.txt")),
        "vulns": 0,
        "secrets": 0
    }

    vulns = {
        "critical": get_file_lines(os.path.join(recon_dir, "nuclei_output/critical.txt")),
        "high": get_file_lines(os.path.join(recon_dir, "nuclei_output/high.txt")),
        "medium": get_file_lines(os.path.join(recon_dir, "nuclei_output/medium.txt")),
        "low": get_file_lines(os.path.join(recon_dir, "nuclei_output/low.txt")),
        "info": get_file_lines(os.path.join(recon_dir, "nuclei_output/info.txt"))
    }
    stats["vulns"] = sum(vulns.values())

    recent_findings = get_findings(os.path.join(recon_dir, "nuclei_output"))

    assets = []
    subdomains_path = os.path.join(recon_dir, "subdomains/subdomains.txt")
    if os.path.exists(subdomains_path):
        with open(subdomains_path, 'r') as f:
            assets = [line.strip() for line in f if line.strip()][:15]

    leaks = []
    truffle_path = os.path.join(recon_dir, "js/js_secrets_trufflehog.json")
    if os.path.exists(truffle_path):
        with open(truffle_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    leaks.append({"type": "Trufflehog Secret", "content": data.get('Raw', 'Secret found')})
                except:
                    continue

    jsluice_path = os.path.join(recon_dir, "js/js_secrets_jsluice.json")
    if os.path.exists(jsluice_path):
        with open(jsluice_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    leaks.append({"type": "jsluice Secret", "content": data.get('kind', 'Secret found')})
                except:
                    continue

    stats["secrets"] = len(leaks)

    scan_data = {
        "domain": domain,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats,
        "vulns": vulns,
        "recentFindings": recent_findings,
        "assets": assets,
        "leaks": leaks[:10]
    }

    if not os.path.exists(template_path):
        sys.exit(1)

    with open(template_path, 'r') as f:
        template = f.read()

    output_html = template.replace('const scanData = {"domain":"Loading..."}; // DATA_INJECTION_POINT', f'const scanData = {json.dumps(scan_data, indent=4)};')

    with open(os.path.join(recon_dir, "dashboard.html"), 'w') as f:
        f.write(output_html)

if __name__ == "__main__":
    main()

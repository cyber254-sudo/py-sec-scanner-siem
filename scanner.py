import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import sys
import json
import requests

# ANSI Color Codes for cool terminal styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def banner():
    print(f"""{CYAN}
   ___                  _              _   _                  
  / __> ___  ___  _ _  | |_  ___  _ _ | | | | ___  ___  _ _  
 | (__ / -_)/ . || '_| |  _|/ ._>| '_|| |_| |/ ._>/ . \| ' \ 
  \___j\___|\___\|_|   |_|  \___.|_|   \___/ \___.\___/|_||_|
    Python CLI Security & Reconnaissance Scanner v1.0
{RESET}""")

def scan_port(target_ip, port):
    """Checks if a specific TCP port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        result = s.connect_ex((target_ip, port))
        s.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None

def run_port_scanner(target_ip, ports):
    print(f"\n{YELLOW}[*] Starting TCP Port Scan on {target_ip}{RESET}")
    print(f"[*] Time started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in ports}
        for future in futures:
            port = future.result()
            if port:
                print(f"{GREEN}[+] Port {port} (OPEN){RESET}")
                open_ports.append(port)

    print("-" * 50)
    print(f"{YELLOW}[*] Port scan complete. Found {len(open_ports)} open port(s).{RESET}\n")
    return open_ports

def audit_security_headers(target_url):
    """Audits HTTP response headers and returns structured findings."""
    print(f"\n{YELLOW}[*] Starting HTTP Security Header Audit on {target_url}{RESET}")
    print("-" * 50)

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    important_headers = {
        "Strict-Transport-Security": "HSTS missing (Vulnerable to downgrade attacks)",
        "Content-Security-Policy": "CSP missing (Vulnerable to XSS and data injection)",
        "X-Frame-Options": "X-Frame-Options missing (Vulnerable to Clickjacking)",
        "X-Content-Type-Options": "X-Content-Type-Options missing (Vulnerable to MIME-sniffing)",
        "Server": "Server banner disclosure (Reveals technology version details)"
    }

    audit_results = {"final_url": target_url, "status_code": None, "headers": []}

    try:
        response = requests.get(target_url, timeout=5, allow_redirects=True)
        audit_results["final_url"] = response.url
        audit_results["status_code"] = response.status_code
        headers = response.headers
        
        print(f"{CYAN}[i] Final URL: {response.url} (Status Code: {response.status_code}){RESET}\n")

        for header, warning_msg in important_headers.items():
            if header in headers:
                status_desc = f"Present: {headers[header]}"
                print(f"{GREEN}[+] Present: {header} = {headers[header]}{RESET}")
                audit_results["headers"].append({"header": header, "status": "PRESENT", "value": headers[header]})
            else:
                print(f"{RED}[!] Missing: {header} -> {warning_msg}{RESET}")
                audit_results["headers"].append({"header": header, "status": "MISSING", "description": warning_msg})

    except requests.exceptions.ConnectionError:
        print(f"{RED}[!] Connection Refused: The target is not hosting a web server on this port or blocking web traffic.{RESET}")
        audit_results["error"] = "Connection Refused"
    except requests.exceptions.Timeout:
        print(f"{RED}[!] Error: The connection timed out while trying to reach the target.{RESET}")
        audit_results["error"] = "Connection Timeout"
    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] Error connecting to target for header audit: {e}{RESET}")
        audit_results["error"] = str(e)
    
    print("-" * 50)
    print(f"{YELLOW}[*] Header audit complete.{RESET}\n")
    return audit_results

def fuzz_directories(target_url):
    """Probes web targets for hidden directories and returns discovered paths."""
    print(f"\n{YELLOW}[*] Starting Directory / Endpoint Fuzzing on {target_url}{RESET}")
    print("-" * 50)

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    target_url = target_url.rstrip("/")
    common_paths = [
        "admin", "administrator", "login", "dashboard", "api", 
        "backup.sql", "config.json", ".env", "robots.txt", 
        "sitemap.xml", "server-status", "test", "wp-login.php"
    ]

    discovered_endpoints = []
    for path in common_paths:
        test_url = f"{target_url}/{path}"
        try:
            response = requests.get(test_url, timeout=3, allow_redirects=False)
            
            if response.status_code == 200:
                print(f"{GREEN}[+] Found (200 OK): {test_url}{RESET}")
                discovered_endpoints.append({"url": test_url, "status": 200, "type": "OK"})
            elif response.status_code in [301, 302]:
                print(f"{YELLOW}[+] Found Redirect ({response.status_code}): {test_url}{RESET}")
                discovered_endpoints.append({"url": test_url, "status": response.status_code, "type": "REDIRECT"})
            elif response.status_code == 403:
                print(f"{CYAN}[!] Forbidden (403 Protected): {test_url}{RESET}")
                discovered_endpoints.append({"url": test_url, "status": 403, "type": "FORBIDDEN"})
        except requests.exceptions.RequestException:
            pass

    print("-" * 50)
    print(f"{YELLOW}[*] Fuzzing complete. Discovered {len(discovered_endpoints)} potential endpoint(s).{RESET}\n")
    return discovered_endpoints

def export_report(report_data, output_filename):
    """Exports structured scan data to a JSON or styled HTML file."""
    try:
        if output_filename.endswith(".json"):
            with open(output_filename, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)
            print(f"{GREEN}[+] JSON Security Report successfully saved to: {output_filename}{RESET}")

        elif output_filename.endswith(".html"):
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Reconnaissance Report - {report_data['target']}</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100 font-sans p-8">
    <div class="max-w-4xl mx-auto space-y-6">
        <header class="border-b border-gray-800 pb-4">
            <h1 class="text-3xl font-bold text-emerald-400">Security Reconnaissance Report</h1>
            <p class="text-gray-400 text-sm mt-1">Target: <span class="text-white font-mono">{report_data['target']}</span> ({report_data['target_ip']})</p>
            <p class="text-gray-400 text-sm">Scan Timestamp: {report_data['timestamp']}</p>
        </header>

        <section class="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <h2 class="text-xl font-semibold mb-3 text-amber-400">Open TCP Ports</h2>
            <div class="flex flex-wrap gap-2">
                {"".join([f'<span class="px-3 py-1 bg-emerald-950 text-emerald-400 border border-emerald-800 rounded font-mono text-sm">Port {p}</span>' for p in report_data['open_ports']]) if report_data['open_ports'] else '<p class="text-gray-500 italic">No open ports found or scanned.</p>'}
            </div>
        </section>

        <section class="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <h2 class="text-xl font-semibold mb-3 text-indigo-400">HTTP Security Headers</h2>
            <ul class="space-y-2">
                {"".join([f'<li class="p-2.5 rounded bg-gray-950 border border-gray-800 flex justify-between items-center"><span class="font-mono text-sm">{h["header"]}</span><span class="px-2 py-0.5 rounded text-xs font-semibold {'bg-emerald-950 text-emerald-400 border border-emerald-800' if h["status"]=='PRESENT' else 'bg-rose-950 text-rose-400 border border-rose-800'}">{h["status"]}</span></li>' for h in report_data.get('headers', {}).get('headers', [])]) if report_data.get('headers', {}).get('headers') else '<p class="text-gray-500 italic">Header audit was not executed or failed.</p>'}
            </ul>
        </section>

        <section class="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <h2 class="text-xl font-semibold mb-3 text-cyan-400">Discovered Endpoints / Fuzzing</h2>
            <ul class="space-y-2">
                {"".join([f'<li class="p-2.5 rounded bg-gray-950 border border-gray-800 flex justify-between items-center"><a href="{e["url"]}" target="_blank" class="font-mono text-sm text-cyan-400 hover:underline">{e["url"]}</a><span class="px-2 py-0.5 rounded text-xs font-semibold bg-blue-950 text-blue-400 border border-blue-800">{e["status"]} {e["type"]}</span></li>' for e in report_data.get('fuzzing', [])]) if report_data.get('fuzzing') else '<p class="text-gray-500 italic">No sensitive endpoints discovered or fuzzing not executed.</p>'}
            </ul>
        </section>
    </div>
</body>
</html>"""
            with open(output_filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"{GREEN}[+] Styled HTML Security Report successfully saved to: {output_filename}{RESET}")
        else:
            print(f"{RED}[!] Error: Output file must end with either .json or .html{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving report file: {e}{RESET}")

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="A powerful command-line security and reconnaissance scanner.")
    parser.add_argument("target", help="Target domain or IP address to scan")
    parser.add_argument("-p", "--ports", type=str, default="21,22,23,25,53,80,110,443,445,3306,3389,8080",
                        help="Comma-separated ports or range (e.g., 80,443,8080)")
    parser.add_argument("--headers", action="store_true", help="Perform an HTTP security header audit on the target")
    parser.add_argument("--fuzz", action="store_true", help="Perform a directory/endpoint fuzzing scan on the target web app")
    parser.add_argument("-o", "--output", type=str, help="Export results to a file (e.g., report.json or report.html)")
    
    args = parser.parse_args()

    # Resolve target domain to IP for port scanning
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{RED}[!] Error: Could not resolve hostname {args.target}{RESET}")
        sys.exit(1)

    # Parse port arguments
    ports_to_scan = []
    try:
        if "," in args.ports:
            ports_to_scan = [int(p.strip()) for p in args.ports.split(",")]
        else:
            ports_to_scan = [int(args.ports)]
    except ValueError:
        print(f"{RED}[!] Error: Invalid port format. Use comma-separated numbers.{RESET}")
        sys.exit(1)

    # Initialize master report dictionary
    report_data = {
        "target": args.target,
        "target_ip": target_ip,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": [],
        "headers": {},
        "fuzzing": []
    }

    # Execute Phase 1: Port Scanning
    report_data["open_ports"] = run_port_scanner(target_ip, ports_to_scan)

    # Execute Phase 2: Header Audit (if requested)
    if args.headers:
        report_data["headers"] = audit_security_headers(args.target)

    # Execute Phase 3: Directory Fuzzing (if requested)
    if args.fuzz:
        report_data["fuzzing"] = fuzz_directories(args.target)

    # Execute Phase 4: Export Report (if requested via -o flag)
    if args.output:
        export_report(report_data, args.output)

if __name__ == "__main__":
    main()
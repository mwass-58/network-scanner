import csv
import ipaddress
import json
import os
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


# ---------- Step 2: host discovery ----------
def is_alive(ip):
    """Send one ping. Return True if the host answers."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def discover_hosts(network):
    """Ping every address in the network and return the live ones."""
    addresses = list(ipaddress.ip_network(network, strict=False).hosts())
    with ThreadPoolExecutor(max_workers=50) as pool:
        answers = list(pool.map(is_alive, addresses))
    return [str(ip) for ip, alive in zip(addresses, answers) if alive]


# ---------- Step 3: port scanning ----------
def scan_port(ip, port, timeout=0.5):
    """Try to connect to one port. Return True if it is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def scan_host(ip, ports):
    """Check many ports on one host at the same time. Return the open ones."""
    ports = list(ports)
    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(lambda p: scan_port(ip, p), ports))
    return [p for p, is_open in zip(ports, results) if is_open]


def parse_ports(text):
    """Turn '1-1024' or '22,80,443' into a list of port numbers."""
    if "-" in text:
        start, end = text.split("-")
        return list(range(int(start), int(end) + 1))
    return [int(p) for p in text.split(",")]


# ---------- Step 4: service detection ----------
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8000: "HTTP-alt", 8080: "HTTP-alt",
}
HTTP_PORTS = {80, 8000, 8080}


def grab_banner(ip, port, timeout=1.0):
    """Connect and read what the service says about itself."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                s.sendall(request.encode())
            data = s.recv(1024).decode(errors="ignore")
    except Exception:
        return ""

    lines = data.strip().splitlines()
    if port in HTTP_PORTS:
        for line in lines:
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
    return lines[0] if lines else ""


def detect_service(ip, port):
    """Return the port, a service name guess, and the banner."""
    return {
        "port": port,
        "service": COMMON_SERVICES.get(port, "unknown"),
        "banner": grab_banner(ip, port),
    }


# ---------- Step 5: result export ----------
def collect_results(target, ports):
    """Run the whole scan and return the findings as a list."""
    results = []
    for host in discover_hosts(target):
        open_ports = scan_host(host, ports)
        services = [detect_service(host, p) for p in open_ports]
        results.append({"host": host, "services": services})
    return results


def export_json(results, path, target, scanned_at):
    """Save the results as a JSON file."""
    data = {"target": target, "scanned_at": scanned_at, "hosts": results}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def export_csv(results, path):
    """Save the results as a CSV table: one row per open port."""
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "port", "service", "banner"])
        for entry in results:
            for svc in entry["services"]:
                writer.writerow(
                    [entry["host"], svc["port"], svc["service"], svc["banner"]]
                )


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.122.0/24"
    ports = parse_ports(sys.argv[2]) if len(sys.argv) > 2 else range(1, 1025)

    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Scanning {target} ...")
    results = collect_results(target, ports)
    print(f"Found {len(results)} live host(s)\n")

    for entry in results:
        print(entry["host"])
        if not entry["services"]:
            print("  no open ports found\n")
            continue
        print(f"  {'PORT':<7}{'SERVICE':<11}BANNER")
        for svc in entry["services"]:
            print(f"  {svc['port']:<7}{svc['service']:<11}{svc['banner']}")
        print()

    os.makedirs("results", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"results/scan_{stamp}.json"
    csv_path = f"results/scan_{stamp}.csv"
    export_json(results, json_path, target, scanned_at)
    export_csv(results, csv_path)
    print(f"Results saved to {json_path}")
    print(f"Results saved to {csv_path}")

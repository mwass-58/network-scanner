import argparse
import os
from datetime import datetime

import report
import scanner


def main():
    parser = argparse.ArgumentParser(
        description="Simple network scanner for your own lab network."
    )
    parser.add_argument("-t", "--target", default="192.168.122.0/24",
                        help="network to scan, e.g. 192.168.122.0/24")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="ports to scan, e.g. 1-1024 or 22,80,443")
    parser.add_argument("--no-report", action="store_true",
                        help="save scan files only, skip the text report")
    args = parser.parse_args()

    ports = scanner.parse_ports(args.ports)
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"Scanning {args.target} (ports {args.ports}) ...")
    results = scanner.collect_results(args.target, ports)
    print(f"Found {len(results)} live host(s)")

    os.makedirs("results", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"results/scan_{stamp}.json"
    csv_path = f"results/scan_{stamp}.csv"
    scanner.export_json(results, json_path, args.target, scanned_at)
    scanner.export_csv(results, csv_path)
    print(f"Saved {json_path}")
    print(f"Saved {csv_path}")

    if args.no_report:
        return

    data = {"target": args.target, "scanned_at": scanned_at, "hosts": results}
    text = "\n".join(report.build_report(data, json_path))
    print()
    print(text)
    report_path = f"results/report_{stamp}.txt"
    with open(report_path, "w") as f:
        f.write(text)
    print(f"Saved {report_path}")


if __name__ == "__main__":
    main()

# Network Scanner

A simple Python network scanner for use on your own lab network.
Built as a learning project in cybersecurity.

## Features

- Host discovery (ping sweep)
- TCP port scanning (multi-threaded)
- Service detection (port lookup and banner grabbing)
- Result export to JSON and CSV
- Text report with severity-rated findings

## Legal notice

Only scan networks you own or have written permission to test.
Unauthorized scanning can be illegal.

## Requirements

- Linux with Python 3.8 or newer
- No external libraries (standard library only)

## Usage

    python netscan.py                              # scan 192.168.122.0/24, ports 1-1024
    python netscan.py -t 192.168.56.0/24           # choose a network
    python netscan.py -t 192.168.122.0/24 -p 22,80 # choose ports
    python netscan.py --no-report                  # export files only

Results are saved to the `results/` folder:

- `scan_<time>.json` full scan data
- `scan_<time>.csv` one row per open port
- `report_<time>.txt` summary and findings

## Lab setup

Tested against an Ubuntu Server 26.04 VM (Apache and SSH) running on
KVM/virt-manager, on the default libvirt network (192.168.122.0/24).

cd ~/network-scanner
exit
x

g
# Network Scanner

A simple Python network scanner for use on your own lab network.
Built as a learning project in cybersecurity.

## Features

- Host discovery (ping sweep)
- TCP port scanning (multi-threaded)
- Service detection (port lookup and banner grabbing)
- Result export to JSON and CSV
- Text report with severity-rated findings

## Legal notice

Only scan networks you own or have written permission to test.
Unauthorized scanning can be illegal.

## Requirements

- Linux with Python 3.8 or newer
- No external libraries (standard library only)

## Usage

    python netscan.py                              # scan 192.168.122.0/24, ports 1-1024
    python netscan.py -t 192.168.56.0/24           # choose a network
    python netscan.py -t 192.168.122.0/24 -p 22,80 # choose ports
    python netscan.py --no-report                  # export files only

Results are saved to the `results/` folder:

- `scan_<time>.json` full scan data
- `scan_<time>.csv` one row per open port
- `report_<time>.txt` summary and findings

## Lab setup

Tested against an Ubuntu Server 26.04 VM (Apache and SSH) running on
KVM/virt-manager, on the default libvirt network (192.168.122.0/24).

## How it works

1. `scanner.py` pings every address, then tries a TCP connection to each port.
2. For open ports it reads the service banner to identify the software.
3. `report.py` rates each finding (High, Medium, Low, Info) with advice.
4. `netscan.py` ties them together with a command-line interface.

## Limitations

- TCP connect scan only (no UDP, no stealth scanning)
- Hosts that block ping are not discovered
- Service detection covers common ports and basic banners

## Author

Patrick Mwangi Mwaniki

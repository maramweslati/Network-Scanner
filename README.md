# Network Scanner & Security Dashboard

## Project Overview

Network Scanner & Security Dashboard is a Python-based network reconnaissance tool that performs ARP-based host discovery and open port detection on a local network, with a graphical dashboard for visualizing results. The project was built to provide a lightweight, self-contained alternative to standard scanning tools, implementing the underlying network logic directly rather than wrapping an existing utility.

## Features

- Active host discovery on the local network via ARP scanning
- Open port detection on discovered hosts
- Graphical dashboard displaying scan results
- Flagging of commonly targeted high-risk ports (e.g. SMB, RDP, Telnet)
- Windows compatibility (Windows 10/11) through Scapy and Npcap integration

## Tech Stack

- **Python** — core implementation language
- **Scapy** — packet crafting and transmission for ARP requests and TCP probing
- **Npcap** — low-level packet capture driver required by Scapy on Windows

## Architecture

The tool follows a linear pipeline: the GUI triggers a scan request, the scanning module sends ARP requests to enumerate active hosts, then probes each discovered host for open ports using Scapy, and returns structured results to the dashboard for display.

```
GUI Dashboard --> Scan Controller --> ARP Discovery (Scapy/Npcap) --> Port Scan --> Results --> GUI Dashboard
```

## Project Structure

```
network-scanner/
    src/            Core scanning logic (ARP discovery, port scanning)
    gui/             Dashboard interface components
    docs/            Project documentation
    requirements.txt
    README.md
```

## Installation and Setup

### Prerequisites

- Python 3.x
- Npcap installed (required by Scapy on Windows)
- Administrator privileges (required for raw packet operations)

### Setup

```
git clone https://github.com/<username>/network-scanner.git
cd network-scanner
pip install -r requirements.txt
```

### Running the tool

```
python main.py
```

The application must be run with administrator privileges to perform ARP and raw packet operations.

## Usage

The user launches the application with administrator rights, selects the target network interface, and initiates a scan. The tool first performs ARP discovery to identify active hosts, then scans each host for open ports. Results are displayed in the dashboard, with high-risk ports highlighted for review.

## Engineering Decisions

Scapy was chosen over higher-level scanning libraries to allow direct control over packet construction and to demonstrate a working understanding of ARP and TCP mechanics rather than relying on an abstraction layer. Npcap was required to work around Windows' lack of native raw socket support, which Linux-based scanning tools do not need to handle. The dashboard layer was added to convert raw scan output into an interpretable interface, rather than leaving results as command-line text.

## Security Considerations

The scanner flags ports commonly associated with exploitation or misconfiguration risk, including SMB (139/445), RDP (3389), Telnet (23), FTP (21), and database ports such as MySQL (3306) and MongoDB (27017) when exposed. These are surfaced in the dashboard to support a basic security assessment of the scanned network, rather than reporting raw port state alone.

## Testing

Manual testing was performed against a local network to validate ARP discovery accuracy and port scan results.

## Limitations and Future Improvements

The tool currently supports Windows only (10/11), due to its dependency on Npcap. Planned improvements include service and version detection, exportable scan reports, and cross-platform support.

---

This project was developed as part of a Bachelor's degree in Information and Communication Technology, network security specialization, at ISET'COM.

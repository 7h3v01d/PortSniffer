## Network Traffic Insight Platform (PortSniffer v2.2)

### Overview

PortSniffer is a desktop-based network traffic inspection and observability platform designed for authorized diagnostic, monitoring, and educational environments.

The application provides structured packet capture, protocol-level inspection, traffic summarization, and export capabilities through a controlled graphical interface. It is intended for use in managed IT, security research, and controlled lab environments.

This platform emphasizes:

- Defensive analysis
- Operational visibility
- Responsible usage
- Compliance-aware deployment

It does not provide offensive or exploit capabilities.

### Key Capabilities

Real-Time Observability

- Live packet capture
- Protocol-level filtering (TCP, UDP, ICMP, ARP)
- Structured packet inspection view
- Traffic statistics and session visibility

### Export & Reporting

- PCAP export for interoperability with tools such as Wireshark
- CSV export for reporting and analytics workflows
- Structured logging support

### Operational Monitoring

- Basic anomaly indicators
- Network flow summaries
- System resource monitoring integration

### Architecture & Technology

- Python 3.9+
- PyQt6 (User Interface Layer)
- Scapy (Packet decoding and capture
- psutil (System telemetry integration)

The architecture is modular and designed to support controlled feature expansion without introducing exploit-based functionality.

### Deployment Requirements

- Windows or Linux
- Administrative / root privileges required for packet capture
- Python 3.9 or newer

### Installation:
```bash
pip install -r requirements.txt
python main.py
```
Governance & Responsible Use Policy

This software captures and processes live network traffic.

Use is strictly limited to:

Networks you own

Networks you administer

Networks where you have explicit written authorization to monitor

Unauthorized interception of communications may violate:

Telecommunications legislation

Privacy laws

Data protection regulations

Corporate policy frameworks

Users are responsible for ensuring compliance with applicable laws and internal governance policies.

The author and contributors accept no liability for misuse.

Security & Data Handling Considerations

Captured traffic may contain sensitive information, including:

Credentials

Authentication tokens

Personal data

Internal infrastructure metadata

Organizations deploying this platform should:

Apply appropriate data retention controls

Secure exported capture files

Restrict access to authorized personnel

Comply with relevant privacy regulations

Intended Use Cases

- Enterprise network diagnostics

- Security operations visibility (non-intrusive)

- Academic protocol analysis

- Lab-based cybersecurity training

Application debugging and traffic tracing

### Explicit Non-Goals

This platform does not:

- Perform active network exploitation
- Conduct vulnerability scanning
- Inject packets or payloads
- Bypass network controls
- Facilitate unauthorized surveillance

It is a passive analysis tool only.

### License

MIT License
See the LICENSE file for full terms.

### Disclaimer

This project is provided “as-is” without warranty of any kind, express or implied.
All usage must comply with applicable laws and regulations.

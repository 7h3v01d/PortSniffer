Changelog
All notable changes to the PortSniffer project will be documented in this file. The format is based on Keep a Changelog, and this project adheres to semantic versioning.
[Unreleased]
Added

Initial project structure with gui.py and network_monitor.py.
Real-time packet capture and display using Scapy and PyQt6.
Visualization features: Network Flow Graph, Packet Size Histogram, and Packet Rate Plot.
Export options for CSV, PCAP, and traffic summaries.
Filter presets and alert rule management.

Changed

Optimized GUI responsiveness by increasing timer interval to 200ms and batching updates to 100 packets.

Fixed

Resolved "Header Info" not displaying by adding "N/A" fallback in gui.py.

[0.1.0] - 2025-08-30
Added

Initial release of PortSniffer with core network monitoring functionality.
Support for filtering by IP, port, and protocol.
Packet details dialog for in-depth inspection.
Alert rules with color highlighting (e.g., HTTP status codes >= 400).
Correlation IDs for tracking packet flows.

Changed

Updated network_monitor.py to include QFileDialog import for file export functionality.
Improved packet processing in packet_callback to handle TCP, UDP, ICMP, and DNS protocols.

Fixed

Added missing QFileDialog import in network_monitor.py to resolve "QFileDialog not defined" error.
Added missing QInputDialog import in network_monitor.py to resolve "QInputDialog not defined" error during packet replay.

Notes

Initial version assumes a development environment with Python 3.9+ and required dependencies (PyQt6, Scapy, psutil).
Tested on Windows with Visual Studio; compatibility with macOS and Linux may vary.

[0.0.1] - 2025-08-01 (Assumed Initial Development Start)
Added

Basic project skeleton with placeholder files for gui.py and network_monitor.py.
Initial setup for packet queue and monitoring thread.

Notes

This version is assumed as the starting point based on development progression. No functional code was present at this stage.


Notes

Versioning:

[0.0.1] is an assumed initial development start date (August 1, 2025) since no prior history was provided.
[0.1.0] marks the first functional release with the fixes and features up to August 30, 2025.
[Unreleased] section is for future changes.


Date: All changes are timestamped with the current date (August 30, 2025) based on our interactions.
Structure: Follows Keep a Changelog conventions with Added, Changed, Fixed, and Notes sections.
Customization: Replace [Your Name or Team Name] or add specific commit hashes/SHA if you use Git. If hosted on GitHub, you can link to commits or pull requests.
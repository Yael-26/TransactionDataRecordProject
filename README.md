# Transaction Data Record (TDR) System

## Overview

This project was developed as part of the Allot Smart Bootcamp.

The system analyzes network traffic captured in PCAP files and generates detailed Transaction Data Records (TDRs) for video streaming sessions.

The project focuses on identifying video connections, tracking transactions within each connection, collecting network statistics, and exporting the results into structured CSV reports.

---

## Features

### PCAP Traffic Analysis

- Parse network traffic from PCAP files
- Support Ethernet, IPv4 and UDP packets
- Process real-world YouTube traffic captures

### Connection Identification

Connections are identified using the standard 5-Tuple:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol

### Transaction Detection

The system:

- Detects video connections
- Identifies transaction boundaries
- Tracks transaction lifecycle
- Associates packets with the correct transaction

### Statistics Collection

For each transaction the system collects:

- Transaction ID
- Connection ID
- RTT
- Packet counts
- Packet size statistics
- Timing information
- Inbound and outbound traffic metrics

### Report Generation

The collected statistics are exported into CSV files for further analysis.

---

## Technologies

- C
- PCAP
- Network Programming
- TCP/IP
- UDP
- Data Structures
- Performance Optimization

---

## Learning Outcomes

This project provided hands-on experience with:

- Network traffic analysis
- Packet parsing
- Connection tracking
- Streaming traffic analysis
- Low-level systems programming
- Performance-oriented software development

---

## Author

Yael Yosef

# Home SIEM/SOC Lab: Multi-Node Wazuh Deployment for Attack Detection and Incident Investigation

A home Security Operations Center (SOC) lab built on Wazuh. The lab collects endpoint telemetry, detects suspicious activity, and documents each investigation as a separate exercise.

## Architecture

```mermaid
flowchart LR
    subgraph EP["Monitored endpoints"]
        A["kakarot<br/>Kali Linux 2025.1 <br/>192.168.245.129<br/>Wazuh agent 4.8.2"]
        B["anonymous<br/>windows10<br/>192.168.245.137<br/>Wazuh agent 4.8.2"]
        C["plan"]
    end

    subgraph WS["Wazuh stack"]
        M["Wazuh manager<br/>wazuhserver (node01)<br/>rules and decoders"]
        F["Filebeat"]
        I["Wazuh indexer<br/>wazuh-alerts-* index"]
        D["Wazuh dashboard"]
    end

    U["SOC analyst<br/>browser"]

    A -- "events, 1514/tcp" --> M
    B -- "events" --> M
    C -- "events" --> M
    M -- "alerts" --> F
    F --> I
    I --> D
    U -- "HTTPS" --> D
```

### Data flow
1. The Wazuh agent on each endpoint collects logs, file integrity data, and system inventory.
2. The agent sends events to the Wazuh manager (default port 1514/tcp, enrollment on 1515/tcp).
3. The manager decodes each event and matches it against its ruleset. Matches become alerts with a rule ID and severity level.
4. Filebeat ships the alerts to the Wazuh indexer, where they are stored in the `wazuh-alerts-*` index.
5. The analyst opens the Wazuh dashboard to search alerts, review endpoints, and investigate.

## Lab components

| Component | Role | OS / Version | IP address |
|---|---|---|---|
| Wazuh manager (`wazuhserver`, node01) | Receives events, applies rules, generates alerts | TODO | TODO |
| Wazuh indexer | Stores and indexes alerts | TODO | TODO |
| Wazuh dashboard | Web interface for the analyst | TODO | TODO |
| Endpoint: kakarot | Monitored host, agent ID 010/suricata IDS | Kali GNU/Linux 2025.1, agent v4.8.2 | 192.168.245.129 |
| Endpoint: anonymouse | Monitored host, agent ID 009 | windows10 | 192.168.245.137|
| Endpoint: ubuntu server | wazuh-index/wazuh-manager/wazuh-dashboard | ubuntu server(wazuh monitoring) | 192.168.245.136 |

## Network
- Virtualization platform: TODO (for example VMware Workstation or VirtualBox)
- Network mode: TODO (for example host-only or NAT)
- Subnet: `192.168.245.0/24` (confirm this matches your setup)

## Exercises

| # | Exercise | Wazuh module | Status |
|---|---|---|---|
| 1 | [File Integrity Monitoring](File-Integrity-Monitoring-Lab/README.md) | Syscheck | Done |
| 2 | [dectecting network intrusion using suricata IDS]() | monitoring and give an alert if malicious traffic find in network | Done |
| 3 |[Linux Command Auditing with auditd and Wazuh]()| finding both legitimate and malicious command using auditd | Done |

## Skills demonstrated
- Deploying and configuring Wazuh manager, indexer, dashboard, and agents
- Enrolling and troubleshooting agents
- Configuring real-time file integrity monitoring
- Reading and analyzing alerts, rule IDs, and severity levels
- Mapping alerts to compliance controls (PCI DSS, NIST 800-53, GDPR, HIPAA)
- Installing, running, and checking Suricata as a systemd service (`systemctl status`, `restart`)
- Reading Suricata's file layout: `suricata.yaml`, `classification.config`, `threshold.config`, and the `rules` directory
- Downloading, extracting, and installing Emerging Threats Open rules, and setting file permissions (`chmod 640`)
- Running TCP SYN, TCP connect, version (`-sV`), OS (`-O`), and UDP scans with Nmap
- Reading Nmap output to find open ports, service versions, and OS guesses
- Understanding how an IDS sees network traffic, including why a scan from the host to itself may not reach an `eth0` capture
- Reading Suricata alert names such as stream "out of window" alerts and ICMP anomalies
- Finding Suricata rules in the Wazuh ruleset (86600 to 86604) and knowing which one reports alerts (86601)
- Searching and filtering alerts in Wazuh Threat Hunting by agent and time range, and expanding an alert to read its fields


## Repository structure
```
.
├── README.md
└── File-Integrity-Monitoring-Lab/
    ├── README.md
    └── screenshots/
└── detecting network intrusion using suricata IDS/
    ├── README.md
    └── screenshots/
└── Linux Command Auditing with auditd and Wazuh/
    ├── README.md
    └── screenshots/
```

## Author
Himavanth
M.Sc. Cybersecurity, JSS Science and Technology University, Mysuru

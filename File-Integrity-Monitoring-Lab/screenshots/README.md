# Intrusion Detection with Suricata IDS and Wazuh

## Overview
This lab runs Suricata as a network intrusion detection system (IDS) on a Kali Linux host, generates scan traffic with Nmap, and reviews the resulting alerts in the Wazuh dashboard. It covers three parts: confirming Suricata is running, producing test traffic, and tracing the alerts into Wazuh using the built-in Suricata ruleset (rule IDs 86600 to 86604).

## Lab environment
| Component | Details |
|---|---|
| Host | kakarot, Kali GNU/Linux 2025.1 |
| Interface | eth0, 192.168.245.129/24 |
| IDS | Suricata (systemd service, AF_PACKET capture mode) |
| Config | `/etc/suricata/suricata.yaml` |
| Rules directory | `/etc/suricata/rules` |
| Scanner | Nmap 7.95 |
| SIEM | Wazuh agent v4.8.2 (agent ID 010), manager `wazuhserver` |

## Objectives
- Verify Suricata is installed and running as a service
- Generate TCP and UDP scan traffic against the host
- Add the Emerging Threats Open ruleset
- Confirm Wazuh decodes Suricata alerts and shows them in the dashboard
- Read the alerts and identify what each signature means

## Steps

### 1. Confirm the network interface
`ifconfig` shows `eth0` at 192.168.245.129. This is the address I scanned and the interface Suricata monitors.

![ifconfig output](screenshots/01-network-interface-ifconfig.png)

### 2. Check the Suricata service
```bash
sudo systemctl status suricata
```
The service is `enabled` and `active (running)`. It runs as `/usr/bin/suricata -D --af-packet -c /etc/suricata/suricata.yaml`.

![Suricata status](screenshots/02-suricata-service-status.png)

### 3. Generate scan traffic with Nmap

**SYN scan**
```bash
nmap -sS 192.168.245.129
```
Three ports are open: 22 (ssh), 80 (http), 443 (https). The other 997 are closed.

![SYN scan command](screenshots/03-nmap-syn-scan-command.png)
![SYN scan results](screenshots/04-nmap-syn-scan-results.png)

**TCP connect scan with version and OS detection**
```bash
nmap -sT -sV -O 192.168.245.129
```
| Port | Service | Version |
|---|---|---|
| 22/tcp | ssh | OpenSSH 9.9p1 Debian 3 |
| 80/tcp | http | Apache httpd 2.4.65 |
| 443/tcp | ssl/https | Not recognized by Nmap. The service returned JSON error responses (401 Unauthorized, 404 Not Found). |

Nmap guessed the OS as Linux 5.0 to 6.2 and reported 0 network hops, since the target is the local machine.

![Version scan](screenshots/05-nmap-tcp-version-os-scan.png)
![OS detection output](screenshots/06-nmap-os-detection-output.png)

**UDP scan**
```bash
nmap -sU -O 192.168.245.129
```
One open UDP port was found: 5353 (zeroconf, mDNS). The other 999 were closed. Nmap could not pick a single OS match from the UDP results.

![UDP scan](screenshots/07-nmap-udp-scan.png)

### 4. Add the Emerging Threats Open rules
The default `/etc/suricata/rules` folder only held protocol event rules (`stream-events.rules`, `http-events.rules`, `dns-events.rules`, and similar). I downloaded the Emerging Threats Open ruleset and copied it in:

```bash
cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/
sudo chmod 640 /etc/suricata/rules/*.rules
```

![Rules download](screenshots/08-emerging-threats-rules-download.png)

### 5. Restart Suricata to load the rules
```bash
sudo systemctl restart suricata
```

![Suricata restart](screenshots/09-suricata-restart.png)

### 6. Check the Suricata rules in Wazuh
Wazuh ships a ruleset for Suricata in `0475-suricata_rules.xml` (path `ruleset/rules`). It has five rules:

| Rule ID | Description | Level |
|---|---|---|
| 86600 | Suricata messages | 0 |
| 86601 | Suricata: Alert - alert.signature | 3 |
| 86602 | Suricata: HTTP | 0 |
| 86603 | Suricata: DNS | 0 |
| 86604 | Suricata: TLS | 0 |

Every Suricata signature that fires is reported to Wazuh through rule 86601 at level 3, with the signature name in the description.

![Wazuh Suricata rules](screenshots/10-wazuh-suricata-rules.jpeg)

### 7. Review the alerts in the Wazuh dashboard
In Threat Hunting, filtered to agent `kakarot` (010), the last 24 hours show 141 hits.

![Alerts list](screenshots/11-wazuh-suricata-alerts.jpeg)

Signatures seen in the list:
| Signature | Rule |
|---|---|
| SURICATA STREAM CLOSEWAIT FIN out of window | 86601 |
| SURICATA STREAM FIN out of window | 86601 |
| SURICATA STREAM ESTABLISHED packet out of window | 86601 |
| SURICATA ICMPv4 unknown code | 86601 |
| SURICATA HTTP Response excessive header repetition | 86601 |

Expanding an alert shows the full document, including the Suricata fields under `data.alert.*`, the flow, and the source and destination.

![Expanded alert](screenshots/12-wazuh-alert-expanded.jpeg)

## Findings
- The Suricata to Wazuh path works. Alerts appear under rule 86601 with the signature text in the description.
- The alerts in my screenshots are stream and protocol anomaly signatures, not Emerging Threats scan signatures. "Out of window" alerts mean Suricata saw TCP packets that did not fit the tracked connection state. Port scans and rapid connection resets commonly cause this.
- All alerts are level 3 in Wazuh, so by default they are low-priority and need tuning before they would page an analyst.

## Limitations
- I scanned the host from itself. Traffic to a local address stays on the loopback interface, which an AF_PACKET capture on `eth0` normally does not see. A cleaner test scans from a second machine on the same network.
- The rules URL points to the Suricata 6.0.8 ruleset. If the installed Suricata is a newer major version, use `suricata-update` so the rules match the engine.
- My alert screenshots start at 14:27, after the 13:39 to 13:47 scans. The scan to alert link is therefore by behavior, not by matching timestamps.

## What I learned
- Suricata alerts only as well as its ruleset. The default folder has protocol event rules, and Emerging Threats adds the attack and scan signatures.
- Wazuh groups all Suricata alerts under one rule (86601), so analysts filter on `data.alert.signature` to tell them apart.
- Stream anomaly alerts are common and noisy. They need a baseline before they mean anything.

## Next steps
- Run the scan from a second VM so Suricata sees real network traffic
- Update rules with `suricata-update` and confirm Emerging Threats scan signatures fire
- Filter Wazuh alerts by `data.alert.signature` and `data.src_ip` to build a scan detection view
- Write a Wazuh custom rule that raises severity for repeated scan alerts from one source
- Map the detections to MITRE ATT&CK (Reconnaissance, T1046 Network Service Discovery)

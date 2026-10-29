# File Integrity Monitoring (FIM) with Wazuh

## Overview
This lab uses the Wazuh syscheck module to detect file changes on a Kali Linux endpoint in real time. I created a test file in `/root` and traced the alert from the agent to the Wazuh dashboard, then looked up the rule that fired.

## Lab environment
| Component | Details |
|---|---|
| Endpoint | Kali GNU/Linux 2025.1 (agent name: kakarot, ID 010) |
| Agent IP | 192.168.245.129 |
| Agent version | Wazuh v4.8.2 |
| Manager | wazuhserver (node01) |
| Module | Syscheck (File Integrity Monitoring) |

## Objectives
- Configure real-time file monitoring on `/root`
- Generate a file change event
- Find and analyze the alert in the Wazuh dashboard
- Identify the rule that fired, its severity, and its compliance mappings

## Steps

### 1. Configure syscheck
I edited `/var/ossec/etc/ossec.conf`. Syscheck is enabled, the default scan frequency is 43200 seconds (12 hours), and `scan_on_start` is set to yes. I added `/root` as a real-time monitored directory with change reporting:

```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
```

![ossec.conf syscheck block](screenshots/01-ossec-conf-syscheck.png)

### 2. Restart the agent
```bash
systemctl restart wazuh-agent
systemctl status wazuh-agent
```
The service came back as `active (running)` with `wazuh-syscheckd` among its processes.

![Agent restart](screenshots/02-wazuh-agent-restart.png)

### 3. Trigger an event
I created an empty file inside the monitored directory:

```bash
touch /root/simple.txt
```

![Test file creation](screenshots/03-create-test-file.png)

### 4. Confirm the agent is connected
The Endpoints page shows agent `kakarot` (010) with status active.

![Agent active in dashboard](screenshots/04-agent-active.jpeg)

### 5. Review the alert in Wazuh
The File Integrity Monitoring dashboard showed no results for the last 15 minutes, so I opened the Events tab. It listed 2 hits.

![FIM dashboard with no results](screenshots/05-fim-dashboard-empty.jpeg)
![FIM events, 2 hits](screenshots/06-fim-events-2-hits.jpeg)

## Findings
| Field | Value |
|---|---|
| Path | `/root/simple.txt` |
| Event | added |
| Mode | realtime |
| Rule ID | 554 |
| Rule description | File added to the system |
| Rule level | 5 |
| Decoder | syscheck_new_entry |
| Size | 0 bytes |
| Owner | root (uid 0, gid 0) |
| Permissions | rw-r--r-- |
| MD5 | d41d8cd98f00b204e9800998ecf8427e |
| SHA1 | da39a3ee5e6b4b0d3255bfef95601890afd80709 |

The MD5 and SHA1 values are the standard hashes of an empty file, which matches the 0 byte size.

![Expanded alert for rule 554](screenshots/07-alert-554-expanded.jpeg)

The second hit was rule 550 (integrity checksum changed, level 7) on a file under `/root/.local/state/wireplumber/`. That is background activity from a system service, not something I triggered.

### Rule 554 details
Rule 554 lives in `0015-ossec_rules.xml` under `ruleset/rules` and belongs to the groups `syscheck`, `syscheck_entry_added`, `syscheck_file`, and `ossec`.

![Rule 554 details](screenshots/08-rule-554-details.jpeg)

### Related FIM rules
| Rule | Meaning | Level |
|---|---|---|
| 550 | Integrity checksum changed | 7 |
| 553 | File deleted | 7 |
| 554 | File added to the system | 5 |

![Related rules](screenshots/09-related-rules.jpeg)

## Compliance mapping
Rule 554 maps to PCI DSS 11.5, NIST 800-53 SI.7, GDPR II_5.1.f, HIPAA 164.312.c.1, GPG13 4.11, and TSC (PI1.4, PI1.5, CC6.1, CC6.8, CC7.2, CC7.3).

## What I learned
- By default syscheck scans every 12 hours. Real-time detection needs `realtime="yes"` on the directory.
- Added, modified, and deleted files fire different rules (554, 550, 553) with different severity levels.
- Not every FIM alert is malicious. Services like wireplumber change files in a user's home directory all the time, so analysts need a baseline to tell normal changes from suspicious ones.

## Next steps
- Modify and delete `simple.txt` to trigger rules 550 and 553
- Monitor `/etc/passwd` and `/etc/shadow`
- Write a custom rule that raises severity for changes in sensitive paths
- Map the alerts to MITRE ATT&CK techniques

GTFOBins Auditor (SAFE)
Overview

GTFOBins Auditor is a defensive security auditing tool designed to identify and prioritize potentially abusable binaries on Linux systems by correlating locally installed executables with the https://gtfobins.github.io/ knowledge base.

Unlike offensive tools, GTFOBins Auditor does not execute payloads, exploits, or attack chains.
Its purpose is visibility, risk assessment, and hardening support for Blue Teams, auditors, and security engineers.

Key Features

🔍 GTFOBins Mapping

Detects installed binaries that have GTFOBins entries

Extracts documented capability categories (shell, sudo, SUID, file-write, etc.)

🔐 SUID Discovery (Real Scan)

Enumerates SUID binaries on the system

Correlates SUID files with GTFOBins entries

Highlights high-priority privilege surfaces

🧾 Sudo Policy Audit

Audits sudo permissions using non-interactive sudo -n -l

Detects NOPASSWD rules

Identifies environments where sudo enumeration requires password or TTY

📊 Risk Scoring (SAFE Heuristic)

Assigns a risk score (0–100) and risk level

CRITICAL

HIGH

MEDIUM

LOW

INFO

Scoring considers:

SUID presence

Linux capabilities

GTFOBins function categories

Sudo misconfigurations

📄 JSON Report Export

Machine-readable output for dashboards, SIEM, or further analysis

Suitable for compliance evidence and security reviews


What This Tool Is NOT

❌ No payload execution

❌ No exploitation

❌ No privilege escalation attempts

❌ No system modification

This tool is SAFE by design and intended for defensive security, auditing, and education.



<img width="1507" height="848" alt="image" src="https://github.com/user-attachments/assets/efff820f-f93c-4384-870a-efafa2141ad6" />


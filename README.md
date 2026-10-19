<div align="center">

# 🛡️ Incident Report: SSH Brute Force Attack on Cloud VM

![Severity](https://img.shields.io/badge/Severity-Low-yellow)
![Status](https://img.shields.io/badge/Status-Closed-brightgreen)
![Outcome](https://img.shields.io/badge/Compromise-None-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-T1110.001-blue)

**Analyst:** Your Name &nbsp;|&nbsp; **Report Date:** DD Month YYYY &nbsp;|&nbsp; **Incident ID:** IR-2026-001

</div>

> ⚠️ **Note:** All values below are sample data. Replace them with your own findings. Mask your VM's public IP, hostname, usernames and cloud account IDs before publishing.

---

## 📌 1. Executive Summary

My cloud-hosted Ubuntu VM, exposed to the internet on SSH (port 22), was targeted by an **automated brute force campaign** from multiple source IPs. Over **~6 hours**, **4,312 failed login attempts** were recorded against **87 distinct usernames**. Log analysis confirmed **no successful authentication** from any attacking IP. The VM was hardened afterwards (key-only SSH, firewall restriction, fail2ban) and the attack surface was reduced.

| Item | Detail |
|---|---|
| **Incident Type** | Brute Force / Credential Guessing |
| **Target** | Ubuntu 22.04 VM (SSH, port 22) |
| **Attack Window** | 2026-10-01 02:14 UTC to 08:31 UTC |
| **Total Failed Attempts** | 4,312 |
| **Unique Source IPs** | 14 |
| **Successful Logins** | **0** |
| **Data Exposure** | None identified |
| **Severity** | Low (no compromise) |

---

## 🔍 2. Detection

The activity was identified through manual review of authentication logs after noticing unusual login failures.

```bash
# Count failed password attempts
grep "Failed password" /var/log/auth.log | wc -l

# Top attacking IPs
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head

# Most targeted usernames
grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -nr | head
```

**Data sources used:** `/var/log/auth.log`, `journalctl -u ssh`, cloud provider network logs, AbuseIPDB (IP reputation).

---

## ⏱️ 3. Timeline (UTC)

| Time | Event |
|---|---|
| `02:14` | First failed SSH login from `185.xxx.xxx.12` |
| `02:14 – 03:00` | Slow, low-rate attempts (reconnaissance phase) |
| `03:00 – 06:45` | Rate increases sharply; multiple IPs join the campaign |
| `06:45` | Peak activity: ~42 attempts per minute |
| `08:31` | Last recorded attempt; activity stops |
| `09:10` | I discovered the activity during log review |
| `09:25` | Successful-login check completed: none found |
| `09:40` | Containment and hardening applied |

```mermaid
timeline
    title Attack and Response Timeline
    02:14 : First failed login
    03:00 : Multi-IP escalation
    06:45 : Peak (~42 attempts/min)
    08:31 : Activity stops
    09:10 : Detected by analyst
    09:40 : Hardening applied
```

---

## 📊 4. Analysis

### 4.1 Top Source IPs

| Rank | Source IP (masked) | Attempts | Country | AbuseIPDB Score |
|:---:|---|:---:|---|:---:|
| 1 | `185.xxx.xxx.12` | 1,204 | 🇳🇱 Netherlands | 100% |
| 2 | `45.xxx.xxx.77` | 983 | 🇺🇸 United States | 97% |
| 3 | `103.xxx.xxx.5` | 611 | 🇨🇳 China | 100% |
| 4 | `91.xxx.xxx.140` | 402 | 🇷🇺 Russia | 89% |
| 5 | `Others (10 IPs)` | 1,112 | Various | n/a |

### 4.2 Most Targeted Usernames

| Rank | Username | Attempts |
|:---:|---|:---:|
| 1 | `root` | 1,890 |
| 2 | `admin` | 612 |
| 3 | `ubuntu` | 487 |
| 4 | `test` | 301 |
| 5 | `oracle` | 244 |

### 4.3 Attack Characteristics

- 🤖 **Automated:** consistent timing between attempts, no human-like pauses.
- 📖 **Dictionary-based:** common default usernames and weak passwords.
- 🌍 **Distributed:** multiple geographies, consistent with botnet or rented scanning infrastructure.
- 🎯 **Opportunistic:** the VM was not specifically targeted; it was found by mass internet scanning.

---

## 🧪 5. Impact Assessment

I checked whether any attempt succeeded and whether any persistence was established.

```bash
# Successful logins
grep "Accepted" /var/log/auth.log

# Recent logins
last -a | head -20

# New users / cron jobs / listening ports / odd processes
cat /etc/passwd | tail -5
crontab -l; ls -la /etc/cron.*
ss -tulnp
ps aux --sort=-%cpu | head
```

| Check | Result |
|---|:---:|
| Successful logins from attacker IPs | ✅ None |
| New user accounts created | ✅ None |
| Suspicious cron jobs / startup items | ✅ None |
| Unexpected listening ports | ✅ None |
| Unusual processes / high CPU | ✅ None |
| Modified `authorized_keys` | ✅ None |

**Conclusion:** No evidence of compromise.

---

## 🗺️ 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|:---:|
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Initial Access | Valid Accounts (attempted) | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Reconnaissance | Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) |

---

## 🧱 7. Containment and Remediation

| # | Action | Status |
|:---:|---|:---:|
| 1 | Disabled SSH password authentication (`PasswordAuthentication no`) | ✅ Done |
| 2 | Disabled direct root login (`PermitRootLogin no`) | ✅ Done |
| 3 | Enforced key-based authentication only | ✅ Done |
| 4 | Restricted port 22 in cloud security group to my IP only | ✅ Done |
| 5 | Installed and configured `fail2ban` (5 failures = 1 hour ban) | ✅ Done |
| 6 | Blocked top attacker IPs at the firewall | ✅ Done |
| 7 | Enabled log forwarding / monitoring | 🔄 In progress |

```bash
# /etc/ssh/sshd_config (relevant hardening)
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
```

---

## 🎓 8. Lessons Learned

1. **Internet-facing SSH is scanned within hours.** Exposure alone invites attacks.
2. **Default usernames are always targeted.** `root`, `admin` and `ubuntu` should never accept password logins.
3. **Restricting access at the network layer (security group) is more effective** than relying only on host-level defences.
4. **Log review should not be manual.** Alerting would have caught this in minutes rather than hours.

### Recommendations

- [ ] Forward logs to a SIEM (Wazuh / Splunk / ELK) with alerting on failed-login thresholds
- [ ] Place SSH behind a VPN or bastion host
- [ ] Add MFA for administrative access
- [ ] Set up automated IP reputation blocking

---

## 🧰 9. Tools Used

![Linux](https://img.shields.io/badge/Linux-Ubuntu-orange)
![fail2ban](https://img.shields.io/badge/fail2ban-IPS-red)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-Threat%20Intel-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-lightgrey)

`grep` · `awk` · `journalctl` · `fail2ban` · `AbuseIPDB` · `VirusTotal` · Cloud security groups

---

## 📎 10. Appendix

<details>
<summary><b>Sample sanitized log excerpt (click to expand)</b></summary>

```text
Oct  1 02:14:07 vm sshd[1042]: Failed password for invalid user admin from 185.xxx.xxx.12 port 51022 ssh2
Oct  1 02:14:09 vm sshd[1044]: Failed password for root from 185.xxx.xxx.12 port 51030 ssh2
Oct  1 02:14:12 vm sshd[1046]: Failed password for invalid user test from 185.xxx.xxx.12 port 51044 ssh2
```

</details>

---

<div align="center">

**Author:** Your Name · [LinkedIn](https://linkedin.com/in/yourprofile) · [GitHub](https://github.com/yourusername)

*Aspiring SOC Analyst | Blue Team | Incident Response*

</div>

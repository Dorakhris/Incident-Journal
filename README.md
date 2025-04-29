# Incident Handler's Journal

## Overview
This journal documents three cybersecurity incidents handled as a Blue Team analyst, showcasing my skills in Digital Forensics and Incident Response (DFIR), Security Operations Center (SOC) operations, Threat Intelligence, and Governance, Risk, and Compliance (GRC). Using tools like Splunk, Nessus, Volatility, and Wireshark, I isolated threats, conducted forensic analysis, and implemented remediation aligned with HIPAA, GDPR, PCI DSS, and NIST 800-53. Each entry includes incident details, actions, metrics, and lessons learned, with threats mapped to MITRE ATT&CK for proactive defense.

## Scenario 1: Ransomware Attack
**Date**: January 16, 2024

**Description**
A U.S. healthcare clinic suffered a ransomware attack at 9:00 a.m., encrypting critical files (e.g., medical records) and halting operations. Employees received a ransom note demanding payment for a decryption key. The attack originated from phishing emails with malicious attachments, deploying ransomware via a threat actor targeting healthcare.

## Tools Used

- Splunk: Log analysis for detecting phishing-related anomalies.
- CrowdStrike Falcon: Endpoint Detection and Response (EDR) for isolating infected systems.
- Veeam: Backup and recovery to restore encrypted files.
- Volatility: Memory forensics to analyze malware.

## The 5 W’s
- Who: Threat actor targeting healthcare.
- What: Ransomware attack encrypting files, disrupting operations.
- When: January 16, 2024, 9:00 a.m.
- Where: Healthcare clinic’s network.
- Why: Financial extortion via phishing emails with malicious attachments.

## Actions Taken

- Isolated infected systems using CrowdStrike to prevent ransomware spread.
- Restored files from Veeam backups, avoiding ransom payment.
- Analyzed memory dumps with Volatility to identify malware (mapped to MITRE ATT&CK T1486: Data Encrypted for Impact).
- Parsed email logs with Splunk to trace phishing origins, identifying malicious IPs via VirusTotal.
- Reported to HHS Office for Civil Rights per HIPAA and coordinated with FBI Cyber Division.
- Notified stakeholders and provided employee phishing training.

## Metrics

- **Time to Detection**: 15 minutes (via Splunk alerts).
- **Time to Resolution**: 8 hours (full system restoration).
- **Data Restored**: 100% (verified via backup integrity checks).

## Lessons Learned

- Regular phishing simulations are critical to reduce employee susceptibility.
- Up-to-date backups ensure rapid recovery without ransom payment.
- Enhanced email filtering (e.g., DMARC, SPF) can block malicious attachments.

## Reflections

- **Incident Type**: Ransomware via phishing.
- **Root Cause**: Employee interaction with malicious email attachments.
- **Solution**: Isolate systems, restore backups, conduct forensics, report to authorities, train staff.

## Continuous Improvement

- Implemented monthly phishing simulations with KnowBe4.
- Updated incident response playbooks to include ransomware-specific steps.
- Increased backup frequency to daily with offsite storage.



# Scenario 2: Data Breach and Extortion

**Date**: January 22, 2024

## Description
An organization experienced a data breach at 7:20 p.m., compromising 50,000 customer records (PII, financial data) with a $100,000 financial impact. On January 20, an employee ignored an extortion email demanding $25,000. A follow-up email on January 22 with stolen data samples and a $50,000 demand prompted security team action.

## Tools Used

- Splunk: Log analysis for breach detection.
- Symantec DLP: Data Loss Prevention to identify exfiltrated data.
- Palo Alto WAF: Web Application Firewall to block further exploits.
- Burp Suite: Web vulnerability analysis.

## The 5 W’s

- Who: Cybercriminal exploiting web vulnerabilities.
- What: Unauthorized access and extortion, compromising 50,000 records.
- When: January 22, 2024, 7:20 p.m.
- Where: Organization’s web application.
- Why: Financial extortion via stolen data, exploiting a web vulnerability.

## Actions Taken

- Analyzed logs with Splunk to identify breach entry point (SQL injection, MITRE ATT&CK T1190: Exploit Public-Facing Application).
- Used Symantec DLP to confirm exfiltrated data scope.
- Patched web application with Palo Alto WAF rules to block further exploits.
- Notified affected customers per GDPR and CCPA, offering credit monitoring.
- Coordinated with law enforcement and used Burp Suite to validate patch efficacy.
- Implemented stricter access controls (MFA).

## Metrics

**Time to Detection**: 2 days (from first email to security team action).

**Records Compromised**: 50,000 (verified via DLP).

**Cost of Incident**: $100,000 (direct costs, revenue loss).

## Lessons Learned

- Routine vulnerability scans can prevent web application exploits.
- Advanced access controls (e.g., MFA) reduce unauthorized access risks.
- Employees need training to report suspicious emails immediately.


## Reflections

- **Incident Type**: Data breach and extortion.
- **Root Cause**: SQL injection in web application.
- **Solution**: Patch vulnerabilities, deploy DLP, notify customers, report to authorities.

## Continuous Improvement

- Scheduled monthly vulnerability scans with Nessus.
- Enhanced developer training on secure coding practices.
- Enforced MFA across all systems.



# Scenario 3: Database Server Vulnerability
**Date**: February 1, 2024


## Description
As a cybersecurity analyst for an e-commerce company, I identified a publicly accessible database server, posing risks to customer data. A vulnerability assessment was conducted to secure the server and communicate risks to decision-makers.

## Tools Used

- Nessus: Vulnerability scanning for open ports and CVEs.
- Metasploit: Penetration testing to validate vulnerabilities.
- Wireshark: Network monitoring for unauthorized access.
- Splunk: Log analysis for access attempts.

## The 5 W’s

- Who: Potential threat actors (external hackers, insiders).
- What: Vulnerability assessment of a publicly accessible database.
- When: February 1, 2024.
- Where: E-commerce company’s remote database server.
- Why: To mitigate risks from open access and protect sensitive data.

## Actions Taken

- Scanned server with Nessus, identifying open ports and outdated SSL (MITRE ATT&CK T1590: Gather Victim Network Information).
- Conducted penetration testing with Metasploit to confirm exploitability.
- Implemented Role Based Access Control (RBAC) to restrict access to authorized users.
- Upgraded from SSL to TLS 1.3 for secure communications, per PCI DSS.
- Configured Splunk to monitor and alert on unauthorized access attempts.


## Metrics

- Vulnerabilities Identified: 12 (via Nessus).
- High-Risk Issues Mitigated: 5 ( open ports, weak SSL).
- Time to Implement Changes: 2 weeks.

## Lessons Learned

- Regular vulnerability scans prevent exposure of critical systems.
- RBAC significantly reduces unauthorized access risks.
- Upgrading encryption protocols enhances data protection.

## Reflections

**Incident Type**: Proactive vulnerability assessment.

**Root Cause**: Publicly accessible database server.

**Solution**: Scan vulnerabilities, implement RBAC, upgrade TLS, monitor logs.

## Continuous Improvement

- Scheduled bi-monthly Nessus scans.
- Trained staff on RBAC implementation and benefits.
- Standardized TLS 1.3 across all servers.


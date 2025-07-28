### **Project 1**

# Project Title
Incident Response: Containing a Healthcare Ransomware Attack



## Case Summary
- **Objective:** As the lead incident handler, my objective was to contain a live ransomware attack on a U.S. healthcare clinic, eradicate the threat, restore all critical operations with zero data loss, and ensure all regulatory reporting obligations under HIPAA were met.
- **Scope:** The incident encompassed the entire clinic's network, with a focus on infected endpoints, email servers, and file servers containing protected health information (PHI).
- **Tools Used:** Splunk, CrowdStrike Falcon, Veeam, Volatility, VirusTotal.
- **Outcome:** I successfully led the response effort, isolating all infected systems within minutes. We achieved 100% data restoration from backups, avoiding any ransom payment. The root cause was traced to a targeted phishing campaign, and all findings were documented for reporting to the HHS and the FBI.



## Tools & Environment
| Tool | Purpose |
| :--- | :--- |
| **Splunk** | Real-time log analysis and alerting, which provided the initial detection of the attack. |
| **CrowdStrike Falcon** | Endpoint Detection & Response (EDR) used to immediately isolate infected hosts from the network. |
| **Veeam** | Backup and recovery solution used to restore encrypted files and systems. |
| **Volatility** | Memory forensics to analyze the malware payload and identify its behavior in memory. |
| **OS/VM Used** | Windows Server (Target), Windows 10 (Endpoints), SIFT Workstation (Analysis). |



## Case Background
On January 16, 2024, at 9:00 a.m., our SOC received a high-priority alert from Splunk correlating with multiple users reporting that their files were inaccessible and displaying a ransom note. As the on-call incident handler, I immediately took charge of the investigation. The initial assessment confirmed a widespread ransomware attack impacting critical patient records and halting all clinic operations. My mission was to execute our incident response plan to control the damage and restore services as quickly and safely as possible.



## Methodology
My response followed a structured incident handling process (aligned with the NIST framework) to ensure a methodical and effective resolution.

1.  **Identification:** The incident was first detected via Splunk alerts for mass file modifications. This was immediately confirmed by user reports of ransom notes.
2.  **Containment:** Using our EDR solution, CrowdStrike Falcon, I immediately executed a "network contain" action on all identified and suspected infected endpoints. This isolated them from the network in seconds, preventing the ransomware from spreading further.
3.  **Eradication & Analysis:** While the containment was active, I took a memory dump from an infected machine for forensic analysis. Using Volatility, I identified the malicious process. Concurrently, I used Splunk to trace the initial entry vector, pinpointing a phishing email with a malicious attachment that had been opened by several users.
4.  **Recovery:** Once the network was secure, I coordinated with the IT team to begin restoring the encrypted files and systems from the most recent Veeam backups. We performed integrity checks to ensure 100% data restoration.
5.  **Post-Incident Activities:** I compiled a full incident report, including IoCs and TTPs, for reporting to the HHS Office for Civil Rights (per HIPAA) and the FBI. I also provided a debrief to leadership and scheduled mandatory phishing awareness training for all employees.



## Findings & Evidence
The investigation confirmed a financially motivated ransomware attack originating from a targeted phishing campaign.

| Artifact Type | Finding | MITRE ATT&CK Mapping |
| :--- | :--- | :--- |
| **Initial Access** | Phishing email with malicious macro-enabled attachment. | T1566.001 - Phishing: Spearphishing Attachment |
| **Execution** | Malicious attachment launched PowerShell to download the payload. | T1059.001 - Command and Scripting Interpreter: PowerShell |
| **Impact** | Critical patient records and system files were encrypted. | T1486 - Data Encrypted for Impact |
| **C2 Indicator** | Malicious IPs identified from email headers and payload analysis. | T1071 - Application Layer Protocol |



## Conclusion
The investigation definitively concluded that the incident was a ransomware attack executed by a threat actor targeting the healthcare sector. The initial vector was a phishing email, and the root cause was an employee interacting with a malicious attachment.

**Impact:** The attack caused an 8-hour operational outage but, due to swift action, resulted in no permanent data loss and avoided any ransom payment. The primary impact was business disruption and the cost of the response effort.

**Recommendations:**
1.  **Technical Controls:** Implement stricter email filtering rules (DMARC, DKIM, SPF) and configure the EDR to automatically block and quarantine suspicious attachments.
2.  **Procedural Controls:** Increase the frequency of backups to daily, with at least one immutable, offsite copy. Update the incident response playbook with ransomware-specific actions.
3.  **Human Controls:** Implement a continuous security awareness training program with monthly phishing simulations to harden the human firewall.



## Lessons Learned / Reflection
This incident was a stark reminder that even with advanced tools, the human element remains a critical part of the attack surface. While our technical response was fast and effective, the incident could have been prevented entirely. The key lesson was the immense value of up-to-date, tested backups, which was the single most important factor that allowed us to recover without paying the ransom. This incident reinforced my belief that a successful defense is a combination of robust technology, solid procedures, and well-trained people.


---
### **Project 2**

# Project Title
Incident Response: Web Application Breach & Data Extortion



## Case Summary
- **Objective:** To investigate a data breach notification where a cybercriminal claimed to have stolen 50,000 customer records. My goals were to validate the attacker's claims, identify the entry point, patch the vulnerability, and determine the full scope of the breach to guide our legal and customer notification strategy.
- **Scope:** The investigation focused on the company's public-facing web application, its underlying database, and all associated logs.
- **Tools Used:** Splunk, Symantec DLP, Palo Alto WAF, Burp Suite.
- **Outcome:** I successfully traced the breach to a critical SQL injection vulnerability. Using our DLP solution, I confirmed the scope of the exfiltrated data, and I deployed an emergency rule to the WAF to immediately block the exploit. This provided the necessary evidence to guide our response to the extortion demand and fulfill GDPR/CCPA notification requirements.



## Tools & Environment
| Tool | Purpose |
| :--- | :--- |
| **Splunk** | Centralized log analysis to identify the malicious SQL queries and trace the attacker's activity. |
| **Symantec DLP** | Data Loss Prevention tool used to confirm which specific data was exfiltrated. |
| **Palo Alto WAF** | Web Application Firewall used to deploy an emergency virtual patch to block the attack vector. |
| **Burp Suite** | Web vulnerability scanner used to validate the vulnerability and confirm the efficacy of the WAF patch. |
| **OS/VM Used** | Linux/Apache/MySQL/PHP (LAMP) stack (Target), Kali Linux (Analysis). |



## Case Background
The incident began when an employee, after a two-day delay, forwarded an extortion email to the security team. The email contained samples of customer PII and demanded $50,000. I was immediately assigned to lead the technical investigation. My first priority was to determine if the threat was credible and, if so, to find and close the security hole to prevent further damage. The situation was critical, with a potential $100,000 financial impact and severe regulatory consequences.



## Methodology
My investigation was focused on speed and accuracy to contain the ongoing breach.

1.  **Log Analysis & Triage:** I immediately dove into our Splunk instance, correlating the timestamps from the extortion email with our web server access logs. I created a query to search for unusual SQL syntax in GET/POST requests, which quickly revealed a series of malicious queries targeting a vulnerable API endpoint.
2.  **Vulnerability Identification:** Based on the logs, I identified a classic SQL injection vulnerability. This was the clear entry point for the breach.
3.  **Containment & Virtual Patching:** To immediately stop the bleeding, I crafted a custom rule for our Palo Alto WAF to block the specific malicious pattern I found in the logs. This served as an emergency "virtual patch."
4.  **Scope Confirmation:** I worked with the DLP team, using the patterns from the breach to configure Symantec DLP to identify the full scope of exfiltrated data. This confirmed the attacker's claim of 50,000 compromised records.
5.  **Validation:** Using Burp Suite, I replicated the attack against a staging server to confirm the vulnerability's existence, then tested it again after applying the WAF rule to validate that the virtual patch was effective.
6.  **Reporting:** I provided my technical findings to the leadership and legal teams, which informed their decision not to engage with the extortionist and to proceed with formal customer notification under GDPR and CCPA.



## Findings & Evidence
The investigation confirmed a data breach caused by a critical web application vulnerability.

| Artifact Type | Finding | MITRE ATT&CK Mapping |
| :--- | :--- | :--- |
| **Initial Access** | SQL Injection vulnerability in a public-facing web API. | T1190 - Exploit Public-Facing Application |
| **Collection** | Attacker queried the backend database to collect PII. | T1005 - Data from Local System |
| **Exfiltration** | Data was exfiltrated over the common HTTP/S channel. | T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol |
| **Impact** | Extortion demand based on stolen data. | T1486 - Data Encrypted for Impact (variant: Data Stolen for Extortion) |



## Conclusion
The breach was the direct result of an unpatched SQL injection vulnerability in a legacy web application. The attacker successfully exploited this flaw to exfiltrate 50,000 customer records containing PII and financial data.

**Impact:** The incident resulted in a direct financial cost of $100,000, necessitated a costly customer notification process under GDPR/CCPA, and caused significant reputational damage.

**Recommendations:**
1.  **Immediate Remediation:** The application code must be fixed by the development team to properly parameterize all SQL queries. The WAF rule should remain in place as a compensating control.
2.  **Proactive Security:** Implement a formal vulnerability management program, including monthly authenticated scans of all web applications with a tool like Nessus or Burp Suite.
3.  **Developer Training:** Mandate secure coding training for all developers, with a specific focus on the OWASP Top 10 vulnerabilities.
4.  **Employee Training:** Train all employees to immediately report any suspicious or extortion-related emails to the security team.



## Lessons Learned / Reflection
This incident was a classic case of how a single technical flaw can lead to massive business and regulatory impact. The two-day delay in reporting the extortion email highlighted a critical gap in employee awareness. Technically, it reinforced the value of a defense-in-depth approach; while the application was vulnerable, having centralized logging (Splunk) and a WAF allowed us to detect and contain the attack much faster than would have been otherwise possible. This case proves that proactive security through regular scanning and secure coding is far less expensive than reactive incident response.



---
### **Project 3**

# Project Title
Proactive Security: Vulnerability Assessment of a Critical Database



## Case Summary
- **Objective:** As part of a proactive security initiative, my goal was to conduct a full vulnerability assessment of a publicly accessible e-commerce database server. I aimed to identify all security weaknesses, validate their exploitability, and develop a prioritized remediation plan to bring the server into compliance with PCI DSS.
- **Scope:** The assessment focused on a single remote database server, including its network configuration, operating system, and database service.
- **Tools Used:** Nessus, Metasploit, Wireshark, Splunk.
- **Outcome:** My assessment identified 12 vulnerabilities, including 5 critical-risk issues such as open database ports and weak SSL/TLS ciphers. I validated the risks using Metasploit and developed a concrete remediation plan, which included implementing RBAC and upgrading to TLS 1.3. The project successfully eliminated a major data breach risk before it could be exploited.



## Tools & Environment
| Tool | Purpose |
| :--- | :--- |
| **Nessus** | Vulnerability scanning to identify open ports, misconfigurations, and known CVEs. |
| **Metasploit** | Penetration testing framework used to validate the exploitability of identified vulnerabilities. |
| **Wireshark** | Network protocol analysis to monitor for unauthorized access attempts and inspect TLS handshakes. |
| **Splunk** | Log analysis to search for historical evidence of brute-force attempts or other malicious activity. |
| **OS/VM Used** | E-commerce Server (Target), Kali Linux (Attack/Analysis). |



## Case Background
During a routine review of our network architecture, I identified a database server that was unexpectedly accessible from the public internet. Recognizing this as a critical risk to sensitive customer and payment data, I initiated a formal vulnerability assessment. My mission was to go beyond a simple scan, prove the tangible risk to leadership, and provide a clear, actionable plan to secure this critical asset and ensure PCI DSS compliance.



## Methodology
I followed a structured assessment methodology to ensure comprehensive and accurate results.

1.  **Passive Reconnaissance:** I began by using Wireshark and Splunk to analyze traffic to and from the server, looking for any existing unauthorized connection attempts.
2.  **Active Scanning:** I conducted a full, credentialed scan of the server using Nessus. This identified all open ports, running services, and associated vulnerabilities, including outdated SSL/TLS versions.
3.  **Vulnerability Validation:** This was the critical step to demonstrate real risk. I used the Metasploit framework to launch controlled, non-destructive exploits against the identified vulnerabilities. This confirmed that the weaknesses were not just theoretical but actively exploitable.
4.  **Risk Analysis & Prioritization:** I analyzed the findings, prioritizing them based on exploitability and potential impact. The publicly accessible database port was ranked as the highest priority.
5.  **Remediation and Hardening:** I developed and implemented a remediation plan. This included working with the network team to apply firewall rules, configuring Role-Based Access Control (RBAC) on the database, and upgrading the server's cryptographic protocols to TLS 1.3.
6.  **Verification:** After the changes were implemented, I performed a final Nessus scan to validate that all identified vulnerabilities had been successfully mitigated.



## Findings & Evidence
The assessment revealed that the server was in a high-risk state, actively exposing it to attack.

| Finding | Tool Used | Risk & Impact | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- |
| **Database Port 3306 Open to Public** | Nessus | Allowed direct brute-force and exploit attempts against the database, risking a full data breach. | T1595.002 - Active Scanning: Vulnerability Scanning |
| **Outdated SSL/Weak Ciphers** | Nessus | Enabled potential Man-in-the-Middle (MITM) attacks to decrypt sensitive data in transit. Non-compliant with PCI DSS. | T1071 - Application Layer Protocol |
| **Exploitable Service Vulnerability** | Metasploit | Confirmed that a CVE identified by Nessus was practically exploitable, allowing for potential remote access. | T1190 - Exploit Public-Facing Application |



## Conclusion
The proactive assessment successfully identified and mitigated a critical security risk before it could be exploited by an attacker. The publicly accessible database posed a direct threat of a major data breach, which would have resulted in severe financial and reputational damage, as well as non-compliance with PCI DSS.

**Impact:** By closing these security gaps, we prevented a likely future incident, protected sensitive customer data, and brought a critical asset into compliance with industry standards.

**Recommendations Implemented:**
1.  **Network Hardening:** The database port was blocked from public access at the firewall level.
2.  **Access Control:** Role-Based Access Control (RBAC) was implemented to ensure only authorized users and applications could access the database.
3.  **Encryption:** The server was reconfigured to disable outdated SSL protocols and enforce the use of TLS 1.3 for all connections.
4.  **Monitoring:** Splunk was configured with new alerts to specifically monitor for any unauthorized access attempts against the database.



## Lessons Learned / Reflection
This project was a powerful demonstration of the value of proactive, offensive-minded security. Rather than waiting for an alert, we went looking for trouble and found it. The most important lesson was the power of validation; showing leadership a Nessus report is one thing, but showing them a successful Metasploit session that proves the risk is real is far more compelling. This assessment shifted a part of our security program from a reactive posture to a proactive one, ultimately preventing a future incident and saving the company significant potential losses.

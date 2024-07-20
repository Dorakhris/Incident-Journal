# Incident Handler's Journal

## Case Scenario 1: 
A small U.S. health care clinic specializing in delivering primary-care services experienced a security incident on a Tuesday morning, at approximately 9:00 a.m. Several employees reported that they were unable to use their computers to access files like medical records. Business operations shut down because employees were unable to access the files and software needed to do their job. Additionally, employees also reported that a ransom note was displayed on their computers. The ransom note stated that all the company's files were encrypted by an organized group of unethical hackers who are known to target organizations in healthcare and transportation industries. In exchange for restoring access to the encrypted files, the ransom note demanded a large sum of money in exchange for the decryption key. The attackers were able to gain access into the company's network by using targeted phishing emails, which were sent to several employees of the company. The phishing emails contained a malicious attachment that installed malware on the employee's computer once it was downloaded. Once the attackers gained access, they deployed their ransomware, which encrypted critical files. The company was unable to access critical patient data, causing major disruptions in their business operations. The company was forced to shut down their computer systems and contact several organizations to report the incident and receive technical assistance.

**Date:** January 16, 2024

**Entry #1:**

### Description:
A small healthcare clinic experienced a ransomware attack on a Tuesday morning around 9:00 a.m. Employees couldn't access important files or software, and operations were shut down. A ransom note appeared on their computers, demanding money for a decryption key to unlock the files. The attackers used phishing emails with malicious attachments to gain access and deploy the ransomware.

### Tools Used:
- Phishing Simulation Software
- Endpoint Detection and Response (EDR) Tools
- Backup and Recovery Solutions

### The 5 W's:
- **Who:** Organized group of hackers
- **What:** Ransomware attack causing file encryption and business shutdown
- **When:** January 16, 2024, at 9:00 a.m.
- **Where:** Healthcare clinic
- **Why:** The attackers accessed the company's systems via phishing emails containing malicious attachments. After gaining access, they deployed ransomware that encrypted critical files. Their motivation appears to be financial, as indicated by the ransom note demanding a large sum of money for the decryption key.

### Actions Taken:
- Isolated infected systems to prevent further spread.
- Initiated recovery from backups to restore encrypted files.
- Conducted a thorough forensic analysis to understand the attack vector.
- Reported the incident to relevant authorities and stakeholders.

### Metrics:
- Time to Detection: 15 minutes
- Time to Resolution: 8 hours
- Data Restored: 100%

### Lessons Learned:
- Need for regular phishing awareness training for employees.
- Importance of maintaining up-to-date backups.
- Enhanced email filtering to block malicious attachments.

### Reflections:
- Incident type: Ransomware via phishing
- Root cause: Phishing emails with malicious attachments
- Solution: More training, secure backups, isolate infected systems, communicate with stakeholders, report to authorities

### Continuous Improvement:
- Implemented monthly phishing simulations.
- Updated incident response playbooks.
- Increased frequency of security awareness training sessions.

## Case Scenario 2: 
The organization experienced a security incident on January 22, 2024, at 7:20 p.m, PT, during which an individual was able to gain unauthorized access to customer personal identifiable information (PII) and financial information. Approximately 50,000 customer records were affected. The financial impact of the incident is estimated to be $100,000 in direct costs and potential loss of revenue. The incident is now closed and a thorough investigation has been conducted. At approximately 3:13 p.m., PT, on January 20, 2024, an employee received an email from an external email address. The email sender claimed that they had successfully stolen customer data. In exchange for not releasing the data to public forums, the sender requested a $25,000 cryptocurrency payment. The employee assumed the email was spam and deleted it. On January 22, 2024, the same employee received another email from the same sender. This email included a sample of the stolen customer data and an increased payment demand of $50,000. On the same day, the employee notified the security team, who began their investigation into the incident.
**Date:** January 22, 2024

**Entry #2:**

### Description:
An individual gained unauthorized access to customer personal and financial information. About 50,000 records were affected, costing an estimated $100,000. On January 20, an employee received an email demanding $25,000 to not release the data. The email was ignored, but a follow-up email with a higher demand of $50,000 was received on January 22, prompting the employee to report it.

### Tools Used:
- Playbook
- Data Loss Prevention (DLP) Tools
- Web Application Firewall (WAF)

### The 5 W's:
- **Who:** Cyber criminal
- **What:** Unauthorized access and blackmail
- **When:** January 22, 2024, at 7:20 p.m.
- **Where:** Organization
- **Why:** Data breach and extortion

### Actions Taken:
- Conducted a thorough investigation to identify the breach source.
- Implemented immediate access control changes.
- Notified affected customers and stakeholders.
- Coordinated with law enforcement for further investigation.

### Metrics:
- Time to Detection: 2 days
- Records Compromised: 50,000
- Cost of Incident: $100,000

### Lessons Learned:
- Importance of routine vulnerability scans.
- Need for robust access control mechanisms.
- Regular updates and patching of web applications.

### Reflections:
- Incident type: Unauthorized access and blackmail
- Root cause: Web application vulnerability
- Solution: Regular scans, allowlisting, more training, report to authorities

### Continuous Improvement:
- Scheduled monthly vulnerability assessments.
- Enhanced security training for developers.
- Implemented stricter access control policies.

## Scenario 3: 
You are a newly hired cybersecurity analyst for an e-commerce company. The company stores information on a remote database server, since many of the employees work remotely from locations all around the world. Employees of the company regularly query, or request, data from the server to find potential customers. The database has been open to the public since the company's launch three years ago. As a cybersecurity professional, you recognize that keeping the database server open to the public is a serious vulnerability. A vulnerability assessment of the situation can help you communicate the potential risks with decision makers at the company. You must create a written report that clearly explains how the vulnerable server is a risk to business operations and how it can be secured

**Date:** February 1, 2024

**Entry #3:**

### Description:
A newly hired cybersecurity analyst is assessing the security of an e-commerce company's database server. The server is publicly accessible, which poses significant risks. The assessment includes identifying threats, evaluating risks, and recommending security improvements.

### Tools Used:
- Vulnerability Scanners (e.g., Nessus)
- Penetration Testing Tools (e.g., Metasploit)
- Access Control Mechanisms (e.g., Role-Based Access Control)

### The 5 W's:
- **Who:** Potential attackers (internal and external)
- **What:** Security assessment of a database server
- **When:** February 1, 2024
- **Where:** E-commerce company
- **Why:** To secure the server and protect sensitive data

### Actions Taken:
- Conducted a thorough vulnerability assessment.
- Implemented Role-Based Access Control (RBAC) to restrict access.
- Upgraded from SSL to TLS for secure communications.
- Established a monitoring system to log and review access attempts.

### Metrics:
- Vulnerabilities Identified: 12
- High-Risk Issues Mitigated: 5
- Time to Implement Changes: 2 weeks

### Lessons Learned:
- Regular vulnerability assessments are essential.
- Role-Based Access Control (RBAC) can significantly reduce risk.
- Upgrading security protocols (e.g., SSL to TLS) enhances protection.

### Reflections:
- Incident type: Vulnerability assessment
- Root cause: Publicly accessible database server
- Solution: Implement RBAC, upgrade to TLS, monitor access attempts

### Continuous Improvement:
- Established a schedule for regular vulnerability assessments.
- Trained staff on the importance of RBAC.
- Updated security protocols across all systems.

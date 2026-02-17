# SSH_BruteForce_Detection

                    Detection of SSH Brute Force attack using SIEM 


Name: Dehiwattage Kavindu Nishitha Fernando

Role: SOC analyst (Lab Project)

Date: 15\02\2026
 

Implementation of SSH Brute Force attack using SIEM tool is SOC Tier 1 project. This project was done by using Splunk Enterprise SIEM tool. In this project, windows OpenSSH authentication logs were added and analysed to detect brute force attacks. By using SPL, threshold-based detection rule was implemented and automated the alerting. A dashboard was created to ease the analysis.


Project objectives:

• Simulate SOC Tier 1 monitoring environment

• Detect SSH brute-force attacks

• Create automated alert

• Design monitoring dashboard

• Perform log-based investigation



Project Enviroment:

Component	Description	

SIEM Platform	Splunk: Enterprise

Operating System:	Windows

Data Source:	Windows OpenSSH Operational Logs (.evtx)

Custom Index:	windows_security

Detection Method:	SPL with regex field extraction



Detection Engineering: 

•	Use case; Multiple failed login attempts were detected from a single IP address.

•	Logic(search);

\\\  index=windows_security source="WinEventLog:OpenSSH/Operational"

| search "Failed password"

| rex "Failed password for (invalid user )?(?<username>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"

| bin _time span=5m

| stats count as failed_attempts by _time src_ip

| where failed_attempts >= 3    \\\
		


Alert Configuration:

•	Schedule: Every 5 minutes

•	Time Range: Last 5 minutes

•	Trigger Condition: Number of results > 0

•	Expiration: Disabled




Findings: 

•	Source IP: 10.23.23.9

•	Total failed attempts: 5

•	Targeted username: Invalid user account

•	Log message: "Failed password for invalid user"

•	No successful logins detected

Dashboard Implementation:

1.	SSH Failed Logins Over Time (Trend Visualization)

2.	Top Source IPs by Failed Attempts

3.	Most Targeted Usernames

4.	Total Failed Login Attempts (Single Value KPI)


Limitations:

•	Dataset contained a limited number of failed login events

•	Detection threshold was tuned for lab simulation

•	Real-world environments require tuning to reduce false positives



Conclusion:

Successfully completing this project gave foundational skills that are essential to a SOC analyst. This project successfully simulated a SOC Tier 1 brute-force detection workflow using Splunk SIEM. Authentication logs were ingested, parsed, and analyzed using custom SPL queries.
       
Skills learned; 

•	Log ingestion

•	Detection engineering

•	SPL query development

•	Alert configuration

•	Security event analysis

•	SOC monitoring dashboard design





















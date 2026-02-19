# Splunk SPL (Search Processing Language) Query Library

**Version:** 2.1  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Splunk Fundamentals

Splunk Search Processing Language (SPL) queries enable SOC analysts to search, aggregate, and correlate security data.

---

## Basic SPL Syntax

```
Splunk Query Structure:

index=main sourcetype=sysmon EventID=1
| where CommandLine contains "powershell"
| stats count by host, user
| sort - count

Breaking down:
├─ index=main ────────────────→ Data source to search
├─ sourcetype=sysmon ─────────→ Filter to specific source type
├─ EventID=1 ──────────────────→ Filter to Event ID 1 (Process Created)
├─ | where CommandLine contains "powershell" ─→ Pipe filtered data
├─ | stats count by host, user ──→ Count by grouping
├─ | sort - count ──────────────→ Sort descending by count
└─ Result: Count of PowerShell processes per host/user
```

---

## Critical Security Queries

### Query 1: Brute Force Detection

```splunk
index=main source="WinEventLog:Security" EventID=4625
| stats count as failed_logons by user, src_ip, dest_host
| where failed_logons > 10
| table user, src_ip, dest_host, failed_logons
| sort - failed_logons

Purpose: Find accounts with >10 failed logons (brute force)
Execution: Every 15 minutes
Alert threshold: >10 in 15 minutes
Severity: CRITICAL
```

### Query 2: Privilege Escalation

```splunk
index=main source="WinEventLog:Security" (EventID=4728 OR EventID=4732)
| search TargetGroupName="Domain Admins" OR TargetGroupName="Enterprise Admins"
| table _time, dest, TargetGroupName, MemberName, SubjectUserName
| sort - _time

Purpose: Alert on any user added to admin groups
Execution: Real-time
Alert threshold: Any occurrence
Severity: CRITICAL
Expected: Rare (maybe monthly IT additions)
Investigation: Verify with IT before it happens
```

### Query 3: Lateral Movement Detection

```splunk
index=main source="WinEventLog:Security" EventID=4648
| where TargetServerName != "localhost" 
  AND SubjectUserName!="SYSTEM" 
  AND TargetUserName contains "admin"
| stats count as explicit_cred_uses by SubjectUserName, TargetServerName, TargetUserName
| where count > 2
| table SubjectUserName, TargetServerName, TargetUserName, count
| sort - count

Purpose: Find non-admins using admin credentials (lateral movement)
Execution: Every hour
Alert threshold: >2 uses of admin cred per user
Severity: HIGH
Investigation: Verify RunAs legitimacy
```

### Query 4: Malware Detection via File Creation

```splunk
index=main sourcetype=sysmon EventID=11
| where (TargetFilename contains "AppData" 
  OR TargetFilename contains "Temp" 
  OR TargetFilename contains "ProgramData")
  AND (Image="*\\powershell.exe" OR Image="*\\cmd.exe")
| stats count as file_creates by host, Image, TargetFilename
| where count > 5
| table host, Image, TargetFilename, count

Purpose: Detect suspicious file creation in temp folders
Execution: Every 30 minutes
Alert threshold: >5 files in Temp by process
Severity: HIGH
Investigation: Check file hashes against malware DB
```

### Query 5: C2 Beaconing Detection

```splunk
index=network sourcetype=zeek_conn
| where dest_port=443 
  AND proto=tcp 
  AND dest_ip NOT IN (8.8.8.8, 1.1.1.1)
| stats count, avg(duration), avg(orig_bytes), avg(resp_bytes) 
  by src_ip, dest_ip
| where avg(duration) > 30 AND avg(duration) < 60 
  AND count > 50
| table src_ip, dest_ip, count, avg(duration)

Purpose: Detect consistent beaconing patterns (malware)
Execution: Every hour
Alert threshold: 50+ connections with consistent duration
Severity: CRITICAL
Characteristics:
├─ Regular interval (~60 seconds)
├─ Consistent packet size
└─ Sustained over hours/days
```

### Query 6: Data Exfiltration Detection

```splunk
index=network sourcetype=zeek_conn
| where dest_ip NOT IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| stats sum(orig_bytes) as outbound_bytes, count 
  by src_ip, dest_ip
| where outbound_bytes > 1000000000
| eval outbound_GB=round(outbound_bytes/1024/1024/1024, 2)
| table src_ip, dest_ip, outbound_GB, count
| sort - outbound_GB

Purpose: Find systems exfiltrating large amounts of data
Execution: Every 4 hours
Alert threshold: >1 GB outbound to external IP
Severity: CRITICAL
Investigation:
├─ What data? (file types, categories)
├─ To where? (destination IP geo-location)
├─ How long? (timeline of transfer)
└─ Why? (legitimate backup, data theft, etc.)
```

### Query 7: Ransomware Detection via File Extension Changes

```splunk
index=main sourcetype=sysmon EventID=2
| where TargetFilename=*.doc.CONTI 
  OR TargetFilename=*.docx.CONTI 
  OR TargetFilename=*.pdf.CONTI
  OR TargetFilename=*.CONTI
| stats count as file_changes by host, Image
| where count > 10
| table host, Image, count, file_changes
| sort - count

Purpose: Alert on bulk file extension changes (ransomware)
Execution: Real-time
Alert threshold: >10 in 5 minutes
Severity: CRITICAL
Response:
├─ IMMEDIATE: Kill processes (Image column)
├─ IMMEDIATE: Disconnect host from network
├─ IMMEDIATE: Notify incident response
└─ IMMEDIATE: Stop all backups (prevent backup infection)
```

---

## Advanced SPL Techniques

### Technique 1: Correlation Analysis

```splunk
Query: Find users with failed logons THEN successful logon

index=main source="WinEventLog:Security"
| search EventID=4625 OR EventID=4624
| transaction user startswith=(EventID=4625) endswith=(EventID=4624) 
  maxspan=10m maxpause=30s
| where eventcount > 10
| table user, src_ip, eventcount, duration
| sort - eventcount

Purpose: Brute force followed by success = compromise
Execution: Every 30 minutes
Finding: Attacker brute forces, succeeds, may continue attacking
```

### Technique 2: Rare Event Detection

```splunk
Query: Find unusual processes for each host

index=main sourcetype=sysmon EventID=1
| stats count as proc_count by host, Image
| eventstats avg(proc_count) as avg_count, stdev(proc_count) as stdev_count
| eval threshold = avg_count + (stdev_count * 2)
| where proc_count > threshold
| table host, Image, proc_count, avg_count, threshold
| sort - proc_count

Purpose: Find processes that are unusual for this host
Detection: Malware that behaves differently than baseline
Advantage: Works even for unknown malware
```

### Technique 3: Time-based Anomaly Detection

```splunk
Query: Find logons outside normal hours

index=main source="WinEventLog:Security" EventID=4624
| where LogonType=3 OR LogonType=10
| eval hour=strftime(_time, "%H")
| eval day=strftime(_time, "%A")
| search NOT (day=Saturday OR day=Sunday OR hour>=18 OR hour<6)
| stats count by user, src_ip, day, hour
| join user [search index=main ... | stats avg(count) as baseline by user]
| where count > baseline * 2
| table user, src_ip, count, baseline

Purpose: Find off-hours or unusual logon times
Detection: Attacker accessing systems at odd times
Advantage: Catches attacks even if credentials valid
```

### Technique 4: Aggregation with Lookups

```splunk
Query: Correlate IPs against known malicious list

index=main sourcetype=zeek_conn
| join dest_ip [|inputlookup malicious_ips.csv]
| table src_ip, dest_ip, timestamp, threat_type
| stats count by src_ip, dest_ip, threat_type
| search threat_type=*C2* OR threat_type=*botnet*

Purpose: Automatically alert on known malicious IPs
Advantage: Integrates threat intelligence into SIEM
Update frequency: Daily (refresh lookup from TI feed)
```

---

## Query Performance Tips

```
1. Use index and sourcetype filters early:
   ✗ BAD: search all data, filter later
   ✓ GOOD: index=main sourcetype=sysmon | ...

2. Use time filters:
   ✗ BAD: (no time filter - searches all historical data)
   ✓ GOOD: earliest=-24h latest=now

3. Reduce data before aggregate:
   ✗ BAD: stats count | where count > 10
   ✓ GOOD: | where count > 10 | stats count

4. Use summary indexing for frequent queries:
   ✗ BAD: Running expensive query hourly
   ✓ GOOD: Summary index pre-calculates results

5. Test queries on small time range first:
   ✗ BAD: earliest=-1y (slow search)
   ✓ GOOD: earliest=-1h (test), then scale up
```

---

## Query Scheduling & Alerting

```
Configure Alert:

Alert Name: "Brute Force Attack - 4625 Spike"
Search: (index=main EventID=4625 | stats count by user, src_ip | where count > 10)
Schedule: Every 15 minutes
Condition: Alert when results > 0
Actions:
├─ Send email to SOC team
├─ Create incident ticket
├─ Post to Slack #security-alerts
└─ Webhook to incident response system

Tuning:
├─ Initial threshold: >10 in 15 minutes
├─ Monitor false positives for 1 week
├─ Adjust if needed (expected: 1 false positive per 1000 alerts)
└─ Review monthly
```

---

## SPL Function Reference

| Function | Purpose | Example |
|----------|---------|---------|
| stats | Aggregate data | stats count, avg(value) by host |
| where | Filter results | where count > 10 |
| eval | Calculate field | eval size_GB=bytes/1024/1024/1024 |
| transaction | Correlate events | transaction user maxspan=10m |
| lookup | Join with external | lookup malware_hashes sha256 |
| regex | Pattern matching | regex field="^[0-9]{1,3}\.[0-9]{1,3}…" |
| foreach | Loop/iteration | foreach * [eval <<FIELD>>=upper(<<FIELD>>)] |
| join | Correlate searches | join user [search ... ] |
| append | Combine datasets | append [search index=... ] |

---

## References

- Splunk Documentation
- Splunk Query Language (SPL) Tutorial
- SANS Splunk Hunting Guide

---

*Document Maintenance:*
- Test all queries monthly
- Update thresholds based on baseline changes
- Archive old queries (use summary indexes instead)
- Share validated queries with SOC team

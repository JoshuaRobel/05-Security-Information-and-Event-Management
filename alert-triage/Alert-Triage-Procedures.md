# SIEM Alert Triage & Investigation

**Version:** 1.1  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Alert Triage Workflow

```
ALERT RECEIVED (from SIEM)
│
├─ Priority Level?
│  ├─ CRITICAL → Immediate investigation (< 5 min)
│  ├─ HIGH → Quick assessment (< 30 min)
│  └─ MEDIUM/LOW → Standard queue (< 4 hours)
│
├─ Alert Verification
│  ├─ Is this a real incident? (Not false positive?)
│  ├─ Do we have baseline data?
│  └─ Can we reproduce the alert?
│
├─ Context Gathering
│  ├─ Related alerts for same host/user?
│  ├─ Historical pattern for this type?
│  └─ Baseline deviation (normal vs unusual)?
│
├─ Risk Assessment
│  ├─ Potential business impact?
│  ├─ Data sensitivity of affected systems?
│  └─ Threat severity and likelihood?
│
├─ Decision Point
│  ├─ Close (benign) → Log and close
│  ├─ Escalate (suspicious) → IR team
│  └─ Monitor (unusual) → Watch for patterns
│
└─ Document & Archive
   ├─ Triage findings
   ├─ Decision rationale
   └─ Evidence collection
```

## Real-World Triage Examples

```
EXAMPLE 1: Brute Force Alert
├─ Alert: >10 failed logons for admin account
├─ Assessment: Account lockout is ACTIVE (good!)
├─ Decision: Close (defense worked as designed)
└─ Note: Monitor for escalation

EXAMPLE 2: Unusual Data Access
├─ Alert: Finance team member accessed HR database
├─ Investigation: Finance person was added to HR team today
├─ Decision: Close (legitimate access change)
└─ Note: Update access baseline

EXAMPLE 3: C2 Connection Detected
├─ Alert: System connecting to known C2 IP
├─ Investigation: IP is legitimate (Google DNS misidentified)
├─ Decision: Tune rule (reduce false positives)
└─ Note: Update threat intelligence baseline
```

---

## References

- SIEM Best Practices Guide
- Alert Tuning Methodologies

---

*Document Maintenance:*
- Monitor false positive rate
- Adjust alert thresholds monthly
- Document tuning changes
## 14. Key Takeaways & Recommendations

### 14.1 Entity Mapping Strategy

Proper entity mapping transforms raw alerts into actionable incidents.

| Entity | Source Field | Mapping Target | Benefit |
|--------|--------------|----------------|---------|
| **User Account** | `UserPrincipalName` | Account entity | Enables user-centric investigation |
| **Source IP** | `IPAddress` | IP entity | Facilitates geolocation & reputation checks |

**Implementation:** In the analytics rule wizard, explicitly map these fields to enable:
- Better incident visualization
- Automated playbook triggers
- Cross-correlation with other alerts
- Faster triage decisions

---

### 14.2 Detection Granularity Options

Different aggregation strategies detect different attack patterns:

| Granularity Level | Query Pattern | Detects | Best For |
|-------------------|---------------|---------|----------|
| **Current: User + IP** | `by UserPrincipalName, IPAddress` | Targeted attacks from single source | Password guessing |
| **Alternative 1: User Only** | `by UserPrincipalName` | Distributed attacks across multiple IPs | Credential stuffing |
| **Alternative 2: IP Only** | `by IPAddress` | Scanning behavior across multiple users | Reconnaissance detection |

**Production Recommendation:** Implement multiple rules with different granularity levels for comprehensive coverage.

---

### 14.3 Failure Code Optimization

Moving from `ResultType != 0` to targeted codes improves precision.

#### Current Approach (Broad):
```kql
| where ResultType != 0  // Captures ALL failures
```

#### Recommended Approach (Targeted):
```kql
| where ResultType in ("50053", "50055", "50056", "50126")
```

#### Failure Code Reference Table:

| ResultType | Meaning | Include in Detection? | Rationale |
|------------|---------|----------------------|-----------|
| **50053** | Account locked | ✅ Yes | Clear brute-force indicator |
| **50055** | Password expired | ✅ Yes | May indicate user confusion, but relevant |
| **50056** | Invalid password | ✅ Yes | Core brute-force evidence |
| **50126** | Invalid username/password | ✅ Yes | Primary authentication failure |
| **50057** | Account disabled | ⚠️ Consider | Often legitimate admin action |
| **50074** | MFA required | ❌ No | Not a failure condition |
| **53003** | Conditional access blocked | ❌ No | Policy-based, not attack |

**Impact of Targeted Approach:**
- ✅ Reduces false positives
- ✅ Focuses on attack-relevant failures
- ✅ Provides clearer investigation context
- ⚠️ May miss novel attack patterns

---

### 14.4 Critical Dependencies

| Dependency | Requirement | Risk if Unavailable | Mitigation |
|------------|-------------|---------------------|------------|
| **Microsoft Entra ID SigninLogs** | Continuous ingestion to Sentinel | Complete detection failure | Monitor log ingestion health with alerts |
| **Log Analytics Workspace** | Proper table schema | Query errors | Regular schema validation |
| **Analytics Rule** | Scheduled execution | Missed attacks | Rule health monitoring |
| **Entity Mapping Configuration** | Correct field mapping | Poor incident context | Test after rule creation |

**Monitoring Recommendation:**
```kql
// Check log ingestion health
SigninLogs
| where TimeGenerated > ago(1h)
| summarize Count = count()
| project Result = iif(Count > 0, "Healthy", "No Logs Received")
```

---

### 14.5 Summary: Production-Ready Configuration

```kql
// Production-optimized query with all recommendations
SigninLogs
| where ResultType in ("50053", "50056", "50126")  // Targeted failure codes
| summarize 
    FailedAttempts = count(),
    FailureCodes = make_set(ResultType),
    Applications = make_set(AppDisplayName),
    TimeWindowStart = min(TimeGenerated),
    TimeWindowEnd = max(TimeGenerated)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Entity Mapping Configuration:**
| Sentinel Entity | Source Column |
|-----------------|---------------|
| Account | `UserPrincipalName` |
| IP | `IPAddress` |

**Recommended Rule Set:**
| Rule Name | Granularity | Threshold | Purpose |
|-----------|-------------|-----------|---------|
| Brute-Force - Targeted | User + IP | ≥5 in 5m | Single-source attacks |
| Brute-Force - Distributed | User only | ≥10 in 5m | Multi-source attacks |
| Brute-Force - Scanner | IP only | ≥20 in 5m | Reconnaissance |
| Brute-Force - Privileged | User + IP | ≥3 in 5m | Critical accounts |

## 15. Appendix: Production-Ready Query Library

This appendix contains query variations for different detection scenarios. Each variant addresses specific use cases and can be deployed independently or as part of a multi-rule strategy.

---

### 15.1 Query Variant Matrix

| Variant | Focus Area | Use Case | Key Feature |
|---------|-----------|----------|-------------|
| **Variant A** | Application Context | Identify targeted applications | Adds `AppDisplayName` to aggregation |
| **Variant B** | Privileged Accounts | Stricter monitoring for admins | Lower threshold (≥3) for critical users |
| **Variant C** | Noise Reduction | Exclude trusted internal IPs | Filters out known good sources |
| **Variant D** | Precision Detection | Attack-focused monitoring | Targets specific failure codes only |

---

### 15.2 Detailed Query Variations

#### Variant A: Include Application Context
*Use when you need to identify which applications are being targeted in a brute-force attack.*

```kql
// Purpose: Identifies targeted applications for prioritized response
// Threshold: ≥5 failures in 5 minutes
// Best for: Understanding attack surface and business impact

SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() 
    by UserPrincipalName, IPAddress, AppDisplayName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Sample Output:**
| UserPrincipalName | IPAddress | AppDisplayName | FailedAttempts | TimeWindow |
|-------------------|-----------|----------------|----------------|------------|
| user@domain.com | 203.0.113.45 | Office 365 | 7 | 14:00-14:05 |
| user@domain.com | 203.0.113.45 | Azure Portal | 3 | 14:00-14:05 |

**Investigation Value:** If critical applications (VPN, Admin Portal) are targeted, prioritize response.

---

#### Variant B: Privileged Account Detection (Lower Threshold)
*Use for monitoring administrator, executive, and service accounts with stricter thresholds.*

```kql
// Purpose: Protect high-value accounts with lower tolerance for failures
// Threshold: ≥3 failures in 5 minutes (stricter than standard)
// Best for: Domain admins, executives, service accounts

let PrivilegedUsers = dynamic([
    "admin@domain.com", 
    "serviceaccount@domain.com",
    "ceo@domain.com",
    "it-admin@domain.com"
]);
SigninLogs
| where UserPrincipalName in (PrivilegedUsers)
| where ResultType != 0
| summarize FailedAttempts = count() 
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
```

**Configuration Note:** Replace the email addresses in the `dynamic()` array with your actual privileged users.

**Why Lower Threshold?** 
- Privileged accounts have higher access
- 3 failed attempts may indicate targeted attack
- Faster response required for critical assets

---

#### Variant C: Exclude Known Good IPs
*Use to reduce false positives by filtering out trusted internal networks and known safe IPs.*

```kql
// Purpose: Eliminate noise from internal applications, VPN concentrators, and trusted partners
// Threshold: ≥5 failures in 5 minutes (after filtering)
// Best for: Production environments with internal traffic

let TrustedIPs = dynamic([
    "192.168.1.0/24",  // Internal corporate network
    "10.0.0.0/8",       // Internal data center
    "172.16.0.0/12",    // Internal services
    "203.0.113.0/24"    // Trusted partner IP range
]);
SigninLogs
| where ResultType != 0
| where IPAddress !in (TrustedIPs)
| summarize FailedAttempts = count() 
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**CIDR Notation Note:** The query uses CIDR ranges. Ensure your trusted IPs are properly formatted.

**Expected Impact:**
- ✅ 30-50% reduction in alerts from internal sources
- ✅ Fewer false positives from legitimate services
- ⚠️ Verify trusted IPs before deployment

---

#### Variant D: Specific Failure Codes Only
*Use for precision detection focused only on attack-relevant failure codes.*

```kql
// Purpose: Minimize false positives by targeting only attack-indicative failures
// Threshold: ≥5 failures in 5 minutes
// Best for: High-fidelity detection with minimal noise

SigninLogs
| where ResultType in ("50053", "50056", "50126")  // Lockout, invalid password, invalid credentials
| summarize FailedAttempts = count() 
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Failure Code Reference:**
| Code | Description | Attack Relevance |
|------|-------------|------------------|
| `50053` | Account locked out | 🔴 High - Account under active attack |
| `50056` | Invalid password | 🔴 High - Password guessing in progress |
| `50126` | Invalid username/password | 🔴 High - Primary failure code for most attacks |

**Excluded Codes (Noise Reduction):**
| Code | Description | Why Excluded |
|------|-------------|--------------|
| `50055` | Password expired | Often legitimate user confusion |
| `50057` | Account disabled | Usually admin action |
| `53003` | Conditional access blocked | Policy-based, not attack |

---

### 15.3 Query Comparison Matrix

| Feature | Variant A | Variant B | Variant C | Variant D |
|---------|-----------|-----------|-----------|-----------|
| **Application Context** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Privileged User Focus** | ❌ No | ✅ Yes | ❌ No | ❌ No |
| **IP Filtering** | ❌ No | ❌ No | ✅ Yes | ❌ No |
| **Targeted Failure Codes** | ❌ No | ❌ No | ❌ No | ✅ Yes |
| **Threshold** | ≥5 | ≥3 | ≥5 | ≥5 |
| **False Positive Rate** | Medium | Low-Medium | Low | Very Low |
| **Complexity** | Low | Medium | Medium | Low |

---

### 15.4 Deployment Recommendations

#### Recommended Rule Set for Production

| Priority | Query Variant | Rule Name | Schedule | Use Case |
|----------|--------------|-----------|----------|----------|
| **1** | Variant D | `BF-Precision-Detection` | 5 min | Primary detection (lowest noise) |
| **2** | Variant A | `BF-Application-Context` | 5 min | Investigation enrichment |
| **3** | Variant B | `BF-Privileged-Accounts` | 5 min | Critical asset protection |
| **4** | Variant C | `BF-Trusted-IP-Filter` | 5 min | Internal noise reduction |

#### Implementation Order
```mermaid
graph LR
    A[Start with Variant D] --> B[Add Variant B for admins]
    B --> C[Add Variant A for context]
    C --> D[Add Variant C if needed]
    style A fill:#bfb,stroke:#333
    style B fill:#ffd,stroke:#333
    style C fill:#bbf,stroke:#333
    style D fill:#fbb,stroke:#333
```

---

### 15.5 Combined Enhanced Query (Best of All Worlds)

For maximum effectiveness, here's a query that combines multiple enhancements:

```kql
// Ultimate brute-force detection - Combines all optimizations
let PrivilegedUsers = dynamic(["admin@domain.com", "service@domain.com"]);
let TrustedIPs = dynamic(["192.168.0.0/16", "10.0.0.0/8"]);
SigninLogs
| where ResultType in ("50053", "50056", "50126")  // Targeted failure codes
| where IPAddress !in (TrustedIPs)  // Exclude trusted IPs
| extend IsPrivileged = iif(UserPrincipalName in (PrivilegedUsers), true, false)
| summarize 
    FailedAttempts = count(),
    FailureCodes = make_set(ResultType),
    Applications = make_set(AppDisplayName),
    TimeWindowStart = min(TimeGenerated),
    TimeWindowEnd = max(TimeGenerated)
    by UserPrincipalName, IPAddress, IsPrivileged, bin(TimeGenerated, 5m)
| where (IsPrivileged == true and FailedAttempts >= 3) or 
       (IsPrivileged == false and FailedAttempts >= 5)
| project-away IsPrivileged
```

**What this combined query does:**
- ✅ Targets specific attack-relevant failure codes
- ✅ Excludes trusted internal IPs
- ✅ Applies different thresholds for privileged vs. standard users
- ✅ Provides rich investigation context
- ✅ Single rule covering multiple scenarios

---

### 15.6 Implementation Checklist

- [ ] **Variant A:** Deploy if application targeting intel is needed
- [ ] **Variant B:** Configure with actual privileged user list
- [ ] **Variant C:** Update trusted IP ranges for your environment
- [ ] **Variant D:** Test in production for false positive rate
- [ ] **Combined Query:** Consider for mature Sentinel deployments

### 15.7 Performance Considerations

| Query | Estimated Performance | Best For |
|-------|----------------------|----------|
| Variant A | Fast | Small-medium environments |
| Variant B | Very Fast | Any size (filtered early) |
| Variant C | Fast | Environments with known IPs |
| Variant D | Fastest | High-volume environments |
| Combined | Medium | Advanced deployments |

---

### 15.8 Skills Demonstrated

| Skill | Evidence in This Section |
|-------|-------------------------|
| **KQL Proficiency** | Multiple query variations with different functions |
| **Use Case Analysis** | Each variant mapped to specific scenarios |
| **Production Readiness** | Threshold tuning, IP filtering, performance notes |
| **Documentation** | Clear explanations, tables, and deployment guidance |
| **Security Architecture** | Multi-rule strategy recommendation |




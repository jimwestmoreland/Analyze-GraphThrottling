# Analyze-GraphThrottling

PowerShell diagnostic scripts that identify the root cause of Microsoft Graph API HTTP 429 (Too Many Requests) throttling in a tenant. Includes a full analysis script (requires Entra ID P1/P2) and a lite version that works on any Entra ID tier.

## The Problem

When a tenant exceeds Microsoft Graph API rate limits, all applications in that tenant start receiving `429 Too Many Requests` responses with `Retry-After` headers. This causes noticeable lag in end-user apps like Excel, Outlook, Teams, and any custom integrations that depend on Graph. The challenge is figuring out **which application or automation is consuming the quota** since throttling is tenant-wide but the source could be any registered app, service principal, or user-driven workflow.

## Which Script Should I Use?

| Script | License Required | Data Source | What It Tells You |
|---|---|---|---|
| **Analyze-GraphThrottling.ps1** | Entra ID P1/P2 | Sign-in logs | Actual API call volume, top callers, hourly patterns, failure rates |
| **Analyze-GraphThrottling-Lite.ps1** | Entra ID Free | App registrations & permissions | Which apps *could* be throttling based on permissions, credentials, and risk scoring |

- **Have P1/P2?** Use the full script. It gives you definitive answers.
- **No P1/P2 (or unsure)?** Start with the lite script. It narrows the suspect list based on permission footprint, then upgrade to the full script if you can get P1/P2 access.
- **Use both together:** Run the lite script first for a quick inventory, then the full script for confirmation with actual call volume data.

---

## Analyze-GraphThrottling.ps1 (Full)

The full script queries Entra ID sign-in logs via the Microsoft Graph PowerShell SDK and produces:

1. **Detailed data tables** (Analyses A-G) showing raw rankings
2. **Automated findings** with cross-correlated insights and severity ratings (LOW/MEDIUM/HIGH/CRITICAL)
3. **Actionable recommendations** based on the data
4. **A structured report file** summarizing everything in a shareable format

### Data Collection (Analyses A-G)

| Analysis | Description |
|---|---|
| **A. Top Applications** | Which apps are making the most Graph API calls and their share of total volume |
| **B. Top Users** | Which user accounts are generating the most sign-in activity (filtered by app or across all apps) |
| **C. Hourly Pattern** | Call volume by hour to reveal automation spikes vs. normal business-hours usage |
| **D. Service Principals** | Daemon/automation apps calling Graph without a user context (common source of over-consumption) |
| **E. Failed/Throttled Sign-ins** | Error breakdown to identify retry storms or authentication failures compounding the problem |
| **F. Source IPs** | IP address concentration to locate specific servers or subnets driving the load |
| **G. Calls Per Minute** | Per-app average call rate with risk rating (LOW/MEDIUM/HIGH) relative to Graph API limits |

### Automated Findings

After collecting data, the script cross-correlates results to produce specific findings such as:

- **Dominant application detection** - Flags apps accounting for 30%+ of traffic with their App ID
- **IP concentration analysis** - Identifies servers generating disproportionate traffic and maps them to the apps running on them
- **Service principal correlation** - Links high-volume automation apps to their source IPs
- **Rate limit proximity** - Flags apps averaging 500+ calls/min with MEDIUM/HIGH/CRITICAL risk
- **Spike detection** - Identifies hours with 3x+ the average volume and checks for off-hours automation patterns
- **Failure amplification** - Detects high failure rates that may indicate retry storms compounding throttling
- **User concentration** - Flags individual accounts generating 25%+ of traffic (possible service accounts)

## Requirements

| Requirement | Details |
|---|---|
| **PowerShell** | 5.1+ or PowerShell 7+ |
| **Module** | Microsoft Graph PowerShell SDK (`Install-Module Microsoft.Graph -Scope CurrentUser`) |
| **License** | Entra ID P1 or P2 (required for sign-in log access; without it, queries return 403) |
| **Entra ID Role** | Security Reader or Reports Reader (least-privilege); Global Reader also works |
| **Graph Permissions** | `AuditLog.Read.All` and `Directory.Read.All` (delegated, consented at interactive login) |
| **Network** | Outbound HTTPS (443) to `graph.microsoft.com` and `login.microsoftonline.com` |

If the tenant requires admin consent for Graph permissions, a Global Admin or Privileged Role Administrator must pre-approve them in **Entra ID > Enterprise Applications > Microsoft Graph Command Line Tools > Permissions**.

## Usage

```powershell
# Default: last 24 hours, auto-detect tenant size, scope analysis accordingly
.\Analyze-GraphThrottling.ps1

# Last 3 days with CSV export
.\Analyze-GraphThrottling.ps1 -DaysBack 3 -ExportCsv

# Force large-tenant mode (100K record cap per query, skips the volume probe)
.\Analyze-GraphThrottling.ps1 -ScopeProfile Large

# Full 7-day pull with no cap (WARNING: can take hours on large tenants)
.\Analyze-GraphThrottling.ps1 -ScopeProfile Full -DaysBack 7 -ExportCsv

# Small-tenant mode - fetches all records for complete analysis
.\Analyze-GraphThrottling.ps1 -ScopeProfile Small

# Manually set the record cap (overrides auto-detected scope profile)
.\Analyze-GraphThrottling.ps1 -MaxRecords 100000

# Focus on a specific application by its App ID
.\Analyze-GraphThrottling.ps1 -AppIdFilter "d3590ed6-52b3-4102-aeff-aad2292ab01c"
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-DaysBack` | int | `1` | Number of days of sign-in history to query |
| `-MaxRecords` | int | `50000` | Maximum records to retrieve per query (prevents excessively long runs) |
| `-FetchAll` | switch | off | Remove the record cap and retrieve all matching records (can take hours) |
| `-ExportCsv` | switch | off | Export raw sign-in data to CSV files in the output folder |
| `-OutputFolder` | string | `.\GraphThrottlingAnalysis` | Directory for the transcript report and CSV exports |
| `-AppIdFilter` | string | none | Filter Step 2 analysis to a specific application by its Entra ID App ID |
| `-ScopeProfile` | string | `Auto` | Tenant sizing profile that controls record caps and query behavior. Values: `Auto`, `Small`, `Medium`, `Large`, `Full` |

## Scale Handling

The script automatically adapts to tenant size via the `-ScopeProfile` parameter. On first run (or when set to `Auto`), it probes the tenant's sign-in log volume and selects the appropriate profile.

### Scope Profiles

| Profile | Estimated Volume | Record Cap | Behavior |
|---|---|---|---|
| **Auto** (default) | - | Varies | Probes the tenant, then selects Small/Medium/Large automatically |
| **Small** | Up to 10K | Unlimited | Enables `-FetchAll` for complete analysis. Suitable for dev/test tenants. |
| **Medium** | 10K - 100K | 50,000 | Standard capped queries. Good balance of coverage and run time. |
| **Large** | 100K+ | 100,000 | Higher cap with sampling. Appropriate for enterprise tenants with heavy Graph usage. |
| **Full** | Any | Unlimited | Fetches all records regardless of volume. Can take hours on large tenants. Use when you need complete data. |

### How Auto-Detection Works

1. After connecting to Graph, the script issues a lightweight probe using the `$count` OData header.
2. If `$count` is not supported by the tenant, it falls back to sampling the last hour and extrapolating.
3. Based on the estimated volume, it maps to a profile and adjusts `MaxRecords` accordingly.
4. Auto-detection never selects `Full` - you must explicitly choose it if you need an uncapped query on a large tenant.
5. If you explicitly pass `-MaxRecords` or `-FetchAll`, your value takes precedence over the profile.

### Choosing a Profile

- For most tenants, just use the default (`Auto`). It does the right thing.
- If Auto underestimates (you see "capped" warnings in the results), re-run with `-ScopeProfile Large` or `-ScopeProfile Full`.
- If you know the tenant is large and want to skip the probe, pass `-ScopeProfile Large` directly.
- Use `-ScopeProfile Full -DaysBack 7 -ExportCsv` for the most thorough analysis when time is not a constraint.

## Output

Every run produces at minimum 2 files in the output folder:

| File | Always Created | Description |
|---|---|---|
| `ThrottlingReport_<timestamp>.txt` | Yes | Structured findings report with risk assessment, findings, recommendations, and top-10 tables for apps/users/IPs/service principals. Designed for sharing. |
| `AnalysisReport_<timestamp>.txt` | Yes | Full console transcript (raw log of everything displayed) |
| `AllGraphSignIns_<timestamp>.csv` | With `-ExportCsv` | All Graph API sign-in records |
| `FilteredAppSignIns_<timestamp>.csv` | With `-ExportCsv` + `-AppIdFilter` | Sign-ins for the specified app only |
| `ServicePrincipalSignIns_<timestamp>.csv` | With `-ExportCsv` | Daemon/automation sign-in records |

### Report Structure

The `ThrottlingReport_<timestamp>.txt` file contains:

1. **Risk Assessment** - Overall severity (LOW/MEDIUM/HIGH/CRITICAL)
2. **Data Summary** - Record counts for each query
3. **Findings** - Numbered, severity-tagged findings with cross-correlated details
4. **Recommendations** - Specific actions to take based on findings
5. **Top 10 Tables** - Applications, users, source IPs (with app mapping), service principals (with IP mapping), and peak hours

## How to Interpret Results

The script does most of the interpretation for you. The **Automated Findings** section in both the console output and the report file provides severity-rated conclusions with the specific app names, App IDs, IPs, and percentages. The **Recommendations** section suggests concrete next steps.

For manual review, look for these patterns in the data tables:

- **One app dominates the call count** - That app (or its configuration) is the primary consumer. Check if it has a misconfigured polling interval, a tight retry loop, or is fetching data it doesn't need.
- **A single service principal has high volume** - This is typically a script, Power Automate flow, Logic App, or custom integration running on a schedule. Find the owner and reduce the call frequency.
- **One IP address produces most of the traffic** - A specific server is the source. Track it down via your CMDB or IP management system.
- **Spikes in off-hours** - Overnight or weekend bursts usually indicate scheduled jobs or batch processes.
- **HIGH/CRITICAL risk rating in Analysis G** - An app averaging over 1,000 Graph calls per minute is likely at or near the throttling threshold.

## Known Limitations

- **Sign-in logs are not real-time.** Entra ID sign-in logs can have a delay of up to 15 minutes. The script analyzes historical patterns, not live traffic.
- **Sign-in logs don't capture every Graph API call.** They record token acquisition events, not individual HTTP requests. A single sign-in may result in hundreds of Graph calls using the cached token. Actual API call volume is higher than what the logs show.
- **Record cap may miss the full picture.** Even with auto-sizing, the `Medium` and `Large` profiles apply record caps for practical run times. If you see "(capped)" warnings in the output, re-run with `-ScopeProfile Full` for complete coverage.
- **Service principal queries may require app-level permissions.** If using delegated permissions, some service principal sign-in data may not be accessible.

## Future Enhancements

The following additions would improve the diagnostic value of this tool:

1. **Managed Identity sign-in analysis** - Adding `managedIdentity` as a sign-in type would capture Azure-hosted workloads (VMs, Functions, Logic Apps) that are a common source of runaway Graph calls but currently excluded from Step 4.

2. **Minute-level burst detection** - Analysis C groups by hour, but Graph enforces per-minute limits. Drilling into the peak hour at minute granularity would reveal the actual burst that triggers throttling.

3. **Resource/endpoint breakdown** - Grouping by `ResourceDisplayName` would show whether calls target Microsoft Graph, Office 365 Exchange Online, SharePoint, etc., narrowing down which endpoint is under pressure.

4. **Conditional Access failure correlation** - The `ConditionalAccessStatus` field is captured but never analyzed. A CA-failure breakdown could reveal whether throttling is compounded by retry storms from blocked policies.

5. **HTML report export** - A `-ExportHtml` switch producing a self-contained HTML report with formatted tables would be more shareable than the plain-text transcript.

---

## Analyze-GraphThrottling-Lite.ps1 (No P1/P2 Required)

The lite script takes a fundamentally different approach. Instead of analyzing *who is calling* Graph (which requires sign-in logs and P1/P2), it inventories *who can call* Graph and scores each app by its throttling risk based on permissions, credentials, and configuration.

### What the Lite Script Analyzes

| Analysis | Description |
|---|---|
| **A. Risk Score Ranking** | Apps ranked by a composite risk score based on permission type, breadth, credential status, and audience |
| **B. Daemon Apps** | Apps with application-level (not delegated) Graph permissions that can run unattended - the most common throttling source |
| **C. Permission Breadth** | Apps ranked by total number of Graph scopes - more scopes means more diverse API usage |
| **D. Multi-Tenant Apps** | Apps configured for external access that may receive calls from outside your organization |
| **E. Credential Status** | Which apps have active vs. expired credentials - apps without credentials cannot be the source |
| **F. Granted Permissions** | Service principals with admin-consented application permissions (confirmed active, not just requested) |

### Risk Scoring

Each app receives a composite risk score (0-100) based on:

| Factor | Points | Rationale |
|---|---|---|
| Has application-level permissions | +30 | Daemon/automation apps are the primary throttling source |
| 20+ Graph scopes | +25 | Broad API footprint suggests heavy, diverse usage |
| 10-19 Graph scopes | +15 | Moderate API breadth |
| 5-9 Graph scopes | +5 | Modest footprint |
| Active credentials (secrets/certs) | +20 | Can authenticate and run right now |
| High-volume permission patterns | +15 | Mail, Calendar, Files, Users, Groups, Sites, Directory scopes |
| Multi-tenant audience | +10 | External callers may contribute to quota consumption |

### Lite Script Requirements

| Requirement | Details |
|---|---|
| **PowerShell** | 5.1+ or PowerShell 7+ |
| **Module** | Microsoft Graph PowerShell SDK (`Install-Module Microsoft.Graph -Scope CurrentUser`) |
| **License** | **Entra ID Free** (any tier - no P1/P2 needed) |
| **Entra ID Role** | Global Reader (least-privilege); Application Administrator also works |
| **Graph Permissions** | `Application.Read.All` and `Directory.Read.All` (delegated, consented at interactive login) |

### Lite Script Usage

```powershell
# Default: inventory all apps with Graph permissions
.\Analyze-GraphThrottling-Lite.ps1

# Export the full app inventory to CSV
.\Analyze-GraphThrottling-Lite.ps1 -ExportCsv

# Include Microsoft first-party apps (excluded by default)
.\Analyze-GraphThrottling-Lite.ps1 -IncludeFirstParty

# Focus on a specific application
.\Analyze-GraphThrottling-Lite.ps1 -AppIdFilter "d3590ed6-52b3-4102-aeff-aad2292ab01c"
```

### Lite Script Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-ExportCsv` | switch | off | Export the full app inventory to a CSV file |
| `-OutputFolder` | string | `.\GraphThrottlingAnalysis` | Directory for the report and CSV exports |
| `-AppIdFilter` | string | none | Focus analysis on a specific application by its Entra ID App ID |
| `-IncludeFirstParty` | switch | off | Include Microsoft first-party apps in Analysis F (excluded by default) |

### Lite Script Output

| File | Always Created | Description |
|---|---|---|
| `LiteThrottlingReport_<timestamp>.txt` | Yes | Structured findings report with risk scores, suspect list, and recommendations |
| `LiteAnalysisReport_<timestamp>.txt` | Yes | Full console transcript |
| `AppInventory_<timestamp>.csv` | With `-ExportCsv` | Complete app inventory with permissions, credentials, and risk scores |

### Limitations of the Lite Script

- **Cannot measure actual call volume.** It identifies apps that *could* cause throttling based on their permission footprint, not apps that *are* causing it.
- **Risk scores are heuristic.** An app with a high risk score and broad permissions may be dormant, while a low-scored app with a single permission could be polling aggressively.
- **First-party Microsoft apps are excluded by default.** Apps like Microsoft Teams, SharePoint, and Exchange Online are rarely customer-controllable. Use `-IncludeFirstParty` to see them.
- **Owner data may be incomplete.** Not all app registrations have assigned owners in Entra ID.

## License

This project is provided as-is under the [MIT License](LICENSE).

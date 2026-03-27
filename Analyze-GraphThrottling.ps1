<#
.SYNOPSIS
    Analyzes Microsoft Graph API usage to identify the source of HTTP 429
    throttling in a tenant.

.DESCRIPTION
    This script queries Entra ID sign-in logs via Microsoft Graph to find:
    1. Which apps/service principals are making the most Graph API calls
    2. Which users or automation accounts are the top callers
    3. Frequency patterns that explain why the tenant is being throttled
    4. Service principal (daemon/automation) call volume
    5. Failed and potentially throttled sign-in attempts
    6. Source IP concentration that may indicate runaway automation

.NOTES
    ===============================================================
    REQUIREMENTS
    ===============================================================

    1. SOFTWARE
       - PowerShell 5.1+ or PowerShell 7+
       - Microsoft Graph PowerShell SDK
         Install:  Install-Module Microsoft.Graph -Scope CurrentUser
         Modules used: Microsoft.Graph.Authentication, Microsoft.Graph.Reports

    2. LICENSING
       - Entra ID P1 or P2 (formerly Azure AD Premium) (required to access sign-in logs)
       - Without P1/P2, sign-in log queries will return 403 Forbidden

    3. ENTRA ID ROLES (one of the following is sufficient)
       +------------------------------+--------------------------------------------+
       | Role                         | Notes                                      |
       +------------------------------+--------------------------------------------+
       | Global Administrator         | Full access - works but overprivileged     |
       | Global Reader                | Read-only tenant-wide - recommended        |
       | Security Administrator       | Grants AuditLog.Read.All + Directory read  |
       | Security Reader              | Read-only security data - recommended      |
       | Reports Reader               | Grants AuditLog.Read.All - minimum role    |
       +------------------------------+--------------------------------------------+

       ** Recommended: Security Reader or Reports Reader (least-privilege) **

    4. MICROSOFT GRAPH API PERMISSIONS (granted interactively at sign-in)
       - AuditLog.Read.All  - read sign-in and audit logs
       - Directory.Read.All - read directory data (app registrations, service principals)
       These are delegated permissions consented via the interactive login prompt.
       If the tenant requires admin consent for these scopes, a Global Admin or
       Privileged Role Administrator must pre-approve them in Entra ID > Enterprise
       Applications > Microsoft Graph Command Line Tools > Permissions.

    5. NETWORK
       - Outbound HTTPS (443) to graph.microsoft.com and login.microsoftonline.com
       - If behind a proxy, ensure Graph PowerShell can authenticate

    ===============================================================

    Run time: 5-15 minutes depending on tenant sign-in log volume

.EXAMPLE
    .\Analyze-GraphThrottling.ps1
    # Default: last 24 hours, auto-detect tenant size, scope analysis accordingly

    .\Analyze-GraphThrottling.ps1 -DaysBack 3 -ExportCsv
    # Last 3 days with CSV export

    .\Analyze-GraphThrottling.ps1 -ScopeProfile Large
    # Force large-tenant mode (100K record cap per query, optimized for scale)

    .\Analyze-GraphThrottling.ps1 -ScopeProfile Full -DaysBack 7 -ExportCsv
    # Full 7-day pull with no cap (WARNING: can take hours on large tenants)

    .\Analyze-GraphThrottling.ps1 -ScopeProfile Small
    # Small-tenant mode - fetches all records for complete analysis

    .\Analyze-GraphThrottling.ps1 -MaxRecords 100000
    # Manually set the record cap (overrides auto-detected scope profile)

    .\Analyze-GraphThrottling.ps1 -AppIdFilter "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    # Focus analysis on a specific application (e.g., Microsoft Office)
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 1,
    [int]$MaxRecords = 50000,
    [switch]$FetchAll,
    [switch]$ExportCsv,
    [string]$OutputFolder = ".\GraphThrottlingAnalysis",
    [string]$AppIdFilter,
    [ValidateSet("Auto","Small","Medium","Large","Full")]
    [string]$ScopeProfile = "Auto"
)

$ErrorActionPreference = "Stop"

# -- Configuration --

$StartDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

# -- Start logging all output to a file --
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$transcriptPath = Join-Path $OutputFolder "AnalysisReport_$timestamp.txt"
try { Stop-Transcript -ErrorAction SilentlyContinue } catch { $null = $_ }
Start-Transcript -Path $transcriptPath -Force | Out-Null

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Graph API Throttling Analysis Script" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Parameters:" -ForegroundColor Yellow
Write-Host "  Days back:    $DaysBack (since $StartDate)"
if ($FetchAll) {
    Write-Host "  Max records:  UNLIMITED (-FetchAll)" -ForegroundColor Yellow
} else {
    Write-Host "  Max records:  $MaxRecords (use -FetchAll to retrieve everything)"
}
if ($AppIdFilter) {
    Write-Host "  App filter:   $AppIdFilter"
}
$scopeNote = if ($ScopeProfile -eq 'Auto') { ' (will auto-detect after connecting)' } else { '' }
Write-Host "  Scope:        $ScopeProfile$scopeNote"
Write-Host "  Export CSV:   $ExportCsv"
Write-Host ""

# -- Helper: Capped paging to avoid hour-long queries on large tenants --
function Get-CappedSignIn {
    param(
        [string]$Filter,
        [string]$SignInType,
        [int]$Cap,
        [bool]$Unlimited
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $params = @{ Filter = $Filter; PageSize = 999; Top = 999 }
    if ($SignInType) { $params['SignInType'] = $SignInType }

    if ($Unlimited) {
        # Fetch everything - can take hours on large tenants
        $params.Remove('Top')
        $params['All'] = $true
        Get-MgAuditLogSignIn @params | ForEach-Object { $results.Add($_) }
    }
    else {
        # Page manually up to the cap
        $batch = Get-MgAuditLogSignIn @params
        while ($batch) {
            foreach ($item in $batch) {
                $results.Add($item)
                if ($results.Count -ge $Cap) { break }
            }
            if ($results.Count -ge $Cap) { break }
            # Get next page via -All with pipeline break
            $batch = $null  # Get-MgAuditLogSignIn doesn't expose a native cursor easily
        }
        # Fallback: use -All but break the pipeline after Cap records
        if ($results.Count -eq 0) {
            $params.Remove('Top')
            $params['All'] = $true
            $count = 0
            Get-MgAuditLogSignIn @params | ForEach-Object {
                if ($count -lt $Cap) {
                    $results.Add($_)
                    $count++
                }
            }
        }
    }
    return $results
}

# -- Step 0: Ensure Microsoft Graph PowerShell SDK is installed --
Write-Host "[Step 0/6] Checking for Microsoft Graph PowerShell SDK..." -ForegroundColor Green
$graphModule = Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication" | Select-Object -First 1
if (-not $graphModule) {
    Write-Host "  Microsoft Graph SDK not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
        Write-Host "  Installed successfully." -ForegroundColor White
    }
    catch {
        Write-Error "  Failed to install Microsoft.Graph module: $($_.Exception.Message)`n  Please run manually: Install-Module Microsoft.Graph -Scope CurrentUser"
        return
    }
}
else {
    Write-Host "  Found Microsoft.Graph.Authentication v$($graphModule.Version)" -ForegroundColor DarkGray
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Reports -ErrorAction Stop
Write-Host ""

# -- Step 1: Connect to Microsoft Graph --
Write-Host "[Step 1/6] Connecting to Microsoft Graph..." -ForegroundColor Green
try {
    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected"
    }
    Write-Host "  Already connected as: $($context.Account)" -ForegroundColor DarkGray
}
catch {
    Write-Host "  Requesting sign-in with required permissions..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -NoWelcome
    $context = Get-MgContext
    Write-Host "  Connected as: $($context.Account)" -ForegroundColor DarkGray
}
Write-Host ""

# -- Step 1.5: Estimate log volume and configure scope --
Write-Host "[Step 1.5/6] Estimating sign-in log volume..." -ForegroundColor Green

$estimatedVolume = 0
$scopeLabel = ""
try {
    # Probe: fetch a small sample to estimate total volume
    $probeFilter = "resourceDisplayName eq 'Microsoft Graph' and createdDateTime ge $StartDate"
    $probeParams = @{ Filter = $probeFilter; Top = 1; Select = @("createdDateTime") }
    $probeResult = Get-MgAuditLogSignIn @probeParams -CountVariable probeCount -ConsistencyLevel "eventual" -ErrorAction SilentlyContinue
    if ($probeCount -and $probeCount -gt 0) {
        $estimatedVolume = $probeCount
    }
}
catch {
    # $count header not supported in all tenants; fall back to sample-based estimate
}

# If $count wasn't available, estimate from a timed sample
if ($estimatedVolume -eq 0) {
    try {
        Write-Host "  Count header not available; sampling to estimate volume..." -ForegroundColor DarkGray
        $sampleStart = (Get-Date).AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $sampleFilter = "resourceDisplayName eq 'Microsoft Graph' and createdDateTime ge $sampleStart"
        $sampleParams = @{ Filter = $sampleFilter; Top = 999; All = $true }
        $sampleCount = 0
        Get-MgAuditLogSignIn @sampleParams | ForEach-Object {
            if ($sampleCount -lt 2000) {
                $sampleCount++
            }
        }
        # Extrapolate: if we got 2000 in 1 hour, multiply by hours in the window
        $hoursInWindow = $DaysBack * 24
        if ($sampleCount -ge 2000) {
            $estimatedVolume = $sampleCount * $hoursInWindow  # likely much more
            Write-Host "  Sample hit 2,000 in 1 hour - estimating $($estimatedVolume.ToString('N0'))+ records over $DaysBack day(s)" -ForegroundColor DarkGray
        }
        elseif ($sampleCount -gt 0) {
            $estimatedVolume = $sampleCount * $hoursInWindow
            Write-Host "  Sample: $sampleCount records in last hour - estimating $($estimatedVolume.ToString('N0')) records over $DaysBack day(s)" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "  Could not estimate volume; using defaults." -ForegroundColor DarkGray
    }
}
else {
    Write-Host "  Estimated Graph sign-in volume: $($estimatedVolume.ToString('N0')) records" -ForegroundColor DarkGray
}

# Determine scope profile
if ($ScopeProfile -eq "Auto") {
    if ($estimatedVolume -le 10000) {
        $ScopeProfile = "Small"
    }
    elseif ($estimatedVolume -le 100000) {
        $ScopeProfile = "Medium"
    }
    elseif ($estimatedVolume -le 500000) {
        $ScopeProfile = "Large"
    }
    else {
        $ScopeProfile = "Large"  # Cap at Large for auto; user must explicitly choose Full
    }
    Write-Host "  Auto-detected scope profile: $ScopeProfile (estimated $($estimatedVolume.ToString('N0')) records)" -ForegroundColor White
}
else {
    Write-Host "  Using manually selected scope profile: $ScopeProfile" -ForegroundColor White
}

# Apply scope profile settings (only override MaxRecords if the user didn't explicitly set it or use -FetchAll)
$scopeSettings = switch ($ScopeProfile) {
    "Small" {
        @{ MaxRecords = 10000;  Description = "Small tenant (<10K records) - full analysis" }
    }
    "Medium" {
        @{ MaxRecords = 50000;  Description = "Medium tenant (10K-100K records) - sampled analysis" }
    }
    "Large" {
        @{ MaxRecords = 100000; Description = "Large tenant (100K+ records) - capped analysis with sampling" }
    }
    "Full" {
        @{ MaxRecords = [int]::MaxValue; Description = "Full analysis - no record cap (may take hours)" }
    }
}

# Only override MaxRecords if user didn't explicitly pass -MaxRecords or -FetchAll
$defaultMaxRecords = 50000
if (-not $FetchAll -and $MaxRecords -eq $defaultMaxRecords) {
    $MaxRecords = $scopeSettings.MaxRecords
}
if ($FetchAll) {
    $MaxRecords = [int]::MaxValue
}
# For Full profile, treat as FetchAll
if ($ScopeProfile -eq "Full") {
    $FetchAll = [switch]$true
}

# For Small tenants, also enable FetchAll since the volume is manageable
if ($ScopeProfile -eq "Small" -and -not $FetchAll) {
    $FetchAll = [switch]$true
    Write-Host "  Small tenant detected - fetching all records for complete analysis" -ForegroundColor DarkGray
}

Write-Host "  Profile: $($scopeSettings.Description)" -ForegroundColor DarkGray
$effectiveMax = if ($FetchAll) { 'UNLIMITED' } else { $MaxRecords.ToString('N0') }
Write-Host "  Effective max records per query: $effectiveMax" -ForegroundColor DarkGray

# Warn if large volume with default time window
if ($estimatedVolume -gt 500000 -and $ScopeProfile -ne "Full") {
    Write-Host ""
    Write-Host "  WARNING: Estimated volume exceeds 500K records." -ForegroundColor Yellow
    Write-Host "  Consider narrowing the time window (-DaysBack 1) or running with" -ForegroundColor Yellow
    Write-Host "  -ScopeProfile Full if you need complete data (expect long run times)." -ForegroundColor Yellow
}
Write-Host ""

# -- Step 2: Query sign-in logs for a specific app (if -AppIdFilter provided) --
$filteredAppSignIns = @()
if ($AppIdFilter) {
    Write-Host "[Step 2/6] Querying sign-in logs for app $AppIdFilter..." -ForegroundColor Green
    Write-Host "  Filter: appId eq '$AppIdFilter' and createdDateTime ge $StartDate" -ForegroundColor DarkGray
    Write-Host "  This may take a few minutes for large tenants..." -ForegroundColor DarkGray

    $filter = "appId eq '$AppIdFilter' and createdDateTime ge $StartDate"
    try {
        $raw = Get-CappedSignIn -Filter $filter -Cap $MaxRecords -Unlimited $FetchAll.IsPresent
        $filteredAppSignIns = $raw | Select-Object CreatedDateTime, UserPrincipalName, UserDisplayName, AppId, AppDisplayName,
                          ResourceDisplayName, ResourceId, IpAddress, Location,
                          @{N='StatusCode';E={$_.Status.ErrorCode}},
                          @{N='StatusReason';E={$_.Status.FailureReason}},
                          ConditionalAccessStatus, ClientAppUsed, DeviceDetail
    }
    catch {
        Write-Warning "  Failed to query sign-in logs: $($_.Exception.Message)"
        Write-Warning "  Ensure you have AuditLog.Read.All permission and Entra ID P1/P2 license."
    }

    if (-not $FetchAll -and $filteredAppSignIns.Count -ge $MaxRecords) { $cappedNote = " (capped at $MaxRecords)" } else { $cappedNote = "" }
    if ($filteredAppSignIns.Count -gt 0) { $appName = $filteredAppSignIns[0].AppDisplayName } else { $appName = $AppIdFilter }
    Write-Host "  Found $($filteredAppSignIns.Count) sign-in entries for $appName$cappedNote" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "[Step 2/6] Skipping app-specific query (use -AppIdFilter to target a specific app)" -ForegroundColor DarkGray
    Write-Host ""
}

# -- Step 3: Query ALL Graph API sign-ins (all apps) --
Write-Host "[Step 3/6] Querying ALL sign-ins targeting Microsoft Graph resource..." -ForegroundColor Green
Write-Host "  This identifies ALL apps consuming Graph API quota..." -ForegroundColor DarkGray

$graphFilter = "resourceDisplayName eq 'Microsoft Graph' and createdDateTime ge $StartDate"
$allGraphSignIns = @()
try {
    $fetchLabel = if ($FetchAll) { 'ALL' } else { $MaxRecords }
    Write-Host "  Fetching up to $fetchLabel records (this is the largest query)..." -ForegroundColor DarkGray
    $raw = Get-CappedSignIn -Filter $graphFilter -Cap $MaxRecords -Unlimited $FetchAll.IsPresent
    $allGraphSignIns = $raw | Select-Object CreatedDateTime, UserPrincipalName, UserDisplayName, AppId, AppDisplayName,
                      ResourceDisplayName, IpAddress,
                      @{N='StatusCode';E={$_.Status.ErrorCode}},
                      @{N='StatusReason';E={$_.Status.FailureReason}},
                      ClientAppUsed
}
catch {
    Write-Warning "  Failed to query all Graph sign-ins: $($_.Exception.Message)"
}

if (-not $FetchAll -and $allGraphSignIns.Count -ge $MaxRecords) { $cappedNote = " (CAPPED at $MaxRecords - use -FetchAll for complete data)" } else { $cappedNote = "" }
Write-Host "  Found $($allGraphSignIns.Count) total Graph API sign-in entries (all apps)$cappedNote" -ForegroundColor White
Write-Host ""

# -- Step 4: Query service principal sign-ins (automation/daemon apps) --
Write-Host "[Step 4/6] Querying service principal sign-ins (automation/daemon apps)..." -ForegroundColor Green
Write-Host "  These are app-only calls (no user context) - common source of over-consumption..." -ForegroundColor DarkGray

$spSignIns = @()
try {
    $spFilter = "createdDateTime ge $StartDate"
    $raw = Get-CappedSignIn -Filter $spFilter -SignInType "servicePrincipal" -Cap $MaxRecords -Unlimited $FetchAll.IsPresent
    $spSignIns = $raw | Where-Object { $_.ResourceDisplayName -eq "Microsoft Graph" } |
        Select-Object CreatedDateTime, AppId, AppDisplayName, ResourceDisplayName, IpAddress,
                      @{N='ServicePrincipalId';E={$_.ServicePrincipalId}},
                      @{N='StatusCode';E={$_.Status.ErrorCode}},
                      @{N='StatusReason';E={$_.Status.FailureReason}}
}
catch {
    Write-Warning "  Service principal sign-in query not available or failed: $($_.Exception.Message)"
    Write-Host "  (This is expected if using delegated permissions - try with application permissions)" -ForegroundColor DarkGray
}

if (-not $FetchAll -and $spSignIns.Count -ge $MaxRecords) { $cappedNote = " (capped at $MaxRecords)" } else { $cappedNote = "" }
Write-Host "  Found $($spSignIns.Count) service principal Graph API entries$cappedNote" -ForegroundColor White
Write-Host ""

# ==================================================================
# Analysis
# ==================================================================

Write-Host "[Step 5/6] Analyzing results..." -ForegroundColor Green
Write-Host ""

# -- Analysis A: Top apps by Graph API call count --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  A. TOP APPLICATIONS BY GRAPH API CALL COUNT" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

if ($allGraphSignIns.Count -gt 0) {
    $appBreakdown = $allGraphSignIns |
        Group-Object AppDisplayName, AppId |
        Sort-Object Count -Descending |
        Select-Object -First 20 @{N='Application';E={$_.Values[0]}},
                                 @{N='AppId';E={$_.Values[1]}},
                                 Count,
                                 @{N='PctOfTotal';E={[math]::Round($_.Count / $allGraphSignIns.Count * 100, 1)}}

    $appBreakdown | Format-Table -AutoSize

    if ($appBreakdown.Count -gt 0) {
        Write-Host "  >> Top consumer: $($appBreakdown[0].Application) with $($appBreakdown[0].Count) calls ($($appBreakdown[0].PctOfTotal)% of total)" -ForegroundColor Yellow
    }
    Write-Host ""
}
else {
    Write-Host "  No data available." -ForegroundColor DarkGray
}

# -- Analysis B: Top users making Graph calls (filtered app or all) --
if ($AppIdFilter) {
    if ($filteredAppSignIns.Count -gt 0) { $appLabel = $filteredAppSignIns[0].AppDisplayName } else { $appLabel = $AppIdFilter }
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "  B. TOP USERS MAKING GRAPH CALLS ($appLabel)" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan

    if ($filteredAppSignIns.Count -gt 0) {
        $userBreakdown = $filteredAppSignIns |
            Group-Object UserPrincipalName |
            Sort-Object Count -Descending |
            Select-Object -First 25 @{N='User';E={$_.Name}},
                                      Count,
                                      @{N='PctOfApp';E={[math]::Round($_.Count / $filteredAppSignIns.Count * 100, 1)}}

        $userBreakdown | Format-Table -AutoSize

        Write-Host "  >> Top user: $($userBreakdown[0].User) with $($userBreakdown[0].Count) calls" -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "  No sign-in data for filtered app." -ForegroundColor DarkGray
    }
} else {
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "  B. TOP USERS MAKING GRAPH API CALLS (all apps)" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan

    if ($allGraphSignIns.Count -gt 0) {
        $userBreakdown = $allGraphSignIns |
            Group-Object UserPrincipalName |
            Sort-Object Count -Descending |
            Select-Object -First 25 @{N='User';E={$_.Name}},
                                      Count,
                                      @{N='PctOfTotal';E={[math]::Round($_.Count / $allGraphSignIns.Count * 100, 1)}}

        $userBreakdown | Format-Table -AutoSize

        Write-Host "  >> Top user: $($userBreakdown[0].User) with $($userBreakdown[0].Count) calls" -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "  No Graph API sign-in data." -ForegroundColor DarkGray
    }
}

# -- Analysis C: Hourly pattern (identify automation spikes) --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  C. HOURLY CALL PATTERN (identifies automation spikes)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

if ($allGraphSignIns.Count -gt 0) {
    $hourlyPattern = $allGraphSignIns |
        Group-Object { $_.CreatedDateTime.ToString("yyyy-MM-dd HH:00") } |
        Sort-Object Name |
        Select-Object @{N='Hour';E={$_.Name}}, Count

    # Show top 20 busiest hours
    Write-Host "  Top 20 busiest hours:" -ForegroundColor White
    $hourlyPattern | Sort-Object Count -Descending | Select-Object -First 20 | Format-Table -AutoSize

    $avgPerHour = [math]::Round(($hourlyPattern | Measure-Object -Property Count -Average).Average, 0)
    $maxHour = ($hourlyPattern | Sort-Object Count -Descending | Select-Object -First 1)
    Write-Host "  >> Average: $avgPerHour calls/hour | Peak: $($maxHour.Count) calls at $($maxHour.Hour)" -ForegroundColor Yellow
    Write-Host ""
}

# -- Analysis D: Service principal / daemon apps --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  D. SERVICE PRINCIPAL (DAEMON/AUTOMATION) GRAPH CALLS" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

if ($spSignIns.Count -gt 0) {
    $spBreakdown = $spSignIns |
        Group-Object AppDisplayName, AppId |
        Sort-Object Count -Descending |
        Select-Object -First 15 @{N='Application';E={$_.Values[0]}},
                                 @{N='AppId';E={$_.Values[1]}},
                                 Count

    $spBreakdown | Format-Table -AutoSize

    Write-Host "  ** These are app-only (no user) calls - automation, scripts, Power Automate **" -ForegroundColor Yellow
    Write-Host "  ** If any of these are making excessive /organization calls, they are likely the cause **" -ForegroundColor Yellow
    Write-Host ""
}
else {
    Write-Host "  No service principal data (may require application-level permissions to query)." -ForegroundColor DarkGray
    Write-Host ""
}

# -- Analysis E: Failed/throttled sign-ins --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  E. FAILED / THROTTLED SIGN-IN ATTEMPTS" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

$failedSignIns = $allGraphSignIns | Where-Object { $_.StatusCode -ne 0 }
if ($failedSignIns.Count -gt 0) {
    Write-Host "  $($failedSignIns.Count) failed Graph API sign-ins out of $($allGraphSignIns.Count) total ($([math]::Round($failedSignIns.Count/$allGraphSignIns.Count*100,1))%)" -ForegroundColor White

    $failureBreakdown = $failedSignIns |
        Group-Object StatusCode, StatusReason |
        Sort-Object Count -Descending |
        Select-Object -First 10 @{N='ErrorCode';E={$_.Values[0]}},
                                 @{N='Reason';E={$_.Values[1]}},
                                 Count

    $failureBreakdown | Format-Table -AutoSize
}
else {
    Write-Host "  No failed sign-ins found (note: 429s may not appear in sign-in logs)." -ForegroundColor DarkGray
}
Write-Host ""

# -- Analysis F: Client IP addresses (find automation sources) --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  F. TOP SOURCE IP ADDRESSES (helps locate automation)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

if ($allGraphSignIns.Count -gt 0) {
    $ipBreakdown = $allGraphSignIns |
        Group-Object IpAddress |
        Sort-Object Count -Descending |
        Select-Object -First 15 @{N='IPAddress';E={$_.Name}}, Count,
                      @{N='PctOfTotal';E={[math]::Round($_.Count / $allGraphSignIns.Count * 100, 1)}}

    $ipBreakdown | Format-Table -AutoSize

    Write-Host "  >> If a single IP has a disproportionate share, it's likely a server running automation." -ForegroundColor Yellow
    Write-Host ""
}

# -- Analysis G: Per-app calls per minute (rate limit proximity check) --
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  G. PER-APP ESTIMATED CALLS PER MINUTE (rate limit check)" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

if ($allGraphSignIns.Count -gt 0) {
    $timeSpan = ($allGraphSignIns | Measure-Object -Property CreatedDateTime -Minimum -Maximum)
    $totalMinutes = (($timeSpan.Maximum) - ($timeSpan.Minimum)).TotalMinutes
    if ($totalMinutes -gt 0) {
        $perAppPerMinute = $allGraphSignIns |
            Group-Object AppDisplayName |
            Sort-Object Count -Descending |
            Select-Object -First 10 @{N='Application';E={$_.Name}},
                                     Count,
                                     @{N='AvgCallsPerMin';E={[math]::Round($_.Count / $totalMinutes, 1)}},
                                     @{N='PeakRisk';E={
                                         $avgPerMin = $_.Count / $totalMinutes
                                         if ($avgPerMin -gt 1000) { 'HIGH' }
                                         elseif ($avgPerMin -gt 500) { 'MEDIUM' }
                                         else { 'LOW' }
                                     }}

        $perAppPerMinute | Format-Table -AutoSize

        Write-Host "  Risk levels based on average calls/min vs typical Graph limits:" -ForegroundColor White
        Write-Host "    LOW    = < 500/min    (within normal range)" -ForegroundColor Green
        Write-Host "    MEDIUM = 500-1000/min (approaching limits, may spike above)" -ForegroundColor Yellow
        Write-Host "    HIGH   = > 1000/min   (likely causing or near throttling)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  NOTE: These are averages over the query window. Actual bursts" -ForegroundColor DarkGray
        Write-Host "  may be much higher. Cross-reference with hourly patterns above." -ForegroundColor DarkGray
        Write-Host ""
    }
}
else {
    Write-Host "  No data available." -ForegroundColor DarkGray
    Write-Host ""
}

# ==================================================================
# Automated Findings
# ==================================================================

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  AUTOMATED FINDINGS" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$findings = [System.Collections.Generic.List[string]]::new()
$severity = "LOW"   # Overall assessment: LOW, MEDIUM, HIGH, CRITICAL

# -- Finding: Dominant application --
if ($allGraphSignIns.Count -gt 0) {
    $topApp = $allGraphSignIns | Group-Object AppDisplayName, AppId |
        Sort-Object Count -Descending | Select-Object -First 1
    $topAppName = $topApp.Values[0]
    $topAppId = $topApp.Values[1]
    $topAppPct = [math]::Round($topApp.Count / $allGraphSignIns.Count * 100, 1)

    if ($topAppPct -ge 50) {
        $finding = "[HIGH] $topAppName (AppId: $topAppId) accounts for $topAppPct% of all Graph API sign-ins ($($topApp.Count) calls). This app is the dominant consumer and the most likely cause of throttling."
        $findings.Add($finding)
        if ($severity -ne "CRITICAL") { $severity = "HIGH" }
    }
    elseif ($topAppPct -ge 30) {
        $finding = "[MEDIUM] $topAppName (AppId: $topAppId) accounts for $topAppPct% of all Graph API sign-ins ($($topApp.Count) calls). This is the top consumer but not an outright majority - multiple apps may be contributing."
        $findings.Add($finding)
        if ($severity -eq "LOW") { $severity = "MEDIUM" }
    }
    else {
        $findings.Add("[LOW] No single application dominates Graph API usage. The top app ($topAppName) accounts for only $topAppPct%.")
    }
}

# -- Finding: Concentrated IP source --
if ($allGraphSignIns.Count -gt 0) {
    $topIp = $allGraphSignIns | Group-Object IpAddress |
        Sort-Object Count -Descending | Select-Object -First 1
    $topIpPct = [math]::Round($topIp.Count / $allGraphSignIns.Count * 100, 1)

    # Cross-reference: which app is this IP using?
    $topIpApps = $allGraphSignIns | Where-Object { $_.IpAddress -eq $topIp.Name } |
        Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 3
    $topIpAppNames = ($topIpApps | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "

    if ($topIpPct -ge 40) {
        $finding = "[HIGH] IP address $($topIp.Name) generates $topIpPct% of all Graph traffic ($($topIp.Count) calls). Apps from this IP: $topIpAppNames. This is likely a server running automation or a proxy aggregation point."
        $findings.Add($finding)
        if ($severity -ne "CRITICAL") { $severity = "HIGH" }
    }
    elseif ($topIpPct -ge 20) {
        $finding = "[MEDIUM] IP address $($topIp.Name) generates $topIpPct% of Graph traffic. Apps from this IP: $topIpAppNames."
        $findings.Add($finding)
        if ($severity -eq "LOW") { $severity = "MEDIUM" }
    }
}

# -- Finding: Service principal (automation) volume --
if ($spSignIns.Count -gt 0 -and $allGraphSignIns.Count -gt 0) {
    $spPct = [math]::Round($spSignIns.Count / $allGraphSignIns.Count * 100, 1)
    $topSp = $spSignIns | Group-Object AppDisplayName, AppId |
        Sort-Object Count -Descending | Select-Object -First 1
    $topSpName = $topSp.Values[0]
    $topSpId = $topSp.Values[1]

    # Cross-reference: top SP's IP
    $topSpIps = $spSignIns | Where-Object { $_.AppDisplayName -eq $topSpName } |
        Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 3
    $topSpIpList = ($topSpIps | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "

    if ($spPct -ge 30) {
        $finding = "[HIGH] Service principals account for $spPct% of Graph traffic. Top automation app: $topSpName (AppId: $topSpId, $($topSp.Count) calls). Source IPs: $topSpIpList. Daemon/automation apps are a major contributor."
        $findings.Add($finding)
        if ($severity -ne "CRITICAL") { $severity = "HIGH" }
    }
    elseif ($topSp.Count -ge 1000) {
        $finding = "[MEDIUM] Top service principal $topSpName (AppId: $topSpId) made $($topSp.Count) calls. Source IPs: $topSpIpList."
        $findings.Add($finding)
        if ($severity -eq "LOW") { $severity = "MEDIUM" }
    }
    else {
        $findings.Add("[LOW] Service principal volume is modest ($($spSignIns.Count) calls, $spPct% of total).")
    }
}

# -- Finding: Calls per minute rate risk --
if ($allGraphSignIns.Count -gt 0) {
    $timeSpanCheck = ($allGraphSignIns | Measure-Object -Property CreatedDateTime -Minimum -Maximum)
    $totalMins = (($timeSpanCheck.Maximum) - ($timeSpanCheck.Minimum)).TotalMinutes
    if ($totalMins -gt 0) {
        $highRiskApps = $allGraphSignIns | Group-Object AppDisplayName |
            Where-Object { ($_.Count / $totalMins) -gt 1000 } |
            Sort-Object Count -Descending
        $medRiskApps = $allGraphSignIns | Group-Object AppDisplayName |
            Where-Object { ($_.Count / $totalMins) -gt 500 -and ($_.Count / $totalMins) -le 1000 } |
            Sort-Object Count -Descending

        foreach ($app in $highRiskApps) {
            $rate = [math]::Round($app.Count / $totalMins, 0)
            $findings.Add("[CRITICAL] $($app.Name) is averaging $rate calls/min - well above the ~2,000/min per-app throttling threshold. Immediate action recommended.")
            $severity = "CRITICAL"
        }
        foreach ($app in $medRiskApps) {
            $rate = [math]::Round($app.Count / $totalMins, 0)
            $findings.Add("[MEDIUM] $($app.Name) is averaging $rate calls/min - approaching throttling thresholds. Bursts may already be triggering 429s.")
            if ($severity -eq "LOW") { $severity = "MEDIUM" }
        }
    }
}

# -- Finding: Hourly spike detection --
if ($allGraphSignIns.Count -gt 0) {
    $hourlyCheck = $allGraphSignIns |
        Group-Object { $_.CreatedDateTime.ToString("yyyy-MM-dd HH:00") } |
        Sort-Object Count -Descending
    if ($hourlyCheck.Count -ge 2) {
        $peakHour = $hourlyCheck[0]
        $avgHourly = [math]::Round(($hourlyCheck | Measure-Object -Property Count -Average).Average, 0)
        if ($avgHourly -gt 0) { $spikeRatio = [math]::Round($peakHour.Count / $avgHourly, 1) } else { $spikeRatio = 0 }

        if ($spikeRatio -ge 5) {
            $findings.Add("[HIGH] Extreme spike detected: $($peakHour.Name) had $($peakHour.Count) calls ($($spikeRatio)x the hourly average of $avgHourly). This burst pattern strongly suggests a scheduled job or batch process.")
            if ($severity -eq "LOW" -or $severity -eq "MEDIUM") { $severity = "HIGH" }
        }
        elseif ($spikeRatio -ge 3) {
            $findings.Add("[MEDIUM] Notable spike at $($peakHour.Name) with $($peakHour.Count) calls ($($spikeRatio)x the average of $avgHourly). Check for scheduled automation at that time.")
            if ($severity -eq "LOW") { $severity = "MEDIUM" }
        }

        # Check for off-hours activity (before 6 AM or after 8 PM UTC)
        $offHoursEntries = $hourlyCheck | Where-Object {
            $hour = [int]($_.Name.Split(' ')[1].Replace(':00',''))
            $hour -lt 6 -or $hour -ge 20
        }
        $offHoursCount = ($offHoursEntries | Measure-Object -Property Count -Sum).Sum
        if ($offHoursCount -gt 0) {
            $offHoursPct = [math]::Round($offHoursCount / $allGraphSignIns.Count * 100, 1)
            if ($offHoursPct -ge 30) {
                $findings.Add("[MEDIUM] $offHoursPct% of Graph calls occur outside business hours (before 06:00 or after 20:00 UTC). This points to automated processes, not interactive users.")
            }
        }
    }
}

# -- Finding: Failure rate --
if ($allGraphSignIns.Count -gt 0 -and $failedSignIns.Count -gt 0) {
    $failPct = [math]::Round($failedSignIns.Count / $allGraphSignIns.Count * 100, 1)
    if ($failPct -ge 20) {
        $topFailure = $failedSignIns | Group-Object StatusCode, StatusReason |
            Sort-Object Count -Descending | Select-Object -First 1
        $findings.Add("[HIGH] $failPct% of Graph API sign-ins are failing (top error: $($topFailure.Values[0]) - $($topFailure.Values[1]), $($topFailure.Count) occurrences). Failed calls that retry aggressively can amplify throttling.")
        if ($severity -eq "LOW" -or $severity -eq "MEDIUM") { $severity = "HIGH" }
    }
    elseif ($failPct -ge 5) {
        $findings.Add("[MEDIUM] $failPct% failure rate across Graph sign-ins. Check if failing apps are retrying without backoff.")
    }
}

# -- Finding: User concentration --
if ($allGraphSignIns.Count -gt 0) {
    $topUser = $allGraphSignIns | Group-Object UserPrincipalName |
        Sort-Object Count -Descending | Select-Object -First 1
    $topUserPct = [math]::Round($topUser.Count / $allGraphSignIns.Count * 100, 1)
    if ($topUserPct -ge 25 -and $topUser.Name) {
        $userApps = $allGraphSignIns | Where-Object { $_.UserPrincipalName -eq $topUser.Name } |
            Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 3
        $userAppList = ($userApps | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
        $findings.Add("[MEDIUM] User $($topUser.Name) accounts for $topUserPct% of all Graph calls ($($topUser.Count)). Apps used: $userAppList. This may be a service account or heavily automated user.")
        if ($severity -eq "LOW") { $severity = "MEDIUM" }
    }
}

# -- Print findings --
$severityColor = switch ($severity) {
    "CRITICAL" { "Red" }
    "HIGH"     { "Red" }
    "MEDIUM"   { "Yellow" }
    "LOW"      { "Green" }
}
Write-Host "  Overall Risk Assessment: $severity" -ForegroundColor $severityColor
Write-Host ""

$findingNum = 1
foreach ($f in $findings) {
    if ($f.StartsWith("[CRITICAL]")) { $color = "Red" }
    elseif ($f.StartsWith("[HIGH]")) { $color = "Red" }
    elseif ($f.StartsWith("[MEDIUM]")) { $color = "Yellow" }
    else { $color = "Green" }
    Write-Host "  $findingNum. $f" -ForegroundColor $color
    Write-Host ""
    $findingNum++
}

if ($findings.Count -eq 0) {
    Write-Host "  No significant findings. Graph API usage appears within normal limits." -ForegroundColor Green
    Write-Host ""
}

# ==================================================================
# Recommendations
# ==================================================================

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$recommendations = [System.Collections.Generic.List[string]]::new()

if ($allGraphSignIns.Count -gt 0) {
    $topAppForRec = $allGraphSignIns | Group-Object AppDisplayName, AppId |
        Sort-Object Count -Descending | Select-Object -First 1
    $topAppPctForRec = [math]::Round($topAppForRec.Count / $allGraphSignIns.Count * 100, 1)

    if ($topAppPctForRec -ge 30) {
        $recommendations.Add("Investigate $($topAppForRec.Values[0]) (AppId: $($topAppForRec.Values[1])). This app drives $topAppPctForRec% of traffic. Check its token acquisition frequency, polling intervals, and whether it caches responses.")
    }
}

if ($spSignIns.Count -gt 0) {
    $topSpForRec = $spSignIns | Group-Object AppDisplayName |
        Sort-Object Count -Descending | Select-Object -First 1
    if ($topSpForRec.Count -ge 500) {
        $recommendations.Add("Review the automation/daemon app '$($topSpForRec.Name)' ($($topSpForRec.Count) calls). Ensure it uses delta queries, batching ($batch), and response caching rather than full-list polling.")
    }
}

if ($failedSignIns.Count -gt 0 -and $allGraphSignIns.Count -gt 0) {
    $failPctRec = [math]::Round($failedSignIns.Count / $allGraphSignIns.Count * 100, 1)
    if ($failPctRec -ge 5) {
        $recommendations.Add("Address the $failPctRec% sign-in failure rate. Failing calls that retry without exponential backoff multiply the load. Implement retry-after header handling per Microsoft best practices.")
    }
}

$recommendations.Add("For any app identified above, verify it respects the Retry-After header on 429 responses and implements exponential backoff (Microsoft docs: https://learn.microsoft.com/en-us/graph/throttling).")
$recommendations.Add("Consider using the Graph API $batch endpoint to combine multiple requests into a single call, reducing token acquisition overhead.")

$recNum = 1
foreach ($rec in $recommendations) {
    Write-Host "  $recNum. $rec" -ForegroundColor White
    Write-Host ""
    $recNum++
}

# ==================================================================
# Export & Report
# ==================================================================
Write-Host "[Step 6/6] Generating report..." -ForegroundColor Green

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# -- Build structured report --
$reportPath = Join-Path $OutputFolder "ThrottlingReport_$timestamp.txt"
$report = [System.Text.StringBuilder]::new()
[void]$report.AppendLine("MICROSOFT GRAPH API THROTTLING ANALYSIS REPORT")
[void]$report.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')")
[void]$report.AppendLine("Tenant: $($context.Account)")
[void]$report.AppendLine("Analysis window: $DaysBack day$(if($DaysBack -gt 1){'s'}) (since $StartDate)")
[void]$report.AppendLine("Scope profile: $ScopeProfile (estimated volume: $($estimatedVolume.ToString('N0')))")
[void]$report.AppendLine("===============================================================")
[void]$report.AppendLine("")

[void]$report.AppendLine("RISK ASSESSMENT: $severity")
[void]$report.AppendLine("")

[void]$report.AppendLine("DATA SUMMARY")
[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("  Total Graph API sign-ins:       $($allGraphSignIns.Count)")
if ($AppIdFilter) {
    if ($filteredAppSignIns.Count -gt 0) { $appLabel = $filteredAppSignIns[0].AppDisplayName } else { $appLabel = $AppIdFilter }
    [void]$report.AppendLine("  Filtered app ($appLabel):  $($filteredAppSignIns.Count)")
}
[void]$report.AppendLine("  Service principal sign-ins:     $($spSignIns.Count)")
[void]$report.AppendLine("  Failed sign-ins:                $($failedSignIns.Count)")
if (-not $FetchAll -and ($allGraphSignIns.Count -ge $MaxRecords -or $filteredAppSignIns.Count -ge $MaxRecords)) {
    [void]$report.AppendLine("  NOTE: Results were capped at $MaxRecords records per query.")
}
[void]$report.AppendLine("")

[void]$report.AppendLine("FINDINGS")
[void]$report.AppendLine("---------------------------------------------------------------")
$fNum = 1
foreach ($f in $findings) {
    [void]$report.AppendLine("  $fNum. $f")
    [void]$report.AppendLine("")
    $fNum++
}
if ($findings.Count -eq 0) {
    [void]$report.AppendLine("  No significant findings.")
    [void]$report.AppendLine("")
}

[void]$report.AppendLine("RECOMMENDATIONS")
[void]$report.AppendLine("---------------------------------------------------------------")
$rNum = 1
foreach ($rec in $recommendations) {
    [void]$report.AppendLine("  $rNum. $rec")
    [void]$report.AppendLine("")
    $rNum++
}

[void]$report.AppendLine("TOP 10 APPLICATIONS BY CALL VOLUME")
[void]$report.AppendLine("---------------------------------------------------------------")
if ($allGraphSignIns.Count -gt 0) {
    $topAppsForReport = $allGraphSignIns | Group-Object AppDisplayName, AppId |
        Sort-Object Count -Descending | Select-Object -First 10
    foreach ($app in $topAppsForReport) {
        $pct = [math]::Round($app.Count / $allGraphSignIns.Count * 100, 1)
        [void]$report.AppendLine("  $($app.Values[0]) | AppId: $($app.Values[1]) | $($app.Count) calls ($pct%)")
    }
}
[void]$report.AppendLine("")

[void]$report.AppendLine("TOP 10 USERS BY CALL VOLUME")
[void]$report.AppendLine("---------------------------------------------------------------")
if ($allGraphSignIns.Count -gt 0) {
    $topUsersForReport = $allGraphSignIns | Group-Object UserPrincipalName |
        Sort-Object Count -Descending | Select-Object -First 10
    foreach ($u in $topUsersForReport) {
        $pct = [math]::Round($u.Count / $allGraphSignIns.Count * 100, 1)
        [void]$report.AppendLine("  $($u.Name) | $($u.Count) calls ($pct%)")
    }
}
[void]$report.AppendLine("")

[void]$report.AppendLine("TOP 10 SOURCE IPs")
[void]$report.AppendLine("---------------------------------------------------------------")
if ($allGraphSignIns.Count -gt 0) {
    $topIpsForReport = $allGraphSignIns | Group-Object IpAddress |
        Sort-Object Count -Descending | Select-Object -First 10
    foreach ($ip in $topIpsForReport) {
        $pct = [math]::Round($ip.Count / $allGraphSignIns.Count * 100, 1)
        # Cross-reference IP to apps
        $ipApps = $allGraphSignIns | Where-Object { $_.IpAddress -eq $ip.Name } |
            Group-Object AppDisplayName | Sort-Object Count -Descending | Select-Object -First 3
        $ipAppStr = ($ipApps | ForEach-Object { $_.Name }) -join ", "
        [void]$report.AppendLine("  $($ip.Name) | $($ip.Count) calls ($pct%) | Apps: $ipAppStr")
    }
}
[void]$report.AppendLine("")

[void]$report.AppendLine("TOP SERVICE PRINCIPALS (AUTOMATION)")
[void]$report.AppendLine("---------------------------------------------------------------")
if ($spSignIns.Count -gt 0) {
    $topSpsForReport = $spSignIns | Group-Object AppDisplayName, AppId |
        Sort-Object Count -Descending | Select-Object -First 10
    foreach ($sp in $topSpsForReport) {
        $spIps = $spSignIns | Where-Object { $_.AppDisplayName -eq $sp.Values[0] } |
            Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 3
        $spIpStr = ($spIps | ForEach-Object { $_.Name }) -join ", "
        [void]$report.AppendLine("  $($sp.Values[0]) | AppId: $($sp.Values[1]) | $($sp.Count) calls | IPs: $spIpStr")
    }
}
else {
    [void]$report.AppendLine("  No service principal data available.")
}
[void]$report.AppendLine("")

[void]$report.AppendLine("PEAK HOURS")
[void]$report.AppendLine("---------------------------------------------------------------")
if ($allGraphSignIns.Count -gt 0) {
    $peakHoursForReport = $allGraphSignIns |
        Group-Object { $_.CreatedDateTime.ToString("yyyy-MM-dd HH:00") } |
        Sort-Object Count -Descending | Select-Object -First 10
    foreach ($h in $peakHoursForReport) {
        [void]$report.AppendLine("  $($h.Name) | $($h.Count) calls")
    }
}
[void]$report.AppendLine("")
[void]$report.AppendLine("===============================================================")
[void]$report.AppendLine("END OF REPORT")

# Save report
[System.IO.File]::WriteAllText($reportPath, $report.ToString(), [System.Text.Encoding]::UTF8)
Write-Host "  Report saved to: $reportPath" -ForegroundColor Green

# -- CSV exports --
if ($ExportCsv) {
    if ($allGraphSignIns.Count -gt 0) {
        $allGraphSignIns | Export-Csv "$OutputFolder\AllGraphSignIns_$timestamp.csv" -NoTypeInformation
        Write-Host "  Exported: AllGraphSignIns_$timestamp.csv ($($allGraphSignIns.Count) rows)" -ForegroundColor White
    }
    if ($filteredAppSignIns.Count -gt 0) {
        $filteredAppSignIns | Export-Csv "$OutputFolder\FilteredAppSignIns_$timestamp.csv" -NoTypeInformation
        Write-Host "  Exported: FilteredAppSignIns_$timestamp.csv ($($filteredAppSignIns.Count) rows)" -ForegroundColor White
    }
    if ($spSignIns.Count -gt 0) {
        $spSignIns | Export-Csv "$OutputFolder\ServicePrincipalSignIns_$timestamp.csv" -NoTypeInformation
        Write-Host "  Exported: ServicePrincipalSignIns_$timestamp.csv ($($spSignIns.Count) rows)" -ForegroundColor White
    }
    Write-Host "  CSV exports saved to: $OutputFolder" -ForegroundColor Green
}
else {
    Write-Host "  Skipping CSV export (use -ExportCsv to enable)" -ForegroundColor DarkGray
}

Write-Host ""

# -- Stop logging --
Stop-Transcript | Out-Null
Write-Host "  Full console log: $transcriptPath" -ForegroundColor Green
Write-Host ""

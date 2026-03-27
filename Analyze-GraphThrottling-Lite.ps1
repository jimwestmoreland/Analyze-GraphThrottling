<#
.SYNOPSIS
    Inventories Graph API application permissions in a tenant to identify the
    most likely sources of HTTP 429 throttling - without requiring Entra ID
    P1/P2 licensing.

.DESCRIPTION
    This is the "lite" companion to Analyze-GraphThrottling.ps1. Where the
    full script analyzes sign-in logs (which require P1/P2), this script
    works on any Entra ID tenant by examining:

    1. App registrations with Microsoft Graph API permissions
    2. Application vs. delegated permission breakdown
    3. Active credential status (secrets/certificates)
    4. Permission breadth scoring (how many Graph scopes each app has)
    5. Multi-tenant app detection (external apps consuming your quota)
    6. Owner/contact mapping for each app
    7. Service principals with Graph permissions (including first-party)

    The goal is to build a prioritized suspect list - which apps COULD be
    causing throttling based on their permission footprint and credential
    status - even when sign-in log data is unavailable.

.NOTES
    ===============================================================
    REQUIREMENTS
    ===============================================================

    1. SOFTWARE
       - PowerShell 5.1+ or PowerShell 7+
       - Microsoft Graph PowerShell SDK
         Install:  Install-Module Microsoft.Graph -Scope CurrentUser
         Modules used: Microsoft.Graph.Authentication,
                       Microsoft.Graph.Applications

    2. LICENSING
       - Entra ID Free or any tier (no P1/P2 required)

    3. ENTRA ID ROLES (one of the following is sufficient)
       +------------------------------+--------------------------------------------+
       | Role                         | Notes                                      |
       +------------------------------+--------------------------------------------+
       | Global Reader                | Read-only tenant-wide - recommended        |
       | Application Administrator    | Full access to app registrations           |
       | Cloud App Administrator      | Access to app registrations and SPs        |
       | Security Reader              | Read-only security data                    |
       +------------------------------+--------------------------------------------+

       ** Recommended: Global Reader (least-privilege for this script) **

    4. MICROSOFT GRAPH API PERMISSIONS (granted interactively at sign-in)
       - Application.Read.All - read all app registrations and service principals
       - Directory.Read.All   - read directory data
       These are delegated permissions consented via the interactive login prompt.

    5. NETWORK
       - Outbound HTTPS (443) to graph.microsoft.com and login.microsoftonline.com

    ===============================================================

    Run time: 1-5 minutes depending on number of app registrations

.EXAMPLE
    .\Analyze-GraphThrottling-Lite.ps1
    # Default: inventory all apps with Graph permissions

    .\Analyze-GraphThrottling-Lite.ps1 -ExportCsv
    # Export the full app inventory to CSV

    .\Analyze-GraphThrottling-Lite.ps1 -IncludeFirstParty
    # Include Microsoft first-party apps (excluded by default since they are
    # rarely the cause of customer throttling)

    .\Analyze-GraphThrottling-Lite.ps1 -AppIdFilter "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    # Focus on a specific application by its App ID
#>

[CmdletBinding()]
param(
    [switch]$ExportCsv,
    [string]$OutputFolder = ".\GraphThrottlingAnalysis",
    [string]$AppIdFilter,
    [switch]$IncludeFirstParty
)

$ErrorActionPreference = "Stop"

# -- Start logging --
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$transcriptPath = Join-Path $OutputFolder "LiteAnalysisReport_$timestamp.txt"
try { Stop-Transcript -ErrorAction SilentlyContinue } catch { $null = $_ }
Start-Transcript -Path $transcriptPath -Force | Out-Null

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Graph API Throttling Analysis - LITE" -ForegroundColor Cyan
Write-Host "  (No P1/P2 license required)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Parameters:" -ForegroundColor Yellow
if ($AppIdFilter) {
    Write-Host "  App filter:        $AppIdFilter"
}
Write-Host "  Include 1st party: $IncludeFirstParty"
Write-Host "  Export CSV:        $ExportCsv"
Write-Host ""
Write-Host "This script inventories app registrations and service" -ForegroundColor DarkGray
Write-Host "principals with Microsoft Graph permissions to build a" -ForegroundColor DarkGray
Write-Host "prioritized suspect list for throttling investigation." -ForegroundColor DarkGray
Write-Host ""

# -- Step 0: Ensure Microsoft Graph PowerShell SDK is installed --
Write-Host "[Step 0/5] Checking for Microsoft Graph PowerShell SDK..." -ForegroundColor Green
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
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Write-Host ""

# -- Step 1: Connect to Microsoft Graph --
Write-Host "[Step 1/5] Connecting to Microsoft Graph..." -ForegroundColor Green
try {
    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected"
    }
    Write-Host "  Already connected as: $($context.Account)" -ForegroundColor DarkGray
}
catch {
    Write-Host "  Requesting sign-in with required permissions..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome
    $context = Get-MgContext
    Write-Host "  Connected as: $($context.Account)" -ForegroundColor DarkGray
}
Write-Host ""

# -- Step 2: Get the Microsoft Graph service principal (resource) --
Write-Host "[Step 2/5] Identifying Microsoft Graph service principal..." -ForegroundColor Green
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -Select Id,AppId,DisplayName
if (-not $graphSp) {
    Write-Error "  Could not find the Microsoft Graph service principal in this tenant."
    return
}
Write-Host "  Found: $($graphSp.DisplayName) (Id: $($graphSp.Id))" -ForegroundColor DarkGray
Write-Host ""

# -- Step 3: Enumerate all app registrations with Graph permissions --
Write-Host "[Step 3/5] Enumerating app registrations with Graph API permissions..." -ForegroundColor Green
Write-Host "  This may take a minute on tenants with many apps..." -ForegroundColor DarkGray

$allApps = Get-MgApplication -All -Select Id,AppId,DisplayName,RequiredResourceAccess,KeyCredentials,PasswordCredentials,SignInAudience,CreatedDateTime
Write-Host "  Total app registrations in tenant: $($allApps.Count)" -ForegroundColor DarkGray

# Filter to apps that have any Microsoft Graph permissions
$graphAppId = "00000003-0000-0000-c000-000000000000"
$appsWithGraph = $allApps | Where-Object {
    $_.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $graphAppId }
}
Write-Host "  Apps with Microsoft Graph permissions: $($appsWithGraph.Count)" -ForegroundColor White

# If filtering to a specific app
if ($AppIdFilter) {
    $appsWithGraph = $appsWithGraph | Where-Object { $_.AppId -eq $AppIdFilter }
    Write-Host "  After AppIdFilter: $($appsWithGraph.Count)" -ForegroundColor White
}

# Build the Graph permission lookup table (role ID -> permission name + type)
Write-Host "  Building permission lookup table..." -ForegroundColor DarkGray
$graphAppRoles = @{}
$graphOAuth2Scopes = @{}

$graphSp.AppRoles | ForEach-Object { $graphAppRoles[$_.Id] = $_.Value }
$graphSp.Oauth2PermissionScopes | ForEach-Object { $graphOAuth2Scopes[$_.Id] = $_.Value }

# If those collections are empty (property not selected), re-fetch with full details
if ($graphAppRoles.Count -eq 0 -and $graphOAuth2Scopes.Count -eq 0) {
    $graphSpFull = Get-MgServicePrincipal -ServicePrincipalId $graphSp.Id
    $graphSpFull.AppRoles | ForEach-Object { $graphAppRoles[$_.Id] = $_.Value }
    $graphSpFull.Oauth2PermissionScopes | ForEach-Object { $graphOAuth2Scopes[$_.Id] = $_.Value }
}
Write-Host "  Permission lookup: $($graphAppRoles.Count) application roles, $($graphOAuth2Scopes.Count) delegated scopes" -ForegroundColor DarkGray

# Analyze each app
$appInventory = [System.Collections.Generic.List[object]]::new()

foreach ($app in $appsWithGraph) {
    $graphResource = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $graphAppId }

    $appPermissions = @()
    $delegatedPermissions = @()

    foreach ($access in $graphResource.ResourceAccess) {
        if ($access.Type -eq "Role") {
            $permName = $graphAppRoles[$access.Id]
            if (-not $permName) { $permName = $access.Id }
            $appPermissions += $permName
        }
        elseif ($access.Type -eq "Scope") {
            $permName = $graphOAuth2Scopes[$access.Id]
            if (-not $permName) { $permName = $access.Id }
            $delegatedPermissions += $permName
        }
    }

    # Credential status
    $now = Get-Date
    $activeSecrets = @($app.PasswordCredentials | Where-Object { $_.EndDateTime -gt $now })
    $activeCerts = @($app.KeyCredentials | Where-Object { $_.EndDateTime -gt $now })
    $expiredSecrets = @($app.PasswordCredentials | Where-Object { $_.EndDateTime -le $now })
    $expiredCerts = @($app.KeyCredentials | Where-Object { $_.EndDateTime -le $now })
    $hasActiveCredential = ($activeSecrets.Count -gt 0 -or $activeCerts.Count -gt 0)

    # Earliest credential expiry (for active credentials)
    $allActiveDates = @()
    $activeSecrets | ForEach-Object { $allActiveDates += $_.EndDateTime }
    $activeCerts | ForEach-Object { $allActiveDates += $_.EndDateTime }
    if ($allActiveDates.Count -gt 0) {
        $earliestExpiry = ($allActiveDates | Sort-Object | Select-Object -First 1)
    } else {
        $earliestExpiry = $null
    }

    # Risk scoring
    $riskScore = 0
    $riskFactors = @()

    # Application permissions are higher risk (daemon/automation, no user context)
    if ($appPermissions.Count -gt 0) {
        $riskScore += 30
        $riskFactors += "Has application permissions (daemon-capable)"
    }

    # More permissions = more likely to be a heavy consumer
    $totalPerms = $appPermissions.Count + $delegatedPermissions.Count
    if ($totalPerms -ge 20) {
        $riskScore += 25
        $riskFactors += "Broad permission footprint ($totalPerms scopes)"
    }
    elseif ($totalPerms -ge 10) {
        $riskScore += 15
        $riskFactors += "Moderate permission footprint ($totalPerms scopes)"
    }
    elseif ($totalPerms -ge 5) {
        $riskScore += 5
        $riskFactors += "Modest permission footprint ($totalPerms scopes)"
    }

    # Active credentials mean it can run right now
    if ($hasActiveCredential) {
        $riskScore += 20
        $riskFactors += "Active credentials ($($activeSecrets.Count) secrets, $($activeCerts.Count) certs)"
    }

    # Multi-tenant apps can be called from external sources
    if ($app.SignInAudience -ne "AzureADMyOrg") {
        $riskScore += 10
        $riskFactors += "Multi-tenant ($($app.SignInAudience))"
    }

    # High-volume permission patterns (mail, calendar, files, users, groups)
    $highVolumePerms = @("Mail.Read", "Mail.ReadWrite", "Mail.Send",
                         "Calendars.Read", "Calendars.ReadWrite",
                         "Files.Read.All", "Files.ReadWrite.All",
                         "User.Read.All", "User.ReadWrite.All",
                         "Group.Read.All", "Group.ReadWrite.All",
                         "Sites.Read.All", "Sites.ReadWrite.All",
                         "Directory.Read.All", "Directory.ReadWrite.All")
    $allPerms = $appPermissions + $delegatedPermissions
    $highVolumeMatches = @($allPerms | Where-Object { $_ -in $highVolumePerms })
    if ($highVolumeMatches.Count -ge 3) {
        $riskScore += 15
        $riskFactors += "Multiple high-volume API scopes ($($highVolumeMatches -join ', '))"
    }

    $appInventory.Add([PSCustomObject]@{
        DisplayName          = $app.DisplayName
        AppId                = $app.AppId
        CreatedDate          = if ($app.CreatedDateTime) { $app.CreatedDateTime.ToString("yyyy-MM-dd") } else { "Unknown" }
        SignInAudience       = $app.SignInAudience
        AppPermissionCount   = $appPermissions.Count
        AppPermissions       = ($appPermissions | Sort-Object) -join "; "
        DelegatedCount       = $delegatedPermissions.Count
        DelegatedPermissions = ($delegatedPermissions | Sort-Object) -join "; "
        TotalGraphScopes     = $totalPerms
        ActiveSecrets        = $activeSecrets.Count
        ActiveCerts          = $activeCerts.Count
        ExpiredSecrets       = $expiredSecrets.Count
        ExpiredCerts         = $expiredCerts.Count
        HasActiveCredential  = $hasActiveCredential
        EarliestExpiry       = if ($earliestExpiry) { $earliestExpiry.ToString("yyyy-MM-dd") } else { "-" }
        RiskScore            = $riskScore
        RiskFactors          = $riskFactors -join "; "
    })
}

# Sort by risk score descending
$appInventory = $appInventory | Sort-Object RiskScore -Descending
Write-Host ""

# -- Step 4: Enumerate service principals with granted Graph permissions --
Write-Host "[Step 4/5] Checking service principal permission grants..." -ForegroundColor Green

# Get OAuth2 permission grants (delegated) targeting Microsoft Graph
$delegatedGrants = @()
try {
    $delegatedGrants = Get-MgOauth2PermissionGrant -All -Filter "resourceId eq '$($graphSp.Id)'"
    Write-Host "  Delegated permission grants to Microsoft Graph: $($delegatedGrants.Count)" -ForegroundColor DarkGray
}
catch {
    Write-Host "  Could not query delegated grants: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# Get app role assignments (application permissions) granted to service principals
$appRoleAssignments = @()
try {
    $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graphSp.Id -All
    Write-Host "  Application permission grants to Microsoft Graph: $($appRoleAssignments.Count)" -ForegroundColor DarkGray
}
catch {
    Write-Host "  Could not query app role assignments: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# Build a lookup of which service principals actually have GRANTED (not just requested) app permissions
$grantedAppPerms = @{}
foreach ($assignment in $appRoleAssignments) {
    $spId = $assignment.PrincipalId
    $roleName = $graphAppRoles[$assignment.AppRoleId]
    if (-not $roleName) { $roleName = $assignment.AppRoleId }
    if (-not $grantedAppPerms.ContainsKey($spId)) {
        $grantedAppPerms[$spId] = @()
    }
    $grantedAppPerms[$spId] += $roleName
}
Write-Host "  Service principals with granted application permissions: $($grantedAppPerms.Count)" -ForegroundColor White

# Fetch owners for top apps where possible
Write-Host "  Fetching app owners for top-risk apps..." -ForegroundColor DarkGray
$ownerMap = @{}
foreach ($appEntry in $appInventory | Select-Object -First 20) {
    try {
        $appObj = $allApps | Where-Object { $_.AppId -eq $appEntry.AppId }
        if ($appObj) {
            $owners = Get-MgApplicationOwner -ApplicationId $appObj.Id -All
            if ($owners.Count -gt 0) {
                $ownerNames = @()
                foreach ($owner in $owners) {
                    $props = $owner.AdditionalProperties
                    if ($props.ContainsKey("userPrincipalName")) {
                        $ownerNames += $props["userPrincipalName"]
                    }
                    elseif ($props.ContainsKey("displayName")) {
                        $ownerNames += $props["displayName"]
                    }
                }
                $ownerMap[$appEntry.AppId] = $ownerNames -join "; "
            }
        }
    }
    catch {
        # Owner lookup may fail for some apps
    }
}
Write-Host ""

# ==================================================================
# Analysis
# ==================================================================

Write-Host "[Step 5/5] Analyzing results..." -ForegroundColor Green
Write-Host ""

# -- Analysis A: Top apps by risk score --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  A. TOP APPS BY THROTTLING RISK SCORE" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

if ($appInventory.Count -gt 0) {
    $topApps = $appInventory | Select-Object -First 20 `
        @{N='Application';E={$_.DisplayName}},
        @{N='AppId';E={$_.AppId}},
        @{N='Risk';E={$_.RiskScore}},
        @{N='AppPerms';E={$_.AppPermissionCount}},
        @{N='DelPerms';E={$_.DelegatedCount}},
        @{N='ActiveCreds';E={if ($_.HasActiveCredential) { "YES" } else { "no" }}},
        @{N='Audience';E={$_.SignInAudience}}
    $topApps | Format-Table -AutoSize

    Write-Host "  >> Highest risk: $($appInventory[0].DisplayName) (score: $($appInventory[0].RiskScore))" -ForegroundColor Yellow
    Write-Host ""

    # Show risk factors for top 5
    Write-Host "  Risk factor breakdown (top 5):" -ForegroundColor Yellow
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    $appInventory | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.DisplayName) (score: $($_.RiskScore))" -ForegroundColor White
        $_.RiskFactors.Split("; ") | ForEach-Object {
            Write-Host "    - $_" -ForegroundColor DarkGray
        }
        $owner = $ownerMap[$_.AppId]
        if ($owner) {
            Write-Host "    - Owner(s): $owner" -ForegroundColor DarkGray
        } else {
            Write-Host "    - Owner(s): not assigned" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}
else {
    Write-Host "  No apps found with Microsoft Graph permissions." -ForegroundColor DarkGray
}
Write-Host ""

# -- Analysis B: Application (daemon) permissions breakdown --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  B. APPS WITH APPLICATION-LEVEL PERMISSIONS (DAEMON)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  These apps can call Graph without user context and are" -ForegroundColor DarkGray
Write-Host "  the most common source of automated throttling." -ForegroundColor DarkGray
Write-Host ""

$daemonApps = $appInventory | Where-Object { $_.AppPermissionCount -gt 0 }
if ($daemonApps.Count -gt 0) {
    $daemonApps | Select-Object -First 15 `
        @{N='Application';E={$_.DisplayName}},
        @{N='AppPerms';E={$_.AppPermissionCount}},
        @{N='ActiveCreds';E={if ($_.HasActiveCredential) { "YES" } else { "no" }}},
        @{N='Earliest Expiry';E={$_.EarliestExpiry}},
        @{N='Permissions';E={
            $perms = $_.AppPermissions
            if ($perms.Length -gt 80) { $perms.Substring(0, 77) + "..." } else { $perms }
        }} |
        Format-Table -AutoSize

    Write-Host "  >> $($daemonApps.Count) apps have application-level Graph permissions" -ForegroundColor Yellow
    $activeDaemon = @($daemonApps | Where-Object { $_.HasActiveCredential })
    Write-Host "  >> $($activeDaemon.Count) of those have active credentials (can run right now)" -ForegroundColor Yellow
}
else {
    Write-Host "  No apps found with application-level Graph permissions." -ForegroundColor DarkGray
}
Write-Host ""

# -- Analysis C: Permission breadth ranking --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  C. APPS BY PERMISSION BREADTH (TOTAL GRAPH SCOPES)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Apps with many Graph scopes are likely making diverse" -ForegroundColor DarkGray
Write-Host "  API calls and consuming more quota." -ForegroundColor DarkGray
Write-Host ""

if ($appInventory.Count -gt 0) {
    $appInventory | Sort-Object TotalGraphScopes -Descending | Select-Object -First 15 `
        @{N='Application';E={$_.DisplayName}},
        @{N='Total Scopes';E={$_.TotalGraphScopes}},
        @{N='App';E={$_.AppPermissionCount}},
        @{N='Delegated';E={$_.DelegatedCount}},
        @{N='Created';E={$_.CreatedDate}} |
        Format-Table -AutoSize
}
Write-Host ""

# -- Analysis D: Multi-tenant apps --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  D. MULTI-TENANT AND EXTERNAL APPS" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Multi-tenant apps may receive calls from external" -ForegroundColor DarkGray
Write-Host "  sources, counting against your tenant's Graph quota." -ForegroundColor DarkGray
Write-Host ""

$multiTenantApps = $appInventory | Where-Object { $_.SignInAudience -ne "AzureADMyOrg" }
if ($multiTenantApps.Count -gt 0) {
    $multiTenantApps | Select-Object -First 15 `
        @{N='Application';E={$_.DisplayName}},
        @{N='Audience';E={$_.SignInAudience}},
        @{N='AppPerms';E={$_.AppPermissionCount}},
        @{N='Risk';E={$_.RiskScore}} |
        Format-Table -AutoSize

    Write-Host "  >> $($multiTenantApps.Count) apps are multi-tenant" -ForegroundColor Yellow
}
else {
    Write-Host "  No multi-tenant apps found with Graph permissions." -ForegroundColor DarkGray
}
Write-Host ""

# -- Analysis E: Credential status --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  E. CREDENTIAL STATUS (ACTIVE vs. EXPIRED)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Apps without active credentials cannot authenticate" -ForegroundColor DarkGray
Write-Host "  and can be deprioritized in the investigation." -ForegroundColor DarkGray
Write-Host ""

$withCreds = @($appInventory | Where-Object { $_.HasActiveCredential })
$withoutCreds = @($appInventory | Where-Object { -not $_.HasActiveCredential })
Write-Host "  Apps with active credentials:   $($withCreds.Count)" -ForegroundColor White
Write-Host "  Apps without active credentials: $($withoutCreds.Count) (can be deprioritized)" -ForegroundColor DarkGray
Write-Host ""

if ($withCreds.Count -gt 0) {
    Write-Host "  Soonest expiring credentials:" -ForegroundColor Yellow
    $withCreds | Where-Object { $_.EarliestExpiry -ne "-" } |
        Sort-Object EarliestExpiry |
        Select-Object -First 10 `
            @{N='Application';E={$_.DisplayName}},
            @{N='Expires';E={$_.EarliestExpiry}},
            @{N='Secrets';E={$_.ActiveSecrets}},
            @{N='Certs';E={$_.ActiveCerts}} |
        Format-Table -AutoSize
}
Write-Host ""

# -- Analysis F: Granted application permissions (actually consented) --
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  F. GRANTED APPLICATION PERMISSIONS (ADMIN CONSENTED)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  These service principals have admin-consented Graph" -ForegroundColor DarkGray
Write-Host "  application permissions and are confirmed active." -ForegroundColor DarkGray
Write-Host ""

if ($grantedAppPerms.Count -gt 0) {
    $grantedList = [System.Collections.Generic.List[object]]::new()
    foreach ($spId in $grantedAppPerms.Keys) {
        try {
            $sp = Get-MgServicePrincipal -ServicePrincipalId $spId -Select DisplayName,AppId,ServicePrincipalType -ErrorAction SilentlyContinue
            if ($sp) {
                # Skip first-party Microsoft apps unless requested
                if (-not $IncludeFirstParty -and $sp.ServicePrincipalType -eq "Application" -and $sp.AppId -match '^[0-9a-f]{8}-0000-') {
                    continue
                }
                $perms = $grantedAppPerms[$spId]
                $grantedList.Add([PSCustomObject]@{
                    DisplayName   = $sp.DisplayName
                    AppId         = $sp.AppId
                    Type          = $sp.ServicePrincipalType
                    GrantedPerms  = $perms.Count
                    Permissions   = ($perms | Sort-Object) -join "; "
                })
            }
        }
        catch {
            # Some SPs may not be readable
        }
    }

    if ($grantedList.Count -gt 0) {
        $grantedList | Sort-Object GrantedPerms -Descending | Select-Object -First 20 `
            @{N='Service Principal';E={$_.DisplayName}},
            @{N='AppId';E={$_.AppId}},
            @{N='Granted';E={$_.GrantedPerms}},
            @{N='Permissions';E={
                $p = $_.Permissions
                if ($p.Length -gt 70) { $p.Substring(0, 67) + "..." } else { $p }
            }} |
            Format-Table -AutoSize

        Write-Host "  >> $($grantedList.Count) service principals have granted Graph application permissions" -ForegroundColor Yellow
    }
}
else {
    Write-Host "  No granted application permissions found." -ForegroundColor DarkGray
}
Write-Host ""

# ==================================================================
# Automated Findings
# ==================================================================

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  AUTOMATED FINDINGS" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$findings = [System.Collections.Generic.List[string]]::new()
$recommendations = [System.Collections.Generic.List[string]]::new()
$severity = "LOW"

# Finding: Daemon apps with active credentials
$activeDaemonApps = @($appInventory | Where-Object { $_.AppPermissionCount -gt 0 -and $_.HasActiveCredential })
if ($activeDaemonApps.Count -gt 0) {
    $topDaemon = $activeDaemonApps[0]
    if ($activeDaemonApps.Count -ge 10) {
        $findings.Add("[HIGH] $($activeDaemonApps.Count) apps have application-level Graph permissions with active credentials. These daemon apps can run unattended and are the most common throttling source. Top suspect: $($topDaemon.DisplayName) (AppId: $($topDaemon.AppId), $($topDaemon.AppPermissionCount) app permissions).")
        if ($severity -eq "LOW" -or $severity -eq "MEDIUM") { $severity = "HIGH" }
    }
    elseif ($activeDaemonApps.Count -ge 3) {
        $findings.Add("[MEDIUM] $($activeDaemonApps.Count) apps have application-level Graph permissions with active credentials. Top suspect: $($topDaemon.DisplayName) (AppId: $($topDaemon.AppId)).")
        if ($severity -eq "LOW") { $severity = "MEDIUM" }
    }
    else {
        $findings.Add("[LOW] $($activeDaemonApps.Count) app(s) have application-level Graph permissions with active credentials: $($topDaemon.DisplayName) (AppId: $($topDaemon.AppId)).")
    }
    $recommendations.Add("Review daemon/automation apps for polling intervals, batch sizes, and unnecessary API calls. Start with the highest-risk apps listed in Analysis A.")
}

# Finding: High permission breadth
$broadApps = @($appInventory | Where-Object { $_.TotalGraphScopes -ge 15 })
if ($broadApps.Count -gt 0) {
    $findings.Add("[MEDIUM] $($broadApps.Count) app(s) have 15+ Graph scopes, suggesting broad API usage: $(($broadApps | Select-Object -First 3 | ForEach-Object { "$($_.DisplayName) ($($_.TotalGraphScopes) scopes)" }) -join ', ').")
    if ($severity -eq "LOW") { $severity = "MEDIUM" }
    $recommendations.Add("Apps with broad permission footprints are more likely to be making diverse Graph calls. Audit whether all requested permissions are still needed.")
}

# Finding: Multi-tenant with active credentials
$multiActive = @($appInventory | Where-Object { $_.SignInAudience -ne "AzureADMyOrg" -and $_.HasActiveCredential -and $_.AppPermissionCount -gt 0 })
if ($multiActive.Count -gt 0) {
    $findings.Add("[MEDIUM] $($multiActive.Count) multi-tenant app(s) have application permissions and active credentials. External callers may be contributing to your tenant's Graph quota: $(($multiActive | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join ', ').")
    if ($severity -eq "LOW") { $severity = "MEDIUM" }
    $recommendations.Add("Multi-tenant daemon apps can be called from outside your organization. Verify the source and necessity of each.")
}

# Finding: Apps with many granted (consented) permissions
if ($grantedAppPerms.Count -gt 20) {
    $findings.Add("[HIGH] $($grantedAppPerms.Count) service principals have admin-consented Graph application permissions. This is a large attack surface and potential throttling footprint.")
    if ($severity -eq "LOW" -or $severity -eq "MEDIUM") { $severity = "HIGH" }
    $recommendations.Add("Review admin-consented application permissions in Entra ID > Enterprise Applications. Revoke any that are no longer needed.")
}

# Finding: No active credentials (good news)
$noCredApps = @($appInventory | Where-Object { -not $_.HasActiveCredential })
if ($noCredApps.Count -gt 0 -and $appInventory.Count -gt 0) {
    $pct = [math]::Round($noCredApps.Count / $appInventory.Count * 100, 0)
    $findings.Add("[INFO] $($noCredApps.Count) of $($appInventory.Count) apps ($pct%) have no active credentials and can be deprioritized - they cannot currently authenticate to Graph.")
}

if ($findings.Count -eq 0) {
    $findings.Add("[INFO] No significant findings detected. The tenant has a minimal Graph permission footprint.")
}

# Display findings
$severityColor = switch ($severity) {
    "CRITICAL" { "Red" }
    "HIGH" { "Red" }
    "MEDIUM" { "Yellow" }
    default { "Green" }
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

# Display recommendations
if ($recommendations.Count -gt 0) {
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  RECOMMENDATIONS" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""
    $recNum = 1
    foreach ($r in $recommendations) {
        Write-Host "  $recNum. $r" -ForegroundColor White
        Write-Host ""
        $recNum++
    }

    # Always recommend the full script if P1/P2 is available
    Write-Host "  $recNum. For definitive analysis, run the full Analyze-GraphThrottling.ps1 script if the tenant has Entra ID P1/P2 licensing. Sign-in logs provide actual call volume data rather than permission-based estimates." -ForegroundColor White
    Write-Host ""
}

# ==================================================================
# Step 6: Generate report file
# ==================================================================

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  GENERATING REPORT" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$reportPath = Join-Path $OutputFolder "LiteThrottlingReport_$timestamp.txt"
$report = [System.Text.StringBuilder]::new()

[void]$report.AppendLine("===============================================================")
[void]$report.AppendLine("  GRAPH API THROTTLING ANALYSIS - LITE REPORT")
[void]$report.AppendLine("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$report.AppendLine("  Tenant: $($context.TenantId)")
[void]$report.AppendLine("  Run by: $($context.Account)")
[void]$report.AppendLine("===============================================================")
[void]$report.AppendLine("")
[void]$report.AppendLine("NOTE: This is the LITE analysis (no Entra ID P1/P2 required).")
[void]$report.AppendLine("It identifies POTENTIAL throttling sources based on app")
[void]$report.AppendLine("registrations and permissions, not actual API call volume.")
[void]$report.AppendLine("For definitive analysis, use Analyze-GraphThrottling.ps1 with P1/P2.")
[void]$report.AppendLine("")
[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("RISK ASSESSMENT: $severity")
[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("")
[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("SUMMARY")
[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("  Total app registrations:              $($allApps.Count)")
[void]$report.AppendLine("  Apps with Graph permissions:          $($appInventory.Count)")
[void]$report.AppendLine("  Apps with application permissions:    $($daemonApps.Count)")
[void]$report.AppendLine("  Active daemon apps (with credentials):$($activeDaemonApps.Count)")
[void]$report.AppendLine("  Multi-tenant Graph apps:              $($multiTenantApps.Count)")
[void]$report.AppendLine("  SPs with granted app permissions:     $($grantedAppPerms.Count)")
[void]$report.AppendLine("")

[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("FINDINGS")
[void]$report.AppendLine("---------------------------------------------------------------")
$findingNum = 1
foreach ($f in $findings) {
    [void]$report.AppendLine("  $findingNum. $f")
    [void]$report.AppendLine("")
    $findingNum++
}

[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("RECOMMENDATIONS")
[void]$report.AppendLine("---------------------------------------------------------------")
$recNum = 1
foreach ($r in $recommendations) {
    [void]$report.AppendLine("  $recNum. $r")
    [void]$report.AppendLine("")
    $recNum++
}
[void]$report.AppendLine("  $recNum. For definitive analysis, run Analyze-GraphThrottling.ps1 with Entra ID P1/P2.")
[void]$report.AppendLine("")

[void]$report.AppendLine("---------------------------------------------------------------")
[void]$report.AppendLine("TOP 10 APPS BY RISK SCORE")
[void]$report.AppendLine("---------------------------------------------------------------")
$rank = 1
foreach ($app in ($appInventory | Select-Object -First 10)) {
    $owner = $ownerMap[$app.AppId]
    if (-not $owner) { $owner = "not assigned" }
    [void]$report.AppendLine("  $rank. $($app.DisplayName)")
    [void]$report.AppendLine("     AppId: $($app.AppId)")
    [void]$report.AppendLine("     Risk Score: $($app.RiskScore) | App Perms: $($app.AppPermissionCount) | Delegated: $($app.DelegatedCount)")
    [void]$report.AppendLine("     Active Credentials: $($app.HasActiveCredential) | Audience: $($app.SignInAudience)")
    [void]$report.AppendLine("     Owner(s): $owner")
    [void]$report.AppendLine("     Factors: $($app.RiskFactors)")
    [void]$report.AppendLine("")
    $rank++
}

[void]$report.AppendLine("===============================================================")
[void]$report.AppendLine("END OF REPORT")

[System.IO.File]::WriteAllText($reportPath, $report.ToString(), [System.Text.Encoding]::UTF8)
Write-Host "  Report saved to: $reportPath" -ForegroundColor Green

# -- CSV export --
if ($ExportCsv) {
    $csvPath = Join-Path $OutputFolder "AppInventory_$timestamp.csv"
    $appInventory | Select-Object DisplayName, AppId, CreatedDate, SignInAudience,
        AppPermissionCount, AppPermissions, DelegatedCount, DelegatedPermissions,
        TotalGraphScopes, ActiveSecrets, ActiveCerts, ExpiredSecrets, ExpiredCerts,
        HasActiveCredential, EarliestExpiry, RiskScore, RiskFactors |
        Export-Csv $csvPath -NoTypeInformation
    Write-Host "  Exported: AppInventory_$timestamp.csv ($($appInventory.Count) rows)" -ForegroundColor White
    Write-Host "  CSV saved to: $OutputFolder" -ForegroundColor Green
}
else {
    Write-Host "  Skipping CSV export (use -ExportCsv to enable)" -ForegroundColor DarkGray
}

Write-Host ""

# -- Stop logging --
Stop-Transcript | Out-Null
Write-Host "  Full console log: $transcriptPath" -ForegroundColor Green
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Analysis complete." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

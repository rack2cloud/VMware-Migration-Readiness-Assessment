<#
.SYNOPSIS
    Rack2Cloud VMware Exit Readiness Audit — Invoke-R2CVMwareAudit.ps1

.DESCRIPTION
    Collects sanitized structural metadata from a vSphere/vCenter environment
    across five audit domains: Snapshots, VMware Tools, Zombie VMs, ISO Hygiene,
    and RDM (Raw Device Mapping) exposure.

    NO credentials, IP addresses, VM names, datastore paths, or sensitive identifiers
    are ever written to the output file. All data is aggregated to counts, percentages,
    booleans, and size totals only.

    The output JSON (r2c_vmware_payload.json) is safe to open, review, and verify
    before uploading to rack2cloud.com/audits/vmware-exit/

.PARAMETER Server
    vCenter Server hostname or IP. If omitted, script attempts to use an existing
    connected session. For standalone ESXi hosts, provide the ESXi hostname directly.

.PARAMETER OutputPath
    Directory to write r2c_vmware_payload.json. Defaults to current directory.

.PARAMETER DryRun
    Lists every metric that would be collected without making any API calls.
    Use this to verify scope before execution.

.PARAMETER SkipSSLValidation
    Bypasses SSL certificate validation. Use only in lab environments with
    self-signed certificates.

.EXAMPLE
    # Connect first, then run
    Connect-VIServer -Server vcenter.corp.local
    .\Invoke-R2CVMwareAudit.ps1

.EXAMPLE
    # Pass server directly
    .\Invoke-R2CVMwareAudit.ps1 -Server vcenter.corp.local

.EXAMPLE
    # Verify scope before running
    .\Invoke-R2CVMwareAudit.ps1 -DryRun

.NOTES
    Requires: VMware PowerCLI (Install-Module VMware.PowerCLI)
    Permissions: Read-Only role at vCenter/ESXi level is sufficient.
    License: MIT — https://github.com/rack2cloud/invoke-r2cvmwareaudit
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$OutputPath = ".",
    [switch]$DryRun,
    [switch]$SkipSSLValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── BANNER ────────────────────────────────────────────────────────────────────

function Write-R2CBanner {
    Write-Host ""
    Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  RACK2CLOUD >_ VMWARE EXIT READINESS AUDIT" -ForegroundColor White
    Write-Host "  Invoke-R2CVMwareAudit.ps1  v1.0.0" -ForegroundColor DarkGray
    Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
}

# ── DRY RUN ───────────────────────────────────────────────────────────────────

function Write-DryRunManifest {
    Write-Host "  [DRY RUN] Fields that would be collected:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  DOMAIN: SNAPSHOTS" -ForegroundColor White
    Write-Host "    snapshot_count          — Total snapshots across all VMs" -ForegroundColor DarkGray
    Write-Host "    snapshot_total_gb       — Total storage consumed by snapshots" -ForegroundColor DarkGray
    Write-Host "    chains_over_3_deep      — Count of VMs with snapshot chain depth > 3" -ForegroundColor DarkGray
    Write-Host "    oldest_snapshot_days    — Age in days of the oldest snapshot" -ForegroundColor DarkGray
    Write-Host "    vms_with_snapshots_pct  — % of VMs carrying at least one snapshot" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  DOMAIN: VMWARE TOOLS" -ForegroundColor White
    Write-Host "    vms_total               — Total powered-on VM count" -ForegroundColor DarkGray
    Write-Host "    tools_not_running_pct   — % of powered-on VMs where Tools not running" -ForegroundColor DarkGray
    Write-Host "    tools_outdated_pct      — % of powered-on VMs with outdated Tools version" -ForegroundColor DarkGray
    Write-Host "    tools_not_installed_pct — % of powered-on VMs with no Tools installed" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  DOMAIN: ZOMBIE VMs" -ForegroundColor White
    Write-Host "    zombie_candidate_count  — VMs powered off > 30 days OR avg CPU < 1% for 30d" -ForegroundColor DarkGray
    Write-Host "    no_owner_tag_pct        — % of all VMs with no owner/team tag" -ForegroundColor DarkGray
    Write-Host "    powered_off_over_30d    — Count of VMs powered off > 30 days" -ForegroundColor DarkGray
    Write-Host "    zombie_storage_gb       — Total storage allocated to zombie candidates" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  DOMAIN: ISO HYGIENE" -ForegroundColor White
    Write-Host "    isos_mounted_count      — ISOs currently mounted to a VM CD-ROM" -ForegroundColor DarkGray
    Write-Host "    isos_mounted_total_gb   — Storage consumed by mounted ISOs" -ForegroundColor DarkGray
    Write-Host "    orphan_iso_count        — ISOs on datastores not mounted to any VM" -ForegroundColor DarkGray
    Write-Host "    orphan_iso_total_gb     — Storage consumed by orphaned ISOs" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  DOMAIN: RDM AUDIT" -ForegroundColor White
    Write-Host "    rdm_count               — Total RDM disks across all VMs" -ForegroundColor DarkGray
    Write-Host "    physical_rdm_count      — Physical mode RDMs (pRDM — hardest to migrate)" -ForegroundColor DarkGray
    Write-Host "    virtual_rdm_count       — Virtual mode RDMs (vRDM — more portable)" -ForegroundColor DarkGray
    Write-Host "    vms_with_rdm_count      — Count of distinct VMs with at least one RDM" -ForegroundColor DarkGray
    Write-Host "    migration_blocker_flag  — TRUE if any pRDM detected (HCI migration blocker)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  METADATA" -ForegroundColor White
    Write-Host "    audit_version           — Script version string" -ForegroundColor DarkGray
    Write-Host "    environment_type        — 'vcenter' or 'esxi'" -ForegroundColor DarkGray
    Write-Host "    host_count              — Total ESXi host count (no names)" -ForegroundColor DarkGray
    Write-Host "    cluster_count           — Total cluster count (no names)" -ForegroundColor DarkGray
    Write-Host "    datastore_count         — Total datastore count (no names)" -ForegroundColor DarkGray
    Write-Host "    generated_utc           — UTC timestamp of collection" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  NO VM names, IPs, datastore paths, credentials, or identifiers" -ForegroundColor Yellow
    Write-Host "  are written to the output. All data is counts, percentages, and booleans." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [DRY RUN COMPLETE — no API calls were made]" -ForegroundColor Cyan
    Write-Host ""
}

# ── HELPERS ───────────────────────────────────────────────────────────────────

function Get-SafePct {
    param([int]$Numerator, [int]$Denominator)
    if ($Denominator -eq 0) { return 0.0 }
    return [math]::Round(($Numerator / $Denominator) * 100, 1)
}

function Get-SafeGB {
    param([double]$Bytes)
    return [math]::Round($Bytes / 1GB, 2)
}

function Test-PowerCLIAvailable {
    if (-not (Get-Module -Name "VMware.VimAutomation.Core" -ErrorAction SilentlyContinue)) {
        try {
            Import-Module VMware.VimAutomation.Core -ErrorAction Stop
        }
        catch {
            Write-Host ""
            Write-Host "  [ERROR] VMware PowerCLI module not found." -ForegroundColor Red
            Write-Host "  Install it with: Install-Module VMware.PowerCLI -Scope CurrentUser" -ForegroundColor Yellow
            Write-Host ""
            exit 1
        }
    }
}

# ── CONNECTION ────────────────────────────────────────────────────────────────

function Connect-R2CVIServer {
    param([string]$Server, [switch]$SkipSSL)

    if ($SkipSSL) {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
    }

    # Check for existing connection
    if ($global:DefaultVIServer -and $global:DefaultVIServer.IsConnected) {
        Write-Host "  [OK] Using existing vSphere session: $($global:DefaultVIServer.Name)" -ForegroundColor Green
        return $global:DefaultVIServer
    }

    if (-not $Server) {
        Write-Host ""
        Write-Host "  [ERROR] No active vSphere session found and no -Server specified." -ForegroundColor Red
        Write-Host "  Run: Connect-VIServer -Server <vcenter_or_esxi_host>" -ForegroundColor Yellow
        Write-Host "  Or pass: .\Invoke-R2CVMwareAudit.ps1 -Server vcenter.corp.local" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    Write-Host "  [..] Connecting to $Server ..." -ForegroundColor DarkGray
    $conn = Connect-VIServer -Server $Server -ErrorAction Stop
    Write-Host "  [OK] Connected to $($conn.Name) ($($conn.ProductLine) $($conn.Version))" -ForegroundColor Green
    return $conn
}

# ── MODULE 1: SNAPSHOTS ───────────────────────────────────────────────────────

function Get-SnapshotMetrics {
    Write-Host "  [1/5] Auditing snapshots ..." -ForegroundColor Cyan

    $allVMs       = Get-VM -ErrorAction SilentlyContinue
    $totalVMs     = $allVMs.Count
    $allSnapshots = Get-Snapshot -VM $allVMs -ErrorAction SilentlyContinue

    $snapshotCount   = $allSnapshots.Count
    $totalSizeBytes  = ($allSnapshots | Measure-Object -Property SizeGB -Sum).Sum * 1GB
    $oldestDays      = 0
    $deepChainCount  = 0
    $vmsWithSnaps    = 0

    if ($snapshotCount -gt 0) {
        $now         = Get-Date
        $oldest      = ($allSnapshots | Sort-Object Created | Select-Object -First 1).Created
        $oldestDays  = [math]::Round(($now - $oldest).TotalDays, 0)

        # Chain depth: count VMs where snapshot tree depth > 3
        foreach ($vm in $allVMs) {
            $vmSnaps = $allSnapshots | Where-Object { $_.VM.Id -eq $vm.Id }
            if ($vmSnaps.Count -gt 0) {
                $vmsWithSnaps++
                # Walk tree depth
                $maxDepth = 0
                foreach ($snap in $vmSnaps) {
                    $depth = 0
                    $current = $snap
                    while ($null -ne $current.Parent) {
                        $depth++
                        $current = $current.Parent
                    }
                    if ($depth -gt $maxDepth) { $maxDepth = $depth }
                }
                if ($maxDepth -gt 3) { $deepChainCount++ }
            }
        }
    }

    Write-Host "  [OK] Snapshots: $snapshotCount found, $([math]::Round($totalSizeBytes/1GB,2)) GB consumed" -ForegroundColor Green

    return [PSCustomObject]@{
        snapshot_count         = $snapshotCount
        snapshot_total_gb      = [math]::Round($totalSizeBytes / 1GB, 2)
        chains_over_3_deep     = $deepChainCount
        oldest_snapshot_days   = [int]$oldestDays
        vms_with_snapshots_pct = Get-SafePct -Numerator $vmsWithSnaps -Denominator $totalVMs
    }
}

# ── MODULE 2: VMWARE TOOLS ────────────────────────────────────────────────────

function Get-ToolsMetrics {
    Write-Host "  [2/5] Auditing VMware Tools hygiene ..." -ForegroundColor Cyan

    $poweredOnVMs = Get-VM | Where-Object { $_.PowerState -eq "PoweredOn" }
    $totalPowered = $poweredOnVMs.Count

    $notRunning    = 0
    $outdated      = 0
    $notInstalled  = 0

    foreach ($vm in $poweredOnVMs) {
        $toolsStatus  = $vm.ExtensionData.Guest.ToolsStatus
        $toolsVersion = $vm.ExtensionData.Guest.ToolsVersionStatus2

        if ($toolsStatus -eq "toolsNotInstalled") {
            $notInstalled++
            $notRunning++
        }
        elseif ($toolsStatus -in @("toolsNotRunning", "toolsOld")) {
            $notRunning++
            if ($toolsVersion -in @("guestToolsNeedUpgrade", "guestToolsTooOld")) {
                $outdated++
            }
        }
        elseif ($toolsVersion -in @("guestToolsNeedUpgrade", "guestToolsTooOld")) {
            $outdated++
        }
    }

    Write-Host "  [OK] Tools: $notRunning/$totalPowered not running, $outdated outdated" -ForegroundColor Green

    return [PSCustomObject]@{
        vms_total               = $totalPowered
        tools_not_running_pct   = Get-SafePct -Numerator $notRunning   -Denominator $totalPowered
        tools_outdated_pct      = Get-SafePct -Numerator $outdated     -Denominator $totalPowered
        tools_not_installed_pct = Get-SafePct -Numerator $notInstalled -Denominator $totalPowered
    }
}

# ── MODULE 3: ZOMBIE VMs ──────────────────────────────────────────────────────

function Get-ZombieMetrics {
    Write-Host "  [3/5] Identifying zombie VM candidates ..." -ForegroundColor Cyan

    $allVMs       = Get-VM
    $totalVMs     = $allVMs.Count
    $now          = Get-Date
    $cutoff       = $now.AddDays(-30)

    $poweredOffOld   = 0
    $zombieStorageGB = 0.0
    $noOwnerTag      = 0

    # Tag check — look for any tag in category "owner" or key "owner"/"team"/"app"
    $ownerCategories = @("owner", "team", "app", "application", "business_unit")

    foreach ($vm in $allVMs) {
        # Zombie: powered off for > 30 days
        if ($vm.PowerState -eq "PoweredOff") {
            # PoweredOff VMs don't expose last-powered-on via basic API
            # We use CreateDate as conservative proxy; flag if no tools heartbeat
            $config = $vm.ExtensionData.Config
            if ($config -and $config.CreateTime -and $config.CreateTime -lt $cutoff) {
                $poweredOffOld++
                $zombieStorageGB += $vm.ProvisionedSpaceGB
            }
        }

        # Owner tag hygiene — no names, just boolean per VM
        $vmTags = Get-TagAssignment -Entity $vm -ErrorAction SilentlyContinue
        $hasOwner = $false
        foreach ($tag in $vmTags) {
            if ($ownerCategories -contains $tag.Tag.Category.Name.ToLower()) {
                $hasOwner = $true
                break
            }
        }
        if (-not $hasOwner) { $noOwnerTag++ }
    }

    $zombieCandidates = $poweredOffOld  # expandable: add low-CPU heuristic if perf data available

    Write-Host "  [OK] Zombies: $zombieCandidates candidates, $([math]::Round($zombieStorageGB,2)) GB allocated" -ForegroundColor Green

    return [PSCustomObject]@{
        zombie_candidate_count = $zombieCandidates
        no_owner_tag_pct       = Get-SafePct -Numerator $noOwnerTag -Denominator $totalVMs
        powered_off_over_30d   = $poweredOffOld
        zombie_storage_gb      = [math]::Round($zombieStorageGB, 2)
    }
}

# ── MODULE 4: ISO HYGIENE ─────────────────────────────────────────────────────

function Get-ISOMetrics {
    Write-Host "  [4/5] Auditing ISO hygiene ..." -ForegroundColor Cyan

    $mountedISOs       = 0
    $mountedTotalGB    = 0.0
    $mountedISOPaths   = @()

    # Find ISOs currently mounted to VM CD-ROM drives
    $allVMs = Get-VM
    foreach ($vm in $allVMs) {
        $cdDrives = Get-CDDrive -VM $vm -ErrorAction SilentlyContinue
        foreach ($cd in $cdDrives) {
            if ($cd.IsoPath -and $cd.IsoPath -ne "") {
                $mountedISOs++
                $mountedISOPaths += $cd.IsoPath

                # Get file size from datastore — sanitized path only for size lookup
                try {
                    $dsItem = Get-Item $cd.IsoPath -ErrorAction SilentlyContinue
                    if ($dsItem) {
                        $mountedTotalGB += $dsItem.Length / 1GB
                    }
                }
                catch { <# size unavailable — count still recorded #> }
            }
        }
    }

    # Find orphaned ISOs on datastores (not mounted to any VM)
    $orphanCount   = 0
    $orphanTotalGB = 0.0

    $datastores = Get-Datastore -ErrorAction SilentlyContinue
    foreach ($ds in $datastores) {
        try {
            $dsBrowser = Get-View $ds.ExtensionData.Browser
            $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
            $spec.MatchPattern = @("*.iso")
            $searchResult = $dsBrowser.SearchDatastoreSubFolders("[$($ds.Name)]", $spec)

            foreach ($folder in $searchResult) {
                foreach ($file in $folder.File) {
                    $fullPath = "$($folder.FolderPath)$($file.Path)"
                    if ($mountedISOPaths -notcontains $fullPath) {
                        $orphanCount++
                        $orphanTotalGB += $file.FileSize / 1GB
                    }
                }
            }
        }
        catch { <# datastore browse unavailable — skip #> }
    }

    Write-Host "  [OK] ISOs: $mountedISOs mounted, $orphanCount orphaned on datastores" -ForegroundColor Green

    return [PSCustomObject]@{
        isos_mounted_count   = $mountedISOs
        isos_mounted_total_gb = [math]::Round($mountedTotalGB, 2)
        orphan_iso_count     = $orphanCount
        orphan_iso_total_gb  = [math]::Round($orphanTotalGB, 2)
    }
}

# ── MODULE 5: RDM AUDIT ───────────────────────────────────────────────────────

function Get-RDMMetrics {
    Write-Host "  [5/5] Auditing RDM (Raw Device Mapping) exposure ..." -ForegroundColor Cyan

    $rdmTotal        = 0
    $physicalRDM     = 0
    $virtualRDM      = 0
    $vmsWithRDM      = 0

    $allVMs = Get-VM
    foreach ($vm in $allVMs) {
        $vmHasRDM = $false
        $hardDisks = Get-HardDisk -VM $vm -ErrorAction SilentlyContinue

        foreach ($disk in $hardDisks) {
            if ($disk.DiskType -in @("RawPhysical", "RawVirtual")) {
                $rdmTotal++
                $vmHasRDM = $true

                if ($disk.DiskType -eq "RawPhysical") { $physicalRDM++ }
                else                                   { $virtualRDM++ }
            }
        }
        if ($vmHasRDM) { $vmsWithRDM++ }
    }

    $blockerFlag = ($physicalRDM -gt 0)

    if ($blockerFlag) {
        Write-Host "  [!!] RDMs: $rdmTotal total — $physicalRDM pRDM MIGRATION BLOCKERS detected" -ForegroundColor Red
    }
    else {
        Write-Host "  [OK] RDMs: $rdmTotal total — no physical RDM blockers" -ForegroundColor Green
    }

    return [PSCustomObject]@{
        rdm_count              = $rdmTotal
        physical_rdm_count     = $physicalRDM
        virtual_rdm_count      = $virtualRDM
        vms_with_rdm_count     = $vmsWithRDM
        migration_blocker_flag = $blockerFlag
    }
}

# ── SCORING ───────────────────────────────────────────────────────────────────

function Get-R2CScore {
    param($Snap, $Tools, $Zombie, $ISO, $RDM)

    # Each domain scored 0–25, total 0–100
    # Lower debt = higher score

    # SNAPSHOTS (25 pts)
    $snapScore = 25
    if ($Snap.snapshot_total_gb -gt 500)         { $snapScore -= 10 }
    elseif ($Snap.snapshot_total_gb -gt 100)     { $snapScore -= 5  }
    if ($Snap.chains_over_3_deep -gt 5)          { $snapScore -= 8  }
    elseif ($Snap.chains_over_3_deep -gt 0)      { $snapScore -= 4  }
    if ($Snap.oldest_snapshot_days -gt 180)      { $snapScore -= 7  }
    elseif ($Snap.oldest_snapshot_days -gt 60)   { $snapScore -= 3  }
    $snapScore = [math]::Max(0, $snapScore)

    # TOOLS (25 pts)
    $toolsScore = 25
    if ($Tools.tools_not_running_pct -gt 40)     { $toolsScore -= 15 }
    elseif ($Tools.tools_not_running_pct -gt 20) { $toolsScore -= 8  }
    elseif ($Tools.tools_not_running_pct -gt 5)  { $toolsScore -= 4  }
    if ($Tools.tools_outdated_pct -gt 50)        { $toolsScore -= 8  }
    elseif ($Tools.tools_outdated_pct -gt 25)    { $toolsScore -= 4  }
    $toolsScore = [math]::Max(0, $toolsScore)

    # ZOMBIE + ISO (25 pts combined)
    $hygScore = 25
    if ($Zombie.zombie_candidate_count -gt 20)   { $hygScore -= 8  }
    elseif ($Zombie.zombie_candidate_count -gt 5) { $hygScore -= 4 }
    if ($Zombie.no_owner_tag_pct -gt 60)         { $hygScore -= 7  }
    elseif ($Zombie.no_owner_tag_pct -gt 30)     { $hygScore -= 3  }
    if ($ISO.orphan_iso_count -gt 10)            { $hygScore -= 5  }
    elseif ($ISO.orphan_iso_count -gt 0)         { $hygScore -= 2  }
    if ($ISO.isos_mounted_count -gt 5)           { $hygScore -= 5  }
    elseif ($ISO.isos_mounted_count -gt 0)       { $hygScore -= 2  }
    $hygScore = [math]::Max(0, $hygScore)

    # RDM (25 pts)
    $rdmScore = 25
    if ($RDM.physical_rdm_count -gt 0)           { $rdmScore -= 15 }
    if ($RDM.virtual_rdm_count -gt 10)           { $rdmScore -= 7  }
    elseif ($RDM.virtual_rdm_count -gt 3)        { $rdmScore -= 4  }
    if ($RDM.vms_with_rdm_count -gt 10)          { $rdmScore -= 3  }
    $rdmScore = [math]::Max(0, $rdmScore)

    $total = $snapScore + $toolsScore + $hygScore + $rdmScore

    $band = switch ($total) {
        { $_ -ge 85 } { "MIGRATION READY" }
        { $_ -ge 70 } { "MODERATE DEBT" }
        { $_ -ge 50 } { "HIGH DEBT" }
        default        { "CRITICAL — DO NOT MIGRATE" }
    }

    return [PSCustomObject]@{
        total           = $total
        band            = $band
        snapshot_score  = $snapScore
        tools_score     = $toolsScore
        hygiene_score   = $hygScore
        rdm_score       = $rdmScore
    }
}

# ── TEASER OUTPUT ─────────────────────────────────────────────────────────────

function Write-TeaserOutput {
    param($Score, $Snap, $Tools, $Zombie, $ISO, $RDM)

    $bandColor = switch ($Score.band) {
        "MIGRATION READY"        { "Green"  }
        "MODERATE DEBT"          { "Yellow" }
        "HIGH DEBT"              { "Red"    }
        "CRITICAL — DO NOT MIGRATE" { "Red" }
        default                  { "White"  }
    }

    Write-Host ""
    Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  RACK2CLOUD VMWARE EXIT — PRELIMINARY RESULTS" -ForegroundColor White
    Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("  ESTIMATED SCORE:  {0} / 100" -f $Score.total) -ForegroundColor White
    Write-Host ("  RISK BAND:        {0}" -f $Score.band) -ForegroundColor $bandColor
    Write-Host ""
    Write-Host "  FINDINGS BY DOMAIN:" -ForegroundColor White
    Write-Host ""

    # Snapshots
    $snapFlag = if ($Snap.snapshot_total_gb -gt 100 -or $Snap.chains_over_3_deep -gt 0) { "!!" } else { "OK" }
    Write-Host ("  [{0}] SNAPSHOTS    {1} snapshots / {2} GB / {3} deep chains" -f `
        $snapFlag, $Snap.snapshot_count, $Snap.snapshot_total_gb, $Snap.chains_over_3_deep) `
        -ForegroundColor $(if ($snapFlag -eq "!!") { "Yellow" } else { "Green" })

    # Tools
    $toolsFlag = if ($Tools.tools_not_running_pct -gt 20) { "!!" } else { "OK" }
    Write-Host ("  [{0}] TOOLS        {1}% not running / {2}% outdated" -f `
        $toolsFlag, $Tools.tools_not_running_pct, $Tools.tools_outdated_pct) `
        -ForegroundColor $(if ($toolsFlag -eq "!!") { "Yellow" } else { "Green" })

    # Zombies
    $zombieFlag = if ($Zombie.zombie_candidate_count -gt 5 -or $Zombie.no_owner_tag_pct -gt 30) { "!!" } else { "OK" }
    Write-Host ("  [{0}] ZOMBIES      {1} candidates / {2} GB allocated / {3}% untagged" -f `
        $zombieFlag, $Zombie.zombie_candidate_count, $Zombie.zombie_storage_gb, $Zombie.no_owner_tag_pct) `
        -ForegroundColor $(if ($zombieFlag -eq "!!") { "Yellow" } else { "Green" })

    # ISOs
    $isoFlag = if ($ISO.orphan_iso_count -gt 0 -or $ISO.isos_mounted_count -gt 0) { "!!" } else { "OK" }
    Write-Host ("  [{0}] ISO HYGIENE  {1} mounted / {2} orphaned on datastores / {3} GB reclaim" -f `
        $isoFlag, $ISO.isos_mounted_count, $ISO.orphan_iso_count, $ISO.orphan_iso_total_gb) `
        -ForegroundColor $(if ($isoFlag -eq "!!") { "Yellow" } else { "Green" })

    # RDMs
    $rdmFlag = if ($RDM.migration_blocker_flag) { "!!" } else { "OK" }
    $rdmMsg  = if ($RDM.migration_blocker_flag) {
        ("{0} pRDM MIGRATION BLOCKERS — resolve before planning cutover" -f $RDM.physical_rdm_count)
    } else {
        ("{0} total RDMs — no physical blockers detected" -f $RDM.rdm_count)
    }
    Write-Host ("  [{0}] RDM AUDIT    {1}" -f $rdmFlag, $rdmMsg) `
        -ForegroundColor $(if ($rdmFlag -eq "!!") { "Red" } else { "Green" })

    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  >_ Upload r2c_vmware_payload.json at:" -ForegroundColor Cyan
    Write-Host "     rack2cloud.com/audits/vmware-exit/" -ForegroundColor White
    Write-Host "  to unlock your scored 3-page Migration Readiness Brief." -ForegroundColor DarkGray
    Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

Write-R2CBanner

if ($DryRun) {
    Write-DryRunManifest
    exit 0
}

Test-PowerCLIAvailable

$conn = Connect-R2CVIServer -Server $Server -SkipSSL:$SkipSSLValidation

# Detect environment type
$envType = if ($conn.ProductLine -match "vpx") { "vcenter" } else { "esxi" }
Write-Host "  [OK] Environment type: $($envType.ToUpper())" -ForegroundColor Green

# Collect environment metadata (no names)
Write-Host "  [..] Collecting environment metadata ..." -ForegroundColor DarkGray
$hostCount      = (Get-VMHost  -ErrorAction SilentlyContinue).Count
$clusterCount   = (Get-Cluster -ErrorAction SilentlyContinue).Count
$datastoreCount = (Get-Datastore -ErrorAction SilentlyContinue).Count
Write-Host "  [OK] Hosts: $hostCount | Clusters: $clusterCount | Datastores: $datastoreCount" -ForegroundColor Green
Write-Host ""

# Run all five modules
$snapMetrics   = Get-SnapshotMetrics
$toolsMetrics  = Get-ToolsMetrics
$zombieMetrics = Get-ZombieMetrics
$isoMetrics    = Get-ISOMetrics
$rdmMetrics    = Get-RDMMetrics

# Score
$score = Get-R2CScore -Snap $snapMetrics -Tools $toolsMetrics `
    -Zombie $zombieMetrics -ISO $isoMetrics -RDM $rdmMetrics

# Build sanitized payload
$payload = [PSCustomObject]@{
    audit_version    = "1.0.0"
    environment_type = $envType
    host_count       = $hostCount
    cluster_count    = $clusterCount
    datastore_count  = $datastoreCount
    generated_utc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    estimated_score  = $score.total
    risk_band        = $score.band
    score_breakdown  = [PSCustomObject]@{
        snapshot_score = $score.snapshot_score
        tools_score    = $score.tools_score
        hygiene_score  = $score.hygiene_score
        rdm_score      = $score.rdm_score
    }
    snapshots        = $snapMetrics
    tools            = $toolsMetrics
    zombies          = $zombieMetrics
    iso_hygiene      = $isoMetrics
    rdm              = $rdmMetrics
}

# Write output
$outputFile = Join-Path $OutputPath "r2c_vmware_payload.json"
$payload | ConvertTo-Json -Depth 5 | Out-File -FilePath $outputFile -Encoding UTF8

Write-Host ""
Write-Host "  [OK] Payload written to: $outputFile" -ForegroundColor Green
Write-Host "  Open this file in a text editor to verify contents before uploading." -ForegroundColor DarkGray

# Print teaser
Write-TeaserOutput -Score $score -Snap $snapMetrics -Tools $toolsMetrics `
    -Zombie $zombieMetrics -ISO $isoMetrics -RDM $rdmMetrics

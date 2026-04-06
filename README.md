# VMware Migration Readiness Assessment

![Pillar](https://img.shields.io/badge/Pillar-VMware%20Exit%20Readiness-38bdf8)
![Status](https://img.shields.io/badge/Status-Production--Ready-38bdf8)
![License](https://img.shields.io/badge/License-MIT-green)

A local PowerShell script that extracts sanitized structural metadata from your vSphere or vCenter environment — no credentials shared, no data leaving your control, no access granted to anyone. Upload the output JSON to [rack2cloud.com/audits/vmware-exit](https://rack2cloud.com/audits/vmware-exit) for a scored 3-page Migration Readiness Brief with a prioritized remediation and migration planning roadmap.

---

## >_ The Architectural Reality

### The Problem

Most VMware shops don't actually know what's in their environment until they try to migrate out of it.

Snapshots accumulate for years. VMware Tools fall out of date silently. VMs with no owner, no workload, and no documentation keep billing. ISOs mounted to CD-ROM drives nobody remembers. And somewhere in the environment — almost certainly — there are Raw Device Mappings that will stop a migration cold the moment you try to move them.

By the time your team discovers these issues, you're already mid-migration. The timeline slips. The cutover window blows. The budget doubles.

### The Solution

Run this script locally inside your own authenticated vSphere or vCenter session. It audits five domains — Snapshots, VMware Tools hygiene, Zombie VMs, ISO hygiene, and RDM exposure — and outputs **only structural metadata**: counts, percentages, booleans, and size totals.

No VM names. No datastore paths. No IP addresses. No credentials. Nothing sensitive leaves your environment.

You get a console teaser with categorized findings immediately. Upload the JSON for the full scored brief — and a concrete first step toward a Nutanix Move migration plan.

---

## 🛡️ The InfoSec Guarantee: Zero Exfiltration

Before running the live collection, verify exactly what this script does using the `-DryRun` flag.

```powershell
.\Invoke-R2CVMwareReadiness.ps1 -DryRun
```

*This executes with zero API calls. It prints every field name and data type that would be written to the JSON. Review it. Audit the source. Only run live when you are satisfied.*

### ✅ Collected — Structural Metadata Only

| Domain | Examples |
|---|---|
| **Snapshots** | Total count, total GB consumed, chain depth > 3 count, oldest snapshot age in days, % of VMs carrying snapshots. |
| **VMware Tools** | % not running, % outdated, % not installed — across all powered-on VMs. |
| **Zombie VMs** | Powered-off VM count > 30 days, total storage allocated to candidates, % of VMs with no owner tag. |
| **ISO Hygiene** | Mounted ISO count + GB, orphaned ISO count + GB on datastores not attached to any VM. |
| **RDM Audit** | Total RDM count, physical RDM count (pRDM), virtual RDM count (vRDM), migration blocker flag (boolean). |

### ❌ Never Collected

- VM names, hostnames, or display names
- Datastore names or paths
- IP addresses (management, vMotion, or guest)
- vCenter hostname or ESXi host FQDNs
- Credentials, service account names, or passwords
- Tag values or custom attribute content
- Any guest OS data or workload payload

---

## ⚙️ Prerequisites & Execution

### Requirements

- PowerShell 5.1+ or PowerShell 7+
- VMware PowerCLI module
- Read-Only role at vCenter or ESXi host level *(no write permissions required)*

### Install PowerCLI (if not already installed)

```powershell
Install-Module VMware.PowerCLI -Scope CurrentUser -Force
```

### Option A: Connected Session (Recommended)

```powershell
# Authenticate first
Connect-VIServer -Server vcenter.corp.local

# Then run the assessment
.\Invoke-R2CVMwareReadiness.ps1
```

### Option B: Pass Server Directly

```powershell
.\Invoke-R2CVMwareReadiness.ps1 -Server vcenter.corp.local
```

### Option C: Standalone ESXi Host

```powershell
.\Invoke-R2CVMwareReadiness.ps1 -Server esxi-host-01.corp.local
```

---

### Usage Commands

```powershell
# 1. Verify collection scope before execution (zero API calls)
.\Invoke-R2CVMwareReadiness.ps1 -DryRun

# 2. Run against current connected session
.\Invoke-R2CVMwareReadiness.ps1

# 3. Target a specific vCenter or ESXi host
.\Invoke-R2CVMwareReadiness.ps1 -Server vcenter.corp.local

# 4. Specify output directory
.\Invoke-R2CVMwareReadiness.ps1 -OutputPath "C:\MigrationExports"

# 5. Lab environments with self-signed certificates
.\Invoke-R2CVMwareReadiness.ps1 -Server vcenter.lab.local -SkipSSLValidation
```

---

## 📊 The Output Pipeline

### 1. The Console Teaser

When you run the script live, you'll see categorized findings immediately — before uploading anything:

```
  ════════════════════════════════════════════════════════
  RACK2CLOUD >_ VMWARE MIGRATION READINESS ASSESSMENT
  ════════════════════════════════════════════════════════

  ESTIMATED SCORE:  54 / 100
  RISK BAND:        HIGH DEBT

  FINDINGS BY DOMAIN:

  [!!] SNAPSHOTS    214 snapshots / 847 GB / 6 deep chains
  [!!] TOOLS        38% not running / 61% outdated
  [!!] ZOMBIES      23 candidates / 1,240 GB allocated / 71% untagged
  [!!] ISO HYGIENE  4 mounted / 11 orphaned on datastores / 94 GB reclaim
  [!!] RDM AUDIT    3 pRDM MIGRATION BLOCKERS — resolve before planning cutover

  ────────────────────────────────────────────────────────
  >_ Upload r2c_vmware_payload.json at:
     rack2cloud.com/audits/vmware-exit/
  to unlock your scored 3-page Migration Readiness Brief.
  ════════════════════════════════════════════════════════
```

The teaser names the category and the specific count — but not the remediation sequence or migration path. The full brief maps every finding to a ranked fix with effort vs. impact scoring, plus a readiness verdict for Nutanix Move.

---

### 2. The Payload: r2c_vmware_payload.json

The script writes a single file to your working directory (or the path specified by `-OutputPath`).

**Review it before uploading.** Open it in any text editor. Confirm no VM names, datastore paths, or IP addresses are present. The file contains only counts, booleans, percentages, and size totals.

<details>
<summary><strong>View Sample JSON Payload</strong></summary>

```json
{
  "audit_version": "1.0.0",
  "environment_type": "vcenter",
  "host_count": 8,
  "cluster_count": 2,
  "datastore_count": 14,
  "generated_utc": "2026-04-06T11:30:00Z",
  "estimated_score": 54,
  "risk_band": "HIGH DEBT",
  "score_breakdown": {
    "snapshot_score": 10,
    "tools_score": 8,
    "hygiene_score": 11,
    "rdm_score": 10
  },
  "snapshots": {
    "snapshot_count": 214,
    "snapshot_total_gb": 847.3,
    "chains_over_3_deep": 6,
    "oldest_snapshot_days": 412,
    "vms_with_snapshots_pct": 34.2
  },
  "tools": {
    "vms_total": 187,
    "tools_not_running_pct": 38.0,
    "tools_outdated_pct": 61.0,
    "tools_not_installed_pct": 8.0
  },
  "zombies": {
    "zombie_candidate_count": 23,
    "no_owner_tag_pct": 71.1,
    "powered_off_over_30d": 23,
    "zombie_storage_gb": 1240.0
  },
  "iso_hygiene": {
    "isos_mounted_count": 4,
    "isos_mounted_total_gb": 18.6,
    "orphan_iso_count": 11,
    "orphan_iso_total_gb": 94.2
  },
  "rdm": {
    "rdm_count": 5,
    "physical_rdm_count": 3,
    "virtual_rdm_count": 2,
    "vms_with_rdm_count": 4,
    "migration_blocker_flag": true
  }
}
```

</details>

---

### 3. The Scored Brief

Upload your `r2c_vmware_payload.json` at **[rack2cloud.com/audits/vmware-exit](https://rack2cloud.com/audits/vmware-exit)** to receive the full interpretation. Delivered as a 3-page tactical PDF within 2 business days:

- **Migration Readiness Score** (0–100) across all five domains
- **Risk band classification** with prescriptive messaging
- **Domain-level findings** — specific counts mapped to migration risk
- **Storage reclaim estimate** — orphaned snapshots, zombie VMs, ISO waste quantified in GB and estimated cost
- **RDM disposition plan** — pRDM blockers called out explicitly with resolution paths
- **"Fix This First" roadmap** — prioritized by effort vs. impact, sequenced for Nutanix Move readiness

---

## Scoring Framework

| Domain | Weight | What It Measures |
|---|---|---|
| Snapshots | 25% | Count, total storage, chain depth, snapshot age — migration risk multiplier |
| VMware Tools | 25% | Running state, version currency — tools debt causes in-flight migration failures |
| Hygiene (Zombie + ISO) | 25% | Unowned VMs, orphaned storage, mounted ISOs — dead weight that complicates cutover |
| RDM Exposure | 25% | Physical vs. virtual RDM count — pRDMs are hard migration blockers for HCI targets |

Score bands:

| Score | Band | Meaning |
|---|---|---|
| 85–100 | Migration Ready | Environment is clean. Proceed to sizing and cutover planning. |
| 70–84 | Moderate Debt | Addressable gaps. Remediate in parallel with migration planning. |
| 50–69 | High Debt | Significant blockers present. Remediate before scheduling cutover. |
| < 50 | Critical | Do not begin migration. High probability of mid-flight failure. |

---

## 🏗️ Required Permissions

The script requires **Read-Only** role at the vCenter or ESXi host level. It makes no changes to your environment — no power operations, no snapshot creation or deletion, no configuration changes of any kind.

For tag category inspection (zombie owner-tag check), standard read access to vCenter tag namespaces is sufficient. If tag permissions are restricted, the `no_owner_tag_pct` field will reflect only accessible VMs.

---

## What Comes After the Report

The Migration Readiness Brief is the first step in a structured exit path:

1. **Migration Readiness Assessment** ← You are here
2. **[HCI Migration Advisor](https://www.rack2cloud.com/vmware-to-hci-migration-advisor/)** — Upload your RVTools export for workload sizing and wave planning
3. **The Architect's Review** — Live engagement: full Nutanix Move migration plan, wave sequencing, and cutover runbook built with your team

---

## 🔍 Audit the Source

This script is fully open source. Every line is reviewable. There are no obfuscated sections, no telemetry, no external network calls, and no data transmission of any kind. The only network calls made are to the vSphere/vCenter API — the same API used by the vSphere Client.

If you identify a data collection concern or a bug, open an issue or submit a PR.

---

## License

MIT License — see [LICENSE](LICENSE)

---

## About

Built by [The Architect](https://rack2cloud.com) — 25+ years of enterprise infrastructure delivery across financial services, healthcare, manufacturing, and public sector.

**rack2cloud.com** | [VMware Exit Coverage](https://rack2cloud.com/post-broadcom-vmware-licensing-changes/) | [Contact](https://rack2cloud.com/contact)

# Horizon CPA — Image Drift Detector

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Horizon](https://img.shields.io/badge/Omnissa%20Horizon-2006%2B-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

A PowerShell script that scans all pods in a **Horizon Cloud Pod Architecture (CPA)** federation, compares the golden image and snapshot assigned to each pool per Global Desktop Entitlement, and generates a self-contained HTML report highlighting any drift.

---

## The problem it solves

In a CPA federation, each pod manages its own desktop pools that are linked to shared **Global Desktop Entitlements (GDEs)**. When an admin updates the golden image or snapshot in one pod but misses another, users connecting through different pods land on different desktops — silently, with no built-in alert.

```
GDE: Windows 10 Enterprise
  SiteA  →  Win10-GoldenVM  @  Snapshot-v6   ✓ In Sync
  SiteB  →  Win10-GoldenVM  @  Snapshot-v5   ⚠ DRIFT
```

This script catches that instantly across your entire federation.

---

## Requirements

- **PowerShell 5.1** or later (included in Windows 10 / Server 2016+)
- **Network access** to all Connection Servers in the federation
- **Horizon admin credentials** (read-only access is sufficient)
- Horizon **2006 (8.0)** or newer

---

## Usage

```powershell
.\horizon-drift-scan.ps1 -ConnectionServer cs01.corp.local -Domain corp
```

A Windows credential prompt appears. The script runs all four phases automatically and opens the HTML report in your browser when complete.

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-ConnectionServer` | ✅ | — | FQDN of any Connection Server in the federation |
| `-Domain` | ✅ | — | Active Directory domain name |
| `-ReportPath` | ❌ | `.\horizon-drift-report.html` | Output path for the HTML report |

### Examples

```powershell
# Basic scan
.\horizon-drift-scan.ps1 -ConnectionServer cs01.corp.local -Domain corp

# Save report to a specific path
.\horizon-drift-scan.ps1 -ConnectionServer cs01.corp.local -Domain corp `
    -ReportPath C:\Reports\drift-$(Get-Date -f 'yyyy-MM-dd').html
```

---

## How it works

The script runs in four phases:

### Phase 1 — CPA Discovery
Authenticates to the specified Connection Server and fetches the pod list via `/federation/v1/pods`. For each remote pod it resolves the Connection Server FQDN from the endpoint list and authenticates to it independently with the same credentials.

### Phase 2 — Inventory
Per pod, fetches all desktop pools via `/inventory/v3/desktop-pools` (automatically falls back to v2 then v1 for older versions). Extracts from each pool:
- `provisioning_settings.parent_vm_id` — the master image VM
- `provisioning_settings.base_snapshot_id` — the snapshot
- `vcenter_id` — which vCenter manages this pool

### Phase 3 — Name Translation
Resolves raw vCenter object IDs to human-readable names using:
- `/external/v1/virtual-machines?vcenter_id=...`
- `/external/v2/base-snapshots?vcenter_id=...&base_vm_id=...`

Results are cached per vCenter to minimise API calls.

### Phase 4 — Drift Comparison
Groups pools by their `global_desktop_entitlement_id`. For each GDE, collects the distinct VM names and snapshot names across all pods. If more than one distinct value exists, **every pod in that GDE is flagged** — there is no "reference" pod; any disagreement means the whole GDE is out of sync.

---

## Console output

```
PHASE 1 - CPA Discovery
  Authenticating to cs01.corp.local ...
  Authenticated as administrator
  Federation pods: SiteA, SiteB
  Local pod 'SiteA' -> cs01.corp.local
  Remote pod 'SiteB' -> cs02.corp.local
  Authenticated to 'SiteB'

PHASE 2+3 - Inventory and Translation
  --- Pod: SiteA (cs01.corp.local) ---
    3 pool(s) from inventory/v3
    2 GDE name(s) mapped
    VM lookup: 12 VMs
    Snapshots: 4 for VM vm-1001
  --- Pod: SiteB (cs02.corp.local) ---
    3 pool(s) from inventory/v3
    2 GDE name(s) mapped
    VM lookup: 12 VMs
    Snapshots: 4 for VM vm-1001

PHASE 4 - Drift Comparison
  Sync:  Win10-LTSC-GE
  DRIFT: Windows 10 Enterprise

Report saved: C:\Reports\horizon-drift-report.html
Done.
```

---

## HTML Report

The report is a **single self-contained HTML file** — no server, no dependencies, no internet required to view it. It can be emailed, archived, or opened offline.

It includes:
- **Summary strip** — total entitlements, in-sync count, drift count, pools scanned
- **Per-GDE cards** — expandable/collapsible, amber accent on any drifted entitlement
- **Per-pod rows** — pod, pool name, master image VM, snapshot, sync status
- **Inline drift tags** — highlights the exact field that differs
- **Animated status indicators** — pulsing green dot for sync, amber for drift

---

## Compatibility

| Horizon Version | Inventory API used | Status |
|---|---|---|
| 2512 (Omnissa) | v3 | ✅ Tested |
| 2306 – 2412 | v3 | ✅ Supported |
| 2111 – 2303 | v3 / v2 | ✅ Auto-detected |
| 2006 – 2103 | v1 | ✅ Auto-detected |

---

## Important — How drift is detected

The script identifies drift by **comparing the display names** of the master image VM and snapshot across pods. It does not compare vCenter object IDs or any internal identifiers.

This means:

- A VM named `Win10-GoldenVM` on SiteA and a VM named `Win10-GoldenVM` on SiteB will be treated as **in sync**
- A VM named `Win10-GoldenVM` on SiteA and `Win10-Golden-VM` on SiteB will be treated as **drift** — even if they are the same image

**To get accurate results, the master image VM and snapshot must have identical names on every pod in the federation.** This is the recommended practice when managing a CPA environment: always use the same naming convention for golden images and snapshots across all sites.

---

## Notes

- **Self-signed certificates** are handled automatically — works in typical lab and enterprise environments with internal CAs.
- **Non-IC pools** (manual or linked-clone pools with no golden image) are detected, labelled `non-IC pool`, and excluded from drift comparison.
- **Session tokens** are invalidated at the end of every run via `HvLogout` on each pod's Connection Server.
- Credentials are **never written to disk**.

---

## Author

**Guy Hemed** — [Terasky](https://www.terasky.com)

---

## License

MIT

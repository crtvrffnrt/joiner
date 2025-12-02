# Joiner VM Provisioning & Post-Setup Automation

## Overview

This repository contains a set of Bash and PowerShell scripts used to stand up short-lived Windows hosts in Azure, lock down inbound access, and hydrate the OS with tooling commonly required by offensive security and purple-team engagements. The collection now includes:

- `joiner.sh` – deploys a Windows 10 workstation that joins Entra ID.
- `createWinServer.sh` – builds a hardened Windows Server 2025 VM and chains the stage‑1 (`21.ps1`) and stage‑2 (`22.ps1`) bootstrap scripts.
- Supporting PowerShell scripts (`1.ps1`, `2.ps1`, `3.ps1`, `21.ps1`, `22.ps1`, `installtools.ps1`) that run inside the guest to disable protections, configure WinRM/RDP, and install red-team tooling.

Use cases include red/purple-team jump hosts, Entra ID lab environments, and analyst sandboxes that need to be reproducible yet disposable.

---

## Repository Map

| File | Purpose |
| --- | --- |
| `joiner.sh` | Primary workstation deployment script (unchanged because it already meets the new standard). |
| `createWinServer.sh` | Server-focused deployment flow with improved validation, dependency checks, and script-source overrides. |
| `1.ps1` | Captures credential parameters inside the VM with input validation and logging. |
| `2.ps1` | Full host hardening + tooling install runbook (WinRM/RDP enablement, Defender controls, tool installs). |
| `3.ps1` | Lightweight post-join helper enabling WinRM/HTTPS, German keyboard layout, and LSASS changes. |
| `21.ps1` | Stage‑1 script dropped by Azure extension to prime Defender exclusions before stage‑2 runs. |
| `22.ps1` | Stage‑2 payload that installs tooling via Winget/Git and finalizes the desktop. |
| `installtools.ps1` | Stand-alone tooling installer that can be executed manually after provisioning. |

All PowerShell scripts now share consistent logging helpers, strict-mode execution, and idempotent operations.

---

## Prerequisites

- Azure subscription + role permitting VM/NSG/extension creation.
- Azure CLI 2.50+ authenticated via `az login --use-device-code`.
- Bash environment with `sshpass`, `evil-winrm`, and `xfreerdp3` (or skip the post-build connection prompt).
- PowerShell 5.1+ inside the VM (Windows 10/11 or Server 2022+ already satisfy this).
- Git access to clone this repository.

---

## Quick Start (Joiner Workstation)

```bash
git clone https://github.com/crtvrffnrt/joiner
cd joiner
chmod +x joiner.sh
./joiner.sh -r "<your-public-ip>" -u "<entra-upn>" -d "<entra-domain>" -p "<entra-password>"
```

The `-r` flag restricts inbound NSG access to your IP. Credentials are passed to the VM so that the Entra join succeeds automatically. See the script banner for optional flags.

---

---

## Guest-Side Script Flow

1. **Stage 1 (`21.ps1`)** – runs first via Custom Script Extension. Adds Defender exclusions and launches Stage 2 once the files are present.
2. **Stage 2 (`22.ps1`)** – installs Winget (if missing), lays down Git/Python/VS Build Tools, installs Azure/M365 modules, clones offensive repositories, refreshes the desktop theme, and reboots.
3. **`installtools.ps1`** – a reusable tooling bootstrapper you can re-run manually. It mirrors Stage 2 but includes optional extras (Azure CLI, Ghidra, PowerToys, etc.).
4. **`2.ps1` & `3.ps1`** – more opinionated host configuration sequences (WinRM HTTPS, firewall relaxations, keyboard layout adjustments, LSASS tampering). Run them only on isolated lab systems.
5. **`1.ps1`** – primarily for debugging; captures the run parameters for audit purposes inside `C:\<ResourceGroup>-1scriptwasexecuted\params.txt`.

Each script writes to `C:\setup_log.txt` on errors and drops a marker folder (`C:\endofscriptreached_*`) so you can check which steps completed.


---

## Security & Clean-Up Considerations

- `joiner.sh` keeps the freshly created resource group on failure so you can investigate. Pass `--delete-on-fail` if you still want the cleanup behavior. `createWinServer.sh` continues to delete stale `WinServAttack*` groups on startup. Never reuse those prefixes for persistent infrastructure.
- Defender, firewall, LSASS, and WinRM changes are invasive. Run the guest-side scripts only in labs you can rebuild from scratch.
- Credentials passed to `joiner.sh` or stored by `1.ps1` are in plaintext for automation purposes—rotate them immediately after use.
- To destroy a lab quickly, delete the generated resource group:
  ```bash
  az group delete -n <resource-group> --yes --no-wait
  ```

Use these scripts responsibly and only in environments where aggressive system modifications are acceptable.
  

# Joiner VM Provisioning & Post-Setup Automation

## Overview

This project provides a Bash-based automation script (`joiner.sh`) and a PowerShell provisioning script (`installtools.ps1`) to:

- Rapidly deploy a Windows-based Azure VM (Windows 10 Pro Gen1) with custom configuration
- Enable Microsoft Entra ID (Azure AD) login via extension
- Restrict inbound access via NSG rules to a user-specified IP
- Perform post-provisioning actions including tool installation, module setup, and environment hardening

### Primary Use Cases

- Offensive security testing environments
- Analyst sandboxes
- Entra ID integration testing
- Controlled ephemeral VM deployments for red/purple teams

---

## ⚠️ WARNING: Resource Group Deletion

This script **automatically deletes** all Azure Resource Groups that match the naming pattern:

thiefjoinerRGDeleteme*

- **Deletion is non-interactive and irreversible.**
- Only use this script in environments where resource cleanup is expected.
- Never use the above naming pattern for persistent infrastructure.

- ---

## Components

### `joiner.sh`

- Deploys a Windows 10 VM in `germanywestcentral`
- Configures NSG rules to allow inbound access only from your IP
- Enables Entra ID login via `AADLoginForWindows` extension
- Executes provisioning via `run-command` and `CustomScriptExtension`
- Supports SSH, RDP, and Evil-WinRM login methods

### `installtools.ps1`

Executed within the provisioned VM to:

- Disable Microsoft Defender (for red team scenarios)
- Install Winget (if missing)
- Install commonly used tools:
  - Git, Python, Nmap, PowerToys, Azure CLI, etc.
- Install PowerShell modules:
  - AADInternals, MSOnline, Az, Microsoft.Graph, AzureAD.Standard.Preview, etc.
- Clone red team tools from base64-encoded GitHub URLs
- Adjust user environment (black background, no wallpaper)
- Trigger reboot and create completion marker

---

## Usage

```bash
chmod +x joiner.sh
./joiner.sh -r <your-ip-in-cidr> -u <entra-username> -d <entra-domain> -p <plaintext-password>
```
Example

```bash
./joiner.sh -r "203.0.113.42" -u "john.doe@contoso.com" -d "contoso.com" -p "ThisIsNotaRealP@ssword"
```


## Security Considerations
- VM is deployed with Gen1 image (no TPM) for compatibility
- Microsoft Defender is disabled as part of post-setup
- Use only in isolated, non-production environments
- Avoid hardcoding sensitive credentials unless necessary for automation
  

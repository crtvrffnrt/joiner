#!/usr/bin/env bash
set -euo pipefail

export PYTHONWARNINGS="ignore::FutureWarning"

readonly DEFAULT_LOCATION="germanywestcentral"
readonly DEFAULT_VM_SIZE="Standard_B4s_v2"
readonly DEFAULT_IMAGE="MicrosoftWindowsDesktop:windows11preview:win11-25h2-ent-cpc-m365:latest"
readonly ADMIN_USERNAME="joiner"
readonly RG_PREFIX="thiefjoinerRGDeleteme"
readonly AUTO_SHUTDOWN_TIME="1900"
readonly FEATURE_NAMESPACE="Microsoft.Compute"
readonly FEATURE_NAME="UseStandardSecurityType"

RESOURCE_GROUP=""
VM_NAME=""
NSG_NAME=""
PUBLIC_IP=""
ADMIN_PASSWORD=""
SCRIPT_SUCCESS=false

PROMPT_FOR_CONNECTION=true
CLEANUP_STALE_GROUPS=true
DELETE_FAILED_RG=true
LOCATION="$DEFAULT_LOCATION"
VM_SIZE="$DEFAULT_VM_SIZE"
VM_IMAGE="$DEFAULT_IMAGE"

usage() {
    cat <<'EOF'
Usage: ./joiner.sh -r <allowed-ip/cidr> -u <entra-user> -d <entra-domain> -p <entra-password> [options]

Required
  -r, --range        CIDR or single IP allowed inbound through the NSG
  -u, --user         Entra ID username (e.g. john.doe@contoso.com)
  -d, --domain       Entra ID domain (e.g. contoso.com)
  -p, --password     Entra ID password (plaintext)

Optional
      --location     Azure location (default: germanywestcentral)
      --vm-size      Azure VM SKU (default: Standard_F4s)
      --image        Azure image URN (default: Win11 25H2 CPC M365)
      --keep-old     Skip deleting previously created thiefjoinerRGDeleteme* groups
      --keep-on-fail Keep the newly created resource group when the script fails
      --no-connect   Do not offer an interactive SSH/RDP connection at the end
  -h, --help         Show this help and exit
EOF
}

display_message() {
    local message="$1"
    local color="${2:-}"
    case "$color" in
        red) printf '\033[91m%s\033[0m\n' "$message" ;;
        green) printf '\033[92m%s\033[0m\n' "$message" ;;
        yellow) printf '\033[93m%s\033[0m\n' "$message" ;;
        blue) printf '\033[94m%s\033[0m\n' "$message" ;;
        *) printf '%s\n' "$message" ;;
    esac
}

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        display_message "Missing required command: $cmd" "red"
        exit 1
    fi
}

json_escape() {
    local str="$1"
    str=${str//\\/\\\\}
    str=${str//\"/\\\"}
    str=${str//$'\n'/\\n}
    str=${str//$'\r'/\\r}
    str=${str//$'\t'/\\t}
    printf '%s' "$str"
}

cleanup_on_exit() {
    if [[ "$SCRIPT_SUCCESS" == true ]]; then
        return
    fi

    if [[ -n "$RESOURCE_GROUP" && "$DELETE_FAILED_RG" == true ]]; then
        display_message "Deleting failed resource group '$RESOURCE_GROUP'..." "yellow"
        az group delete \
            --name "$RESOURCE_GROUP" \
            --yes \
            --no-wait \
            --only-show-errors || true
    fi
}
trap cleanup_on_exit EXIT

generate_random_password() {
    local password
    password=$(tr -dc 'A-Za-z0-9!@#%^&*' < /dev/urandom | head -c 24 || true)
    printf '%s' "$password"
}

random_suffix() {
    local suffix
    suffix=$(tr -dc '0-9' < /dev/urandom | head -c 4 || true)
    printf '%s' "$suffix"
}

check_azure_authentication() {
    if ! az account show --only-show-errors >/dev/null 2>&1; then
        display_message "Please authenticate to Azure with 'az login --use-device-code' before running this script." "red"
        exit 1
    fi
}

ensure_security_type_feature() {
    local state
    state=$(az feature show \
        --namespace "$FEATURE_NAMESPACE" \
        --name "$FEATURE_NAME" \
        --query "properties.state" \
        -o tsv 2>/dev/null || echo "")

    if [[ "$state" == "Registered" ]]; then
        display_message "Feature ${FEATURE_NAMESPACE}/${FEATURE_NAME} already registered." "green"
        return
    fi

    display_message "Registering feature ${FEATURE_NAMESPACE}/${FEATURE_NAME}..." "yellow"
    az feature register \
        --namespace "$FEATURE_NAMESPACE" \
        --name "$FEATURE_NAME" \
        --only-show-errors >/dev/null

    display_message "Registration submitted. Azure can take several minutes. Re-run the script once registration completes:" "yellow"
    display_message "az feature show --namespace $FEATURE_NAMESPACE --name $FEATURE_NAME --query properties.state -o tsv" "blue"
    exit 1
}

delete_old_resource_groups() {
    display_message "Looking for stale resource groups matching ${RG_PREFIX}* ..." "blue"
    local groups_found=0
    while IFS= read -r group; do
        [[ -z "$group" ]] && continue
        groups_found=1
        display_message "Deleting stale resource group '$group'..." "yellow"
        az group delete \
            --name "$group" \
            --yes \
            --no-wait \
            --only-show-errors >/dev/null && \
            display_message "Scheduled deletion for '$group'." "green"
    done < <(az group list --query "[?starts_with(name, '${RG_PREFIX}')].name" -o tsv)

    if [[ "$groups_found" -eq 0 ]]; then
        display_message "No stale resource groups found." "green"
    fi
}

create_resource_group() {
    display_message "Creating resource group '$RESOURCE_GROUP' in $LOCATION..." "blue"
    az group create \
        --name "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --only-show-errors >/dev/null
}

create_nsg() {
    display_message "Creating network security group '$NSG_NAME'..." "blue"
    az network nsg create \
        --name "$NSG_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --only-show-errors >/dev/null
}

configure_nsg_rules() {
    local allowed_ip="$1"

    display_message "Configuring NSG rules for $allowed_ip ..." "blue"

    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG_NAME" \
        --name "AllowJoinerInbound" \
        --priority 200 \
        --direction Inbound \
        --access Allow \
        --protocol Tcp \
        --source-address-prefixes "$allowed_ip" \
        --source-port-ranges '*' \
        --destination-address-prefixes '*' \
        --destination-port-ranges 3389 22 5985 5986 \
        --only-show-errors >/dev/null

    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG_NAME" \
        --name "DenyAllInbound" \
        --priority 1000 \
        --direction Inbound \
        --access Deny \
        --protocol '*' \
        --source-address-prefixes '*' \
        --source-port-ranges '*' \
        --destination-address-prefixes '*' \
        --destination-port-ranges '*' \
        --only-show-errors >/dev/null
}

wait_for_vm_power_state() {
    local desired_state="$1"
    local message="$2"

    display_message "$message" "blue"
    while true; do
        local state
        state=$(az vm get-instance-view \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VM_NAME" \
            --query "instanceView.statuses[?starts_with(code,'PowerState/')].code" \
            -o tsv)

        if [[ "$state" == "$desired_state" ]]; then
            display_message "VM reached state $desired_state." "green"
            break
        fi

        display_message "Current state: ${state:-unknown}. Waiting 15 seconds..." "yellow"
        sleep 15
    done
}

wait_for_vm_agent_ready() {
    display_message "Waiting for VM agent to report ProvisioningState/succeeded ..." "blue"
    while true; do
        local agent_status
        agent_status=$(az vm get-instance-view \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VM_NAME" \
            --query "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded'].displayStatus" \
            -o tsv)

        if [[ "$agent_status" == "Ready" ]]; then
            display_message "VM agent is Ready." "green"
            return
        fi

        display_message "VM agent still provisioning. Sleeping 30 seconds..." "yellow"
        sleep 30
    done
}

enable_aad_login() {
    display_message "Enabling Entra ID login extension..." "blue"
    az vm extension set \
        --resource-group "$RESOURCE_GROUP" \
        --vm-name "$VM_NAME" \
        --name AADLoginForWindows \
        --publisher Microsoft.Azure.ActiveDirectory \
        --version 1.0 \
        --only-show-errors >/dev/null
}

run_inline_script() {
    local tempfile
    tempfile=$(mktemp)
    cat <<'POWERSHELL' > "$tempfile"
param(
    [string]$username,
    [string]$domain,
    [string]$password,
    [string]$RESOURCE_GROUP
)

try {
    $url = "https://raw.githubusercontent.com/crtvrffnrt/joiner/refs/heads/main/3.ps1"
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60
    if ($response.StatusCode -ne 200) {
        throw "Failed to download script. HTTP Status: $($response.StatusCode)"
    }

    $scriptContent = $response.Content
    if ([string]::IsNullOrWhiteSpace($scriptContent)) {
        throw "Downloaded script content is empty."
    }

    & ([scriptblock]::Create($scriptContent)) -username $username -domain $domain -password $password -RESOURCE_GROUP $RESOURCE_GROUP
}
catch {
    Write-Host "Error executing bootstrap script: $_"
    exit 1
}
POWERSHELL

    az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --command-id RunPowerShellScript \
        --scripts @"$tempfile" \
        --parameters "username=$ENTRA_USERNAME" "domain=$ENTRA_DOMAIN" "password=$ENTRA_PASSWORD" "RESOURCE_GROUP=$RESOURCE_GROUP" \
        --only-show-errors >/dev/null

    rm -f "$tempfile"
}

run_custom_script_extension() {
    display_message "Installing tools via CustomScriptExtension..." "blue"
    local escaped_username escaped_domain escaped_password escaped_rg settings
    escaped_username=$(json_escape "$ENTRA_USERNAME")
    escaped_domain=$(json_escape "$ENTRA_DOMAIN")
    escaped_password=$(json_escape "$ENTRA_PASSWORD")
    escaped_rg=$(json_escape "$RESOURCE_GROUP")
    settings=$(cat <<JSON
{
  "fileUris": [
    "https://raw.githubusercontent.com/crtvrffnrt/joiner/refs/heads/main/1.ps1"
  ],
  "commandToExecute": "powershell -ExecutionPolicy Bypass -File 1.ps1 -username \\"${escaped_username}\\" -domain \\"${escaped_domain}\\" -password \\"${escaped_password}\\" -RESOURCE_GROUP \\"${escaped_rg}\\""
}
JSON
)

    az vm extension set \
        --resource-group "$RESOURCE_GROUP" \
        --vm-name "$VM_NAME" \
        --name CustomScriptExtension \
        --publisher Microsoft.Compute \
        --settings "$settings" \
        --only-show-errors >/dev/null
}

configure_auto_shutdown() {
    display_message "Configuring auto-shutdown at ${AUTO_SHUTDOWN_TIME}..." "blue"
    az vm auto-shutdown \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --time "$AUTO_SHUTDOWN_TIME" \
        --only-show-errors >/dev/null
}

retrieve_public_ip() {
    PUBLIC_IP=$(az vm show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        -d \
        --query "publicIps" \
        -o tsv)
}

prompt_for_connection() {
    if [[ "$PROMPT_FOR_CONNECTION" != true ]]; then
        return
    fi

    printf '\n'
    read -r -p "Connect now via ssh or rdp? (ssh/rdp/skip): " connection_choice
    case "$connection_choice" in
        ssh)
            require_command sshpass
            display_message "Opening SSH session..." "blue"
            sshpass -p "$ADMIN_PASSWORD" ssh -o StrictHostKeyChecking=no "$ADMIN_USERNAME@$PUBLIC_IP"
            ;;
        rdp)
            local rdp_cmd=""
            if command -v xfreerdp >/dev/null 2>&1; then
                rdp_cmd="xfreerdp"
            elif command -v xfreerdp3 >/dev/null 2>&1; then
                rdp_cmd="xfreerdp3"
            elif [[ -x /usr/bin/xfreerdp3 ]]; then
                rdp_cmd="/usr/bin/xfreerdp3"
            fi

            if [[ -z "$rdp_cmd" ]]; then
                display_message "xfreerdp is not installed. Install it or choose ssh." "red"
                exit 1
            fi

            display_message "Opening RDP session via $rdp_cmd..." "blue"
            "$rdp_cmd" /v:"$PUBLIC_IP" /u:"$ADMIN_USERNAME" /p:"$ADMIN_PASSWORD" /cert:ignore /dynamic-resolution /clipboard /drive:joiner,./ /admin
            ;;
        skip|"")
            display_message "Skipping interactive connection." "yellow"
            ;;
        *)
            display_message "Unknown option '$connection_choice'." "red"
            exit 1
            ;;
    esac
}

summarize() {
    cat <<EOF

Connect to your VM with the following details:
  Resource Group : $RESOURCE_GROUP
  VM Name        : $VM_NAME
  Location       : $LOCATION
  Public IP      : $PUBLIC_IP
  Local Admin    : $ADMIN_USERNAME
  Admin Password : $ADMIN_PASSWORD

Suggested commands:
  cmdkey /generic:"$PUBLIC_IP" /user:"$ADMIN_USERNAME" /pass:"$ADMIN_PASSWORD"; mstsc /v:$PUBLIC_IP
  sshpass -p "$ADMIN_PASSWORD" ssh -o StrictHostKeyChecking=no "$ADMIN_USERNAME@$PUBLIC_IP"
  evil-winrm -i "$PUBLIC_IP" -u "$ADMIN_USERNAME" -p "$ADMIN_PASSWORD" -P 5985
EOF
}

parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -r|--range)
                ALLOWED_IP="$2"
                shift 2
                ;;
            -u|--user)
                ENTRA_USERNAME="$2"
                shift 2
                ;;
            -d|--domain)
                ENTRA_DOMAIN="$2"
                shift 2
                ;;
            -p|--password)
                ENTRA_PASSWORD="$2"
                shift 2
                ;;
            --location)
                LOCATION="$2"
                shift 2
                ;;
            --vm-size)
                VM_SIZE="$2"
                shift 2
                ;;
            --image)
                VM_IMAGE="$2"
                shift 2
                ;;
            --no-connect)
                PROMPT_FOR_CONNECTION=false
                shift
                ;;
            --keep-old)
                CLEANUP_STALE_GROUPS=false
                shift
                ;;
            --keep-on-fail)
                DELETE_FAILED_RG=false
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                display_message "Unknown argument: $1" "red"
                usage
                exit 1
                ;;
        esac
    done

    if [[ -z "${ALLOWED_IP:-}" || -z "${ENTRA_USERNAME:-}" || -z "${ENTRA_DOMAIN:-}" || -z "${ENTRA_PASSWORD:-}" ]]; then
        display_message "Missing required arguments." "red"
        usage
        exit 1
    fi
}

main() {
    parse_args "$@"
    require_command az

    check_azure_authentication
    ensure_security_type_feature

    if [[ "$CLEANUP_STALE_GROUPS" == true ]]; then
        delete_old_resource_groups
    fi

    ADMIN_PASSWORD=$(generate_random_password)
    local suffix
    suffix=$(random_suffix)
    RESOURCE_GROUP="${RG_PREFIX}${suffix}"
    VM_NAME="win${suffix}"
    NSG_NAME="${VM_NAME}-nsg"

    create_resource_group
    create_nsg
    configure_nsg_rules "$ALLOWED_IP"

    display_message "Starting VM deployment..." "blue"
    PUBLIC_IP=$(az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --image "$VM_IMAGE" \
        --size "$VM_SIZE" \
        --nsg "$NSG_NAME" \
        --admin-username "$ADMIN_USERNAME" \
        --admin-password "$ADMIN_PASSWORD" \
        --license-type Windows_Client \
        --accept-term \
        --security-type Standard \
        --public-ip-sku Standard \
        --only-show-errors \
        --query "publicIpAddress" \
        -o tsv)

    wait_for_vm_power_state "PowerState/running" "Waiting for VM to enter 'running' state..."
    enable_aad_login
    wait_for_vm_agent_ready
    configure_auto_shutdown

    run_inline_script
    wait_for_vm_power_state "PowerState/running" "Waiting for VM to finish reboot after bootstrap..."
    run_custom_script_extension
    wait_for_vm_power_state "PowerState/running" "Waiting for VM to finish reboot after CustomScriptExtension..."
    az vm restart --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --only-show-errors >/dev/null
    wait_for_vm_power_state "PowerState/running" "Final restart in progress..."

    retrieve_public_ip
    display_message "VM provisioning complete!" "green"
    summarize
    prompt_for_connection

    SCRIPT_SUCCESS=true
}

main "$@"

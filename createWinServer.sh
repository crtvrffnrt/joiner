#!/bin/bash

set -euo pipefail

export PYTHONWARNINGS="ignore::FutureWarning"

RAW_BASE_URL=${RAW_BASE_URL:-"https://raw.githubusercontent.com/crtvrffnrt/joiner/refs/heads/main"}
LOCATION=${LOCATION:-"germanywestcentral"}
VM_SIZE=${VM_SIZE:-"Standard_F4s_v2"}
IMAGE=${IMAGE:-"MicrosoftWindowsServer:WindowsServer:2025-datacenter-azure-edition:latest"}
DEFAULT_USERNAME=${DEFAULT_USERNAME:-"joiner"}

trap 'display_message "Script failed at line ${LINENO}. Check Azure resources for partial deployments." "red"' ERR

display_message() {
    local message="$1"
    local color="${2:-default}"
    case $color in
        red) echo -e "\033[91m${message}\033[0m" ;;
        green) echo -e "\033[92m${message}\033[0m" ;;
        yellow) echo -e "\033[93m${message}\033[0m" ;;
        blue) echo -e "\033[94m${message}\033[0m" ;;
        *) echo "$message" ;;
    esac
}

usage() {
    cat <<EOF
Usage: $(basename "$0") -r <allowed-ip-or-cidr>

Required:
  -r  Public IP or CIDR allowed through the NSG (e.g. 203.0.113.10 or 203.0.113.0/32)

Environment overrides:
  RAW_BASE_URL     Source for 21.ps1 / 22.ps1 (default: ${RAW_BASE_URL})
  LOCATION         Azure region (default: ${LOCATION})
  VM_SIZE          VM size (default: ${VM_SIZE})
  IMAGE            Azure image URN (default: ${IMAGE})
  DEFAULT_USERNAME Local admin username (default: ${DEFAULT_USERNAME})
EOF
    exit 1
}

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        display_message "Missing required command: $cmd" "red"
        exit 1
    fi
}

check_azure_authentication() {
    if ! az account show >/dev/null 2>&1; then
        display_message "Authenticate to Azure first: az login --use-device-code" "red"
        exit 1
    fi
}

delete_old_resource_groups() {
    az group list --query "[?starts_with(name, 'WinServAttack')].name" -o tsv | while read -r group; do
        [ -z "$group" ] && continue
        if az group delete --name "$group" --yes --no-wait >/dev/null 2>&1; then
            display_message "Scheduled deletion for resource group: $group" "green"
        else
            display_message "Unable to delete resource group: $group" "yellow"
        fi
    done
}

generate_random_hostname() {
    local charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local random_part=""
    for _ in {1..6}; do
        random_part+="${charset:RANDOM%${#charset}:1}"
    done
    echo "DESKTOP-$random_part"
}

configure_nsg_rules() {
    local nsg_name="$1"
    local resource_group="$2"
    local allowed_ip="$3"

    az network nsg rule create \
        --resource-group "$resource_group" \
        --nsg-name "$nsg_name" \
        --name DenyInbound \
        --priority 1000 \
        --direction Inbound \
        --access Deny \
        --protocol '*' \
        --source-address-prefixes '*' \
        --source-port-ranges '*' \
        --destination-address-prefixes '*' \
        --destination-port-ranges '*' >/dev/null

    az network nsg rule create \
        --resource-group "$resource_group" \
        --nsg-name "$nsg_name" \
        --name AllowInbound \
        --priority 200 \
        --direction Inbound \
        --access Allow \
        --protocol Tcp \
        --source-address-prefixes "$allowed_ip" \
        --source-port-ranges '*' \
        --destination-address-prefixes '*' \
        --destination-port-ranges 3389 22 5985 5986 >/dev/null
}

wait_for_vm_to_be_running() {
    local resource_group="$1"
    local vm_name="$2"

    while true; do
        local vm_state
        vm_state=$(az vm get-instance-view --resource-group "$resource_group" --name "$vm_name" --query "instanceView.statuses[?code=='PowerState/running'].code" -o tsv)
        if [[ "$vm_state" == "PowerState/running" ]]; then
            display_message "VM is running. Waiting for services to initialize..." "yellow"
            sleep 30
            break
        fi
        display_message "Waiting for VM to be running..." "yellow"
        sleep 10
    done
}

generate_random_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 15 && printf "+"
}

validate_ip_input() {
    local ip="$1"
    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; then
        display_message "Invalid IP/CIDR provided: $ip" "red"
        exit 1
    fi
}

deploy_extension() {
    local rg="$1"
    local vm="$2"
    local script_name="$3"
    local command="$4"
    local payload

    payload=$(cat <<EOF
{"fileUris": ["${RAW_BASE_URL}/${script_name}"], "commandToExecute": "${command}"}
EOF
)

    az vm extension set \
        --resource-group "$rg" \
        --vm-name "$vm" \
        --name CustomScriptExtension \
        --publisher Microsoft.Compute \
        --settings "$payload" >/dev/null
}

prompt_connection() {
    local ip="$1"
    local user="$2"
    local password="$3"

    read -rp "Connect via (ssh/rdp/evilwinrm/skip)? " connection_choice
    case "$connection_choice" in
        ssh)
            require_command sshpass
            sshpass -p "$password" ssh -o StrictHostKeyChecking=no "$user@$ip"
            ;;
        rdp)
            require_command xfreerdp3
            xfreerdp3 /v:"$ip" /u:"$user" /p:"$password" /cert:ignore /dynamic-resolution /clipboard /drive:joiner,./ /admin
            ;;
        evilwinrm)
            require_command evil-winrm
            evil-winrm -i "$ip" -u "$user" -p "$password"
            ;;
        skip|"")
            display_message "Skipping interactive connection." "yellow"
            ;;
        *)
            display_message "Invalid choice. Exiting." "red"
            exit 1
            ;;
    esac
}

main() {
    local allowed_ip=""
    while getopts "r:h" opt; do
        case $opt in
            r) allowed_ip="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    if [[ -z "$allowed_ip" ]]; then
        usage
    fi
    validate_ip_input "$allowed_ip"

    require_command az
    check_azure_authentication
    delete_old_resource_groups
    sleep 3

    local random_suffix
    random_suffix=$(echo $RANDOM$RANDOM | head -c 4)
    local resource_group="WinServAttack${random_suffix}"
    local vm_name
    vm_name=$(generate_random_hostname)
    local admin_password
    admin_password=$(generate_random_password)
    local nsg_name="${vm_name}-nsg"

    display_message "Creating Resource Group ${resource_group} in ${LOCATION}..." "blue"
    az group create --name "$resource_group" --location "$LOCATION" >/dev/null

    display_message "Creating NSG ${nsg_name} and configuring rules..." "blue"
    az network nsg create --resource-group "$resource_group" --name "$nsg_name" >/dev/null
    configure_nsg_rules "$nsg_name" "$resource_group" "$allowed_ip"

    display_message "Provisioning Windows Server VM ${vm_name}..." "blue"
    az vm create \
        --resource-group "$resource_group" \
        --name "$vm_name" \
        --image "$IMAGE" \
        --admin-username "$DEFAULT_USERNAME" \
        --admin-password "$admin_password" \
        --license-type Windows_Server --accept-term \
        --public-ip-sku Standard --size "$VM_SIZE" \
        --nsg "$nsg_name" \
        --computer-name "$vm_name" >/dev/null

    wait_for_vm_to_be_running "$resource_group" "$vm_name"

    display_message "Waiting 60 seconds for VM services to stabilize..." "yellow"
    sleep 60

    display_message "Deploying stage 1 script (21.ps1)..." "blue"
    deploy_extension "$resource_group" "$vm_name" "21.ps1" "powershell -ExecutionPolicy Bypass -File 21.ps1"
    sleep 60

    display_message "Deploying stage 2 script (22.ps1)..." "blue"
    deploy_extension "$resource_group" "$vm_name" "22.ps1" "powershell -ExecutionPolicy Bypass -File 22.ps1"
    sleep 180

    display_message "Ensuring hostname consistency..." "blue"
    local hostname_vm
    hostname_vm=$(az vm get-instance-view --resource-group "$resource_group" --name "$vm_name" --query "computerName" -o tsv)
    if [[ "$hostname_vm" == "$vm_name" ]]; then
        display_message "Hostname verified: $hostname_vm" "green"
    else
        display_message "Hostname mismatch (expected $vm_name, got $hostname_vm)" "yellow"
    fi

    display_message "Issuing final VM reboot..." "blue"
    az vm restart --resource-group "$resource_group" --name "$vm_name" >/dev/null

    display_message "Waiting for VM to return to running state..." "yellow"
    az vm wait --resource-group "$resource_group" --name "$vm_name" --custom "instanceView.statuses[?code=='PowerState/running']" --timeout 300 >/dev/null

    local public_ip
    public_ip=$(az vm show --resource-group "$resource_group" --name "$vm_name" -d --query "publicIps" -o tsv)

    cat <<EOF

================== Connection Details ==================
Resource Group : $resource_group
VM Name        : $vm_name
Public IP      : $public_ip
Username       : $DEFAULT_USERNAME
Password       : $admin_password
========================================================
EOF

    prompt_connection "$public_ip" "$DEFAULT_USERNAME" "$admin_password"
}

main "$@"

#!/bin/bash

display_message() {
    local message="$1"
    local color="$2"
    case $color in
        red) echo -e "\033[91m${message}\033[0m" ;;
        green) echo -e "\033[92m${message}\033[0m" ;;
        yellow) echo -e "\033[93m${message}\033[0m" ;;
        blue) echo -e "\033[94m${message}\033[0m" ;;
        *) echo "$message" ;;
    esac
}

export PYTHONWARNINGS="ignore::FutureWarning"

check_azure_authentication() {
    az account show &> /dev/null
    if [ $? -ne 0 ]; then
        display_message "Please authenticate to Azure using 'az login --use-device-code'." "red"
        exit 1
    fi
}

delete_old_resource_groups() {
    az group list --query "[?starts_with(name, 'WinServAttack')].name" -o tsv | while read -r group; do
        az group delete --name "$group" --yes --no-wait &> /dev/null
        if [ $? -eq 0 ]; then
            display_message "Deleted old resource group: $group" "green"
        else
            display_message "Failed to delete resource group: $group" "red"
        fi
    done
}

generate_random_hostname() {
    local charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local random_part=""
    for i in {1..6}; do
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
    --destination-port-ranges '*' > /dev/null

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
    --destination-port-ranges 3389 22 5985 5986 > /dev/null
}

wait_for_vm_to_be_running() {
    local resource_group="$1"
    local vm_name="$2"

    while true; do
        vm_state=$(az vm get-instance-view --resource-group "$resource_group" --name "$vm_name" --query "instanceView.statuses[?code=='PowerState/running'].code" -o tsv)
        if [[ "$vm_state" == "PowerState/running" ]]; then
            display_message "VM is running. Waiting for services to initialize..." "yellow"
            sleep 30
            break
        else
            display_message "Waiting for VM to be running..." "yellow"
            sleep 10
        fi
    done
}

generate_random_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 15 && echo -n "+"
}

main() {
    local allowed_ip=""
    while getopts "r:" opt; do
        case $opt in
            r) allowed_ip="$OPTARG" ;;
            *) display_message "Use -r to specify allowed IP range." "red"; exit 1 ;;
        esac
    done

    if [ -z "$allowed_ip" ]; then
        display_message "Allowed IP must be provided with -r" "red"
        exit 1
    fi

    check_azure_authentication
    delete_old_resource_groups
    sleep 3

    RANDOMNUM=$(echo $RANDOM$RANDOM | head -c 4)
    RESOURCE_GROUP="WinServAttack$RANDOMNUM"
    LOCATION="germanywestcentral"
    VM_NAME=$(generate_random_hostname)
    ADMIN_USER="joiner"
    ADMIN_PASSWORD=$(generate_random_password)
    IMAGE="MicrosoftWindowsServer:WindowsServer:2025-datacenter-azure-edition:latest"
    NSG_NAME="${VM_NAME}-nsg"

    display_message "Creating Resource Group..." "blue"
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

    display_message "Creating NSG and configuring rules..." "blue"
    az network nsg create --resource-group "$RESOURCE_GROUP" --name "$NSG_NAME"
    configure_nsg_rules "$NSG_NAME" "$RESOURCE_GROUP" "$allowed_ip"

    display_message "Creating Windows Server 2025 Pentest VM..." "blue"
    az vm create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --image "$IMAGE" \
    --admin-username "$ADMIN_USER" \
    --admin-password "$ADMIN_PASSWORD" \
    --license-type Windows_Server --accept-term \
    --public-ip-sku Standard --size Standard_F4s_v2 \
    --nsg "$NSG_NAME" \
    --computer-name "$VM_NAME"

    wait_for_vm_to_be_running "$RESOURCE_GROUP" "$VM_NAME"

    display_message "Waiting 60 seconds for VM services to stabilize..." "yellow"
    sleep 60

    display_message "Deploying pentest setup script (2.ps1) using CustomScriptExtension..." "blue"
    az vm extension set \
    --resource-group "$RESOURCE_GROUP" \
    --vm-name "$VM_NAME" \
    --name CustomScriptExtension \
    --publisher Microsoft.Compute \
    --settings '{"fileUris": ["https://raw.githubusercontent.com/crtvrffnrt/joiner/refs/heads/main/2.ps1"], "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File 2.ps1"}'

    display_message "Waiting 120 seconds for script execution and potential auto-reboot..." "yellow"
    sleep 120

    display_message "Restarting the VM after setup script execution..." "blue"
    az vm restart --resource-group "$RESOURCE_GROUP" --name "$VM_NAME"

    display_message "Waiting for VM to become available after reboot..." "blue"
    az vm wait --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --custom "instanceView.statuses[?code=='PowerState/running']" --timeout 300

    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" -d --query "publicIps" -o tsv)

    display_message "Connection Details:" "green"
    echo
    echo "Connect to your VM using the following details:"
    echo "Public IP: $IP"
    echo "Username: $ADMIN_USER"
    echo "Allowed IP range: $allowed_ip"
    echo "Ports open: RDP (3389), SSH (22), WinRM (5985/5986)"
    echo
    echo "Copyable connection commands:"
    echo "cmdkey /generic:\"$IP\" /user:\"$ADMIN_USER\" /pass:\"$ADMIN_PASSWORD\"; mstsc /v:$IP"
    echo "xfreerdp /v:$IP /u:$ADMIN_USER /p:\"$ADMIN_PASSWORD\" /cert:ignore /dynamic-resolution /clipboard /drive:joiner,./ /admin"
    echo "sshpass -p \"$ADMIN_PASSWORD\" ssh -o StrictHostKeyChecking=no \"$ADMIN_USER@$IP\""
    echo "evil-winrm -i $IP -u $ADMIN_USER -p \"$ADMIN_PASSWORD\" -P 5985"
    echo

    read -p "Connect via (ssh/rdp/evilwinrm)? " connection_choice
    if [[ "$connection_choice" == "ssh" ]]; then
        display_message "Connecting via SSH..." "blue"
        sshpass -p "$ADMIN_PASSWORD" ssh -o StrictHostKeyChecking=no "$ADMIN_USER@$IP"
    elif [[ "$connection_choice" == "rdp" ]]; then
        display_message "Connecting via RDP (xfreerdp3)..." "blue"
        /usr/bin/xfreerdp3 /v:"$IP" /u:"$ADMIN_USER" /p:"$ADMIN_PASSWORD" /cert:ignore /dynamic-resolution /clipboard /drive:joiner,./ /admin
    elif [[ "$connection_choice" == "evilwinrm" ]]; then
        display_message "Connecting via Evil-WinRM..." "blue"
        evil-winrm -i "$IP" -u "$ADMIN_USER" -p "$ADMIN_PASSWORD"
    else
        display_message "Invalid choice. Exiting." "red"
        exit 1
    fi
}


main "$@"

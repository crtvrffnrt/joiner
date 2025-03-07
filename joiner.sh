#!/bin/bash

# Function to display messages with colors
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

# Function to check Azure authentication
check_azure_authentication() {
    az account show &> /dev/null
    if [ $? -ne 0 ]; then
        display_message "Please authenticate to your Azure account using 'az login --use-device-code'." "red"
        exit 1
    fi
}

# Function to delete old resource groups created by this script
delete_old_resource_groups() {
    az group list --query "[?starts_with(name, 'Win2025ServerRG')].name" -o tsv | while read -r group; do
        az group delete --name "$group" --yes --no-wait &> /dev/null
        if [ $? -eq 0 ]; then
            display_message "Successfully deleted resource group $group." "green"
        else
            display_message "Failed to delete resource group $group." "red"
        fi
    done
}

# Function to configure NSG rules
configure_nsg_rules() {
    local nsg_name="$1"
    local resource_group="$2"
    local allowed_ip="$3"

    # Deny all inbound traffic by default
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

    # Allow specific IP for RDP, SSH, WinRM
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

# Function to wait until VM is running
wait_for_vm_to_be_running() {
    local resource_group="$1"
    local vm_name="$2"

    while true; do
        vm_state=$(az vm get-instance-view --resource-group "$resource_group" --name "$vm_name" --query "instanceView.statuses[?code=='PowerState/running'].code" -o tsv)
        if [[ "$vm_state" == "PowerState/running" ]]; then
            display_message "VM is running. Waiting for 30 seconds to ensure services are ready..." "yellow"
            sleep 30
            break
        else
            display_message "Waiting for VM to be in 'running' state..." "yellow"
            sleep 10
        fi
    done
}

# Function to generate a random 12-character password
generate_random_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
}

# Main script execution
main() {
    local allowed_ip=""
    local username=""
    local domain=""
    local password=""

    # Parse arguments
    while getopts "r:u:d:p:" opt; do
        case $opt in
            r) allowed_ip="$OPTARG" ;;
            u) username="$OPTARG" ;;
            d) domain="$OPTARG" ;;
            p) password="$OPTARG" ;;
            *)
                display_message "Invalid option provided. Use -r to specify the allowed IP range, -u for username, -d for domain, and -p for password." "red"
                exit 1
                ;;
        esac
    done

    # Validate allowed IP range
    if [ -z "$allowed_ip" ]; then
        display_message "Allowed IP range must be provided using the -r flag." "red"
        exit 1
    fi

    # Validate username, domain, and password
    if [ -z "$username" ] || [ -z "$domain" ] || [ -z "$password" ]; then
        display_message "Username, domain, and password must be provided using the -u, -d, and -p flags." "red"
        exit 1
    fi

    # Check Azure authentication
    check_azure_authentication

    # Delete old resource groups
    delete_old_resource_groups
    sleep 5
    # Variables

    RESOURCE_GROUP="Win2025ServerRG09$RANDOM"
    LOCATION="germanywestcentral"
    VM_NAME="WindowsServer"
    ADMIN_USER="$username"
    ADMIN_PASSWORD=$(generate_random_password)
    IMAGE="MicrosoftWindowsServer:WindowsServer:2025-datacenter-azure-edition:latest"
    NSG_NAME="${VM_NAME}-nsg"

    # Create Resource Group
    display_message "Creating Resource Group..." "blue"
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
    sleep 5
    # Create NSG
    display_message "Creating Network Security Group..." "blue"
    az network nsg create --resource-group "$RESOURCE_GROUP" --name "$NSG_NAME"

    # Configure NSG rules
    configure_nsg_rules "$NSG_NAME" "$RESOURCE_GROUP" "$allowed_ip"
    sleep 15
    # Create VM with password authentication
    display_message "Creating Windows Server 2025 VM with password authentication..." "blue"
    az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --image "$IMAGE" \
        --admin-username "$ADMIN_USER" \
        --admin-password "$ADMIN_PASSWORD" \
        --public-ip-sku Standard \
        --nsg "$NSG_NAME" 

    # Wait for VM to be ready
    sleep 5
    display_message "Waiting for VM provisioning..." "blue"
    
    az vm wait --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --created

    # Get Public IP
    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" -d --query "publicIps" -o tsv)
    display_message "VM IP: $IP" "green"
    sleep 5
    # Configure Azure VM for SSH and Entra ID Join
    SETUP_SCRIPT="setup_win2025.ps1"
    cat << EOF > $SETUP_SCRIPT
Set-MpPreference -DisableRealtimeMonitoring $true
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

Install-Module AADInternals -Force -Scope AllUsers
Install-Module -Name "AADInternals-Endpoints" -Force -Scope AllUsers
sleep 10
Import-Module AADInternals
Import-Module -Name "AADInternals-Endpoints"
echo $(date) >> 1.txt

$secpasswd = ConvertTo-SecureString "$password" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("$username@$domain", $secpasswd)

Install-Module Microsoft.Graph -Force -Scope AllUsers
sleep 5
Import-Module Microsoft.Graph
sleep 10
Get-AADIntAccessTokenForAADJoin -SaveToCache -Credentials $credential
sleep 5

Join-AADIntDeviceToAzureAD -DeviceName "$RESOURCE_GROUP" -DeviceType "WindowsServer" -OSVersion "2025" -JoinType Registersleep 5

# Also join the device using native command
Add-Computer -DomainName 'AzureAD' -Credential $credential -Force -Restart

EOF
    sleep 5
    # Upload setup script and execute
    display_message "Uploading setup script..." "blue"
    az vm run-command invoke \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --command-id RunPowerShellScript \
        --scripts @${SETUP_SCRIPT}

    # Clean up setup script
 

    # Wait for reboot to complete
    display_message "Waiting some time for reboot to complete..." "blue"
    sleep 123

    # Automatically SSH into the VM
    display_message "Establishing SSH session to $VM_NAME..." "blue"

    sleep 5
    # Display RDP connection details
    display_message "Your Windows VM has been created successfully!" "green"
    echo "Connect to your VM using the following details:"
    echo "Public IP: $IP"
    echo "Username: $ADMIN_USER"
    echo "Allowed IP range: $allowed_ip"
    echo "Ports open: RDP (3389), SSH (22), WinRM (5985/5986)"

    # Generate PowerShell and Linux commands for connection
    echo
    echo "To connect from Windows (PowerShell):"
    echo "cmdkey /generic:\"$IP\" /user:\"$ADMIN_USER\" /pass:\"$ADMIN_PASSWORD\"; mstsc /v:$IP"
    echo
    echo "To connect from Linux (xfreerdp):"
    echo "xfreerdp /v:$IP /u:$ADMIN_USER /p:\"$ADMIN_PASSWORD\" /cert:ignore"
    echo
    display_message "Successfully deployed Windows Server 2025 VM. You can connect via RDP or SSH." "green"
    echo
    echo "try to ssh in:"
    sshpass -p "$ADMIN_PASSWORD" ssh "$ADMIN_USER@$IP"
}

main "$@"


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

check_azure_authentication() {
    az account show &> /dev/null
    if [ $? -ne 0 ]; then
        display_message "Please authenticate to your Azure account using 'az login --use-device-code'." "red"
        exit 1
    fi
}

delete_old_resource_groups() {
    az group list --query "[?starts_with(name, 'thiefjoinerRGDeleteme')].name" -o tsv | while read -r group; do
        az group delete --name "$group" --yes --no-wait &> /dev/null
        if [ $? -eq 0 ]; then
            display_message "Successfully deleted resource group $group." "green"
        else
            display_message "Failed to delete resource group $group." "red"
        fi
    done
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
            display_message "VM is running. Waiting for 30 seconds to ensure services are ready..." "yellow"
            sleep 30
            break
        else
            display_message "Waiting for VM to be in 'running' state..." "yellow"
            sleep 10
        fi
    done
}

generate_random_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 15 && echo -n "+"
}

main() {
    local allowed_ip=""
    local username=""
    local domain=""
    local password=""
    
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
    
    if [ -z "$allowed_ip" ]; then
        display_message "Allowed IP range must be provided using the -r flag." "red"
        exit 1
    fi
    
    if [ -z "$username" ] || [ -z "$domain" ] || [ -z "$password" ]; then
        display_message "Username, domain, and password must be provided using the -u, -d, and -p flags." "red"
        exit 1
    fi
    
    check_azure_authentication
    delete_old_resource_groups
    sleep 3
    RANDOMNUM=$RANDOM
    RESOURCE_GROUP="thiefjoinerRGDeleteme$RANDOMNUM"
    LOCATION="germanywestcentral"
    VM_NAME="WindowsJoiner$RANDOMNUM"
    ADMIN_USER="joiner"
    ADMIN_PASSWORD=$(generate_random_password)
    ##IMAGE="MicrosoftWindowsServer:WindowsServer:2025-datacenter-azure-edition:latest"
    IMAGE="MicrosoftWindowsDesktop:Windows-10:win10-22h2-pro:latest"
    NSG_NAME="${VM_NAME}-nsg"
    
    display_message "Creating Resource Group..." "blue"
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
    sleep 5
    
    display_message "Creating Network Security Group..." "blue"
    az network nsg create --resource-group "$RESOURCE_GROUP" --name "$NSG_NAME"
    
    configure_nsg_rules "$NSG_NAME" "$RESOURCE_GROUP" "$allowed_ip"
    sleep 15
    
    display_message "Creating Windows Server VM with password authentication..." "blue"
    az vm create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --image "$IMAGE" \
    --admin-username "$ADMIN_USER" \
    --admin-password "$ADMIN_PASSWORD" \
    --public-ip-sku Standard \
    --nsg "$NSG_NAME"
    
    sleep 5
    display_message "Waiting for VM provisioning..." "blue"
    az vm wait --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --created
    display_message "Waiting for VM Agent to reach Ready state..." "blue"
    
    while true; do
        VM_STATUS=$(az vm get-instance-view \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VM_NAME" \
            --query "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded'].displayStatus" \
        --output tsv)
        
        if [[ "$VM_STATUS" == "Ready" ]]; then
            display_message "VM Agent is in Ready state." "green"
            break
        else
            display_message "VM Agent not ready yet. Checking again in 30 seconds..." "yellow"
            sleep 30
        fi
    done
    sleep 5
    IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" -d --query "publicIps" -o tsv)
    display_message "VM IP: $IP" "green"
    display_message "sshpass -p \"$ADMIN_PASSWORD\" ssh -o StrictHostKeyChecking=no \"$ADMIN_USER@$IP\"" "green"
    sleep 5
    # Execute the merged setup script remotely by downloading and invoking it
    display_message "Uploading and executing merged setup script..." "blue"
    az vm run-command invoke \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --command-id RunPowerShellScript \
    --scripts '
        param(
            [string]$username,
            [string]$domain,
            [string]$password,
            [string]$RESOURCE_GROUP
        )
        try {
            $url = "https://raw.githubusercontent.com/crtvrffnrt/joiner/refs/heads/main/2.ps1"
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing
            if ($response.StatusCode -ne 200) {
                Write-Host "Failed to download script. HTTP Status: $($response.StatusCode)"
                exit 1
            }
            $scriptContent = $response.Content
            if (-not $scriptContent) {
                Write-Host "Downloaded script content is empty."
                exit 1
            }
            & ([scriptblock]::Create($scriptContent)) -username $username -domain $domain -password $password -RESOURCE_GROUP $RESOURCE_GROUP
        } catch {
            Write-Host "Error executing script: $_"
            exit 1
        }
    ' \
    --parameters "username=$username" "domain=$domain" "password=$password" "RESOURCE_GROUP=$RESOURCE_GROUP"
    sleep 15
    display_message "Waiting some time for reboot to complete..." "blue"
    az vm wait --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --updated
    sleep 10
    display_message "Establishing SSH session to $VM_NAME..." "blue"
    sleep 5
    display_message "Your Windows VM has been created successfully! and is currently restarting" "green"
    echo "Connect to your VM using the following details:"
    echo "Public IP: $IP"
    echo "Username: $ADMIN_USER"
    echo "Allowed IP range: $allowed_ip"
    echo "Ports open: RDP (3389), SSH (22), WinRM (5985/5986)"
    echo
    echo "cmdkey /generic:\"$IP\" /user:\"$ADMIN_USER\" /pass:\"$ADMIN_PASSWORD\"; mstsc /v:$IP"
    echo "xfreerdp /v:$IP /u:$ADMIN_USER /p:\"$ADMIN_PASSWORD\" /cert:ignore"
    echo "sshpass -p \"$ADMIN_PASSWORD\" ssh -o StrictHostKeyChecking=no \"$ADMIN_USER@$IP\""
    sleep 120
    az vm run-command invoke \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --command-id RunPowerShellScript \
    --scripts "Get-Content -Path 'C:\to.json' -Raw" > ./to.json
    display_message "SSH Into"
    read -p "Do you want to connect via SSH or xfreerdp? (ssh/rdp): " connection_choice
    if [[ "$connection_choice" == "ssh" ]]; then
        display_message "Connecting via SSH..." "blue"
        sshpass -p "$ADMIN_PASSWORD" ssh -o StrictHostKeyChecking=no "$ADMIN_USER@$IP"
        elif [[ "$connection_choice" == "rdp" ]]; then
        display_message "Connecting via xfreerdp..." "blue"
        xfreerdp /v:"$IP" /u:"$ADMIN_USER" /p:"$ADMIN_PASSWORD" /cert:ignore
    else
        display_message "Invalid choice. Exiting." "red"
        exit 1
    fi
}
main "$@"

param(
    [string]$username,
    [string]$domain,
    [string]$password,
    [string]$RESOURCE_GROUP
)

# Create directory if it doesn't exist
$dirPath = "C:\$RESOURCE_GROUP-1scriptwasexecuted"
mkdir $dirPath -ErrorAction SilentlyContinue

# Define the output file path inside the newly created directory
$outputFile = "$dirPath\params.txt"

# Create content for the file
$content = @"
Username: $username
Domain: $domain
Password: $password
Resource Group: $RESOURCE_GROUP
"@

# Write content to the file
$content | Out-File -FilePath $outputFile -Encoding UTF8
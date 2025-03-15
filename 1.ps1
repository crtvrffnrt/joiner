param(
    [string]$username,
    [string]$domain,
    [string]$password,
    [string]$RESOURCE_GROUP
)
mkdir "C:\$RESOURCE_GROUP-one" -ErrorAction SilentlyContinue

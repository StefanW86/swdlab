#Install Module
#Install-Module -Name Posh-ACME -Scope CurrentUser

Import-Module Posh-ACME

#Connect-AzAccount -Tenant '' -Subscription ''

### Connect with managed identity
<#
# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process | Out-Null

# Connect using a Managed Service Identity
try {
	$AzureContext = (Connect-AzAccount -Identity).context
}
catch{
    Write-log -Logfiles $Logfiles -Severity ERROR -STDout -Message "There is no system-assigned user identity. Aborting."; 
    Write-log -Logfiles $Logfiles -Severity ERROR -STDout -Message "$_"
	exit 1
}

# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext -ErrorAction Stop
#>

$folder = '.'
$kvName = 'keyvault'
$storageAccount = "storageaccount"
$containerName  = "acme"
$contactEmail = "admin@swdlab.de"
$threshold = (Get-Date).AddDays(5)

#Lets Encrypt Stage Server for testing
#Set-PAServer LE_STAGE

#Lets Encrypt Production Server
Set-PAServer LE_PROD
New-PAAccount -AcceptTOS -Contact $contactEmail -Force

function OrderCertificate {
    param (
        [string]$domain,
        [string]$folder,
        [string]$storageAccount,
        [string]$containerName,
        [string]$kvName,
        [string]$certName
    )
    $pArgs = @{
    WRPath = $folder
    }
    New-PAOrder $domain -Plugin WebRoot -PluginArgs $pArgs

    $splat = @{
        Account = (Get-PAAccount)
        Plugin = 'WebRoot'
        PluginArgs = @{WRPath = $folder}
    }
    Get-PAOrder | Get-PAAuthorization | ForEach-Object {
        Publish-Challenge -Domain $_.DNSId -Token $_.HTTP01Token @splat
    }

    $validationFile = Get-ChildItem -path "${folder}\.well-known\acme-challenge"

    ##Upload to Storage Account

    $localFile      = $validationFile.FullName
    $blobName       = ".well-known/acme-challenge/$($validationFile.Name)"

    # Kontext über OAuth/Connected Account
    $ctx = New-AzStorageContext -StorageAccountName $storageAccount -UseConnectedAccount
    # Upload inkl. Content-Type/Metadaten
    Set-AzStorageBlobContent -File $localFile -Container $containerName -Blob $blobName -Context $ctx

    # Request Certificate
    $paCert = New-PACertificate -Domain $domain -AcceptTOS

    ## ToDo Remove
    #$blobItem = Get-AzStorageBlob -Container $containerName -Context $ctx | Where-Object { $_.Name -like "*${$validationFile.Name}*" }
    # Delete Validation File from Storage Account
    #Remove-AzStorageBlob -Container $containerName -Blob $blobItem -Context $ctx -DeleteSnapshot -Force

    #Datei im Keyvault importieren

    $securePfx = ConvertTo-SecureString -String 'poshacme' -AsPlainText -Force
    Import-AzKeyVaultCertificate -VaultName $kvName -Name $certName -FilePath $paCert.PfxFile -Password $securePfx

}

$keyvaultCertificates = Get-AzKeyVaultCertificate -VaultName $kvName

foreach($keyvaultCertificate in $keyvaultCertificates){
    $cert = Get-AzKeyVaultCertificate -VaultName $kvName -Name $keyvaultCertificate.Name
    $domain = $cert.Certificate.Subject -replace 'CN=',''
    if($cert.Expires -lt $threshold) {
        Write-Output "Certificate expires $($cert.Name)"
        try {
        OrderCertificate -domain $domain -folder $folder -storageAccount $storageAccount -containerName $containerName -kvName $kvName -certName $cert.Name
        Write-Output "Zertifikat für $($domain) erfolgreich bestellt und im Key Vault $($kvName) als $($cert.Name) importiert."
        }
        catch {
            Write-Error "Fehler beim Bestellen des Zertifikats für $($domain): $_"
        }
    } else {
        Write-Output "Zertifikat $($cert.Name) ist noch gültig bis $($cert.Expires)"
    }
    
    if($cert.Certificate.Subject -eq $cert.Certificate.Issuer) {
        Write-Output "Dies ist ein selbstsigniertes Zertifikat: $($keyvaultCertificate.Name)"
        
        try {
            OrderCertificate -domain $domain -folder $folder -storageAccount $storageAccount -containerName $containerName -kvName $kvName -certName $cert.Name
            Write-Output "Zertifikat für $($domain) erfolgreich bestellt und im Key Vault $($kvName) als $($cert.Name) importiert."
        }
        catch {
            Write-Error "Fehler beim Bestellen des Zertifikats für $($domain): $_"
        }
    }
}




#$appgw = Get-AzApplicationGateway -Name appgw-prod-gwc-vx-selfservice-001 -ResourceGroupName rg-prod-gwc-hub-network-001
# Specify the resource id to the user assigned managed identity - This can be found by going to the properties of the managed identity
#Set-AzApplicationGatewayIdentity -ApplicationGateway $appgw -UserAssignedIdentityId "/subscriptions/acab852a-ad67-403e-8939-1842cc5ad3e3/resourcegroups/rg-prod-gwc-hub-shared/providers/Microsoft.ManagedIdentity/userAssignedIdentities/svc-hub-appgw"



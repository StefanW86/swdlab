<#
.SYNOPSIS
    Enable/Disable the TLS/DTLS listeners on the VDA

.DESCRIPTION
    Enable or disable the TLS/DTLS listeners on the VDA. 
    Optionally, the TLS/DTLS certificate, port, version and cipher suite to use can be specified.

.PARAMETER Disable
    Disables the TLS/DTLS listeners.
.PARAMETER Enable
    Enables the TLS/DTLS listeners.
.PARAMETER SSLPort
    Specifies the port to use. Default is port 443.
.PARAMETER SSLMinVersion
    Specifies the minimum TLS/DTLS version to use (allowed values are SSL_3.0, TLS_1.0, TLS_1.1, TLS_1.2 and TLS_1.3).
    Default is TLS_1.0. 
.PARAMETER SSLCipherSuite
    Specifies the cipher suite to use (allowed values are GOV, COM and ALL). Default is ALL.
.PARAMETER CertificateThumbPrint
    Specifies the certificate thumbprint to identify the certificate to use. Default is the certificate that
    matches the FQDN of the VDA.

.EXAMPLE
    To disable the TLS/DTLS listeners
    Enable-VdaSSL -Disable
.EXAMPLE
    To enable the TLS/DTLS listeners
    Enable-VdaSSL -Enable
.EXAMPLE
    To enable the TLS/DTLS listeners on port 4000
    Enable-VdaSSL -Enable -SSLPort 4000
.EXAMPLE
    To enable the TLS/DTLS listeners using TLS 1.2 with the GOV cipher suite
    Enable-VdaSSL -Enable -SSLMinVersion "TLS_1.2" -SSLCipherSuite "GOV"
.EXAMPLE
    To enable the TLS/DTLS listeners using the specified computer certificate
    Enable-VdaSSL -Enable -CertificateThumbprint "373641446CCA0343D1D5C77EB263492180B3E0FD"
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
Param(
    [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$False, ParameterSetName = "DisableMode")]
    [switch] $Disable,

    [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [switch] $Enable,
    
    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [int] $SSLPort = 443,

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [ValidateSet("SSL_3.0", "TLS_1.0", "TLS_1.1", "TLS_1.2", "TLS_1.3")]
    [String] $SSLMinVersion = "TLS_1.0",

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [ValidateSet("GOV", "COM", "ALL")]
    [String] $SSLCipherSuite = "ALL",

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, ParameterSetName = "EnableMode")]
    [string]$CertificateThumbPrint 
    )

    Set-StrictMode -Version 2.0
    $erroractionpreference = "Stop"

    #Check if the user is an administrator
    if(!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Host "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator."
        break
    }

    #Write Header
    Write-Host "Enable TLS/DTLS to the VDA"
    Write-Host "Running command Enable-VdaSSL to enable or disable TLS/DTLS to the VDA."
    Write-Host "This includes:"
    Write-Host "`ta.Disable TLS/DTLS to VDA or"
    Write-Host "`tb.Enable TLS/DTLS to VDA"
    Write-Host "`t`t1.Setting ACLs"
    Write-Host "`t`t2.Setting registry keys"
    Write-Host "`t`t3.Configuring Firewall"
    Write-Host ""
    Write-Host ""

    # Registry path constants 
    $ICA_LISTENER_PATH = 'HKLM:\system\CurrentControlSet\Control\Terminal Server\Wds\icawd'
    $ICA_CIPHER_SUITE = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'
    $DHEnabled = 'Enabled'
    $BACK_DHEnabled = 'Back_Enabled'
    $ENABLE_SSL_KEY = 'SSLEnabled'
    $SSL_CERT_HASH_KEY = 'SSLThumbprint'
    $SSL_PORT_KEY = 'SSLPort'
    $SSL_MINVERSION_KEY = 'SSLMinVersion'
    $SSL_CIPHERSUITE_KEY = 'SSLCipherSuite'

    $POLICIES_PATH = 'HKLM:\SOFTWARE\Policies\Citrix\ICAPolicies'
    $ICA_LISTENER_PORT_KEY = 'IcaListenerPortNumber'
    $SESSION_RELIABILITY_PORT_KEY = 'SessionReliabilityPort'
    $WEBSOCKET_PORT_KEY = 'WebSocketPort'

    #Read ICA, CGP and HTML5 ports from the registry
    try
    {
        $IcaPort = (Get-ItemProperty -Path $POLICIES_PATH -Name $ICA_LISTENER_PORT_KEY).IcaListenerPortNumber
    }
    catch
    {
        $IcaPort = 1494
    }

    try
    {
        $CgpPort = (Get-ItemProperty -Path $POLICIES_PATH -Name $SESSION_RELIABILITY_PORT_KEY).SessionReliabilityPort
    }
    catch
    {
        $CgpPort = 2598
    }

    try
    {
        $Html5Port = (Get-ItemProperty -Path $POLICIES_PATH -Name $WEBSOCKET_PORT_KEY).WebSocketPort
    }
    catch
    {
        $Html5Port = 8008
    }

    if (!$IcaPort)
    {
        $IcaPort = 1494
    }
    if (!$CgpPort)
    {
        $CgpPort = 2598
    }
    if (!$Html5Port)
    {
        $Html5Port = 8008
    }

    # Determine the name of the ICA Session Manager
    if (Get-Service | Where-Object {$_.Name -eq 'porticaservice'}) 
    {
        $username = 'NT SERVICE\PorticaService'
        $serviceName = 'PortIcaService'
    }
    else
    {
        $username = 'NT SERVICE\TermService'
        $serviceName = 'TermService'
    }

    switch ($PSCmdlet.ParameterSetName)
    {
        "DisableMode"
        {
            #Replace Diffie-Hellman Enabled value to its original value
            if (Test-Path $ICA_CIPHER_SUITE)
            {
                $back_enabled_exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -ErrorAction SilentlyContinue
                if ($back_enabled_exists -ne $null)
                {
                    Set-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value $back_enabled_exists.Back_Enabled
                    Remove-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled
                }
            }

            if ($PSCmdlet.ShouldProcess("This will delete any existing firewall rules for Citrix SSL Service and enable rules for ICA, CGP and Websocket services.", "Are you sure you want to perform this action?`nThis will delete any existing firewall rules for Citrix SSL Service and enable rules for ICA, CGP and Websocket services.", "Configure Firewall"))
            {
                #Enable any existing rules for ICA, CGP and HTML5 ports
                netsh advfirewall firewall add rule name="Citrix ICA Service"        dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$IcaPort | Out-Null
                netsh advfirewall firewall add rule name="Citrix CGP Server Service" dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$CgpPort | Out-Null
                netsh advfirewall firewall add rule name="Citrix Websocket Service"  dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$Html5Port | Out-Null

                #Enable existing rules for UDP-ICA, UDP-CGP 
                netsh advfirewall firewall add rule name="Citrix ICA UDP" dir=in action=allow service=$serviceName profile=any protocol=udp localport=$IcaPort | Out-Null
                netsh advfirewall firewall add rule name="Citrix CGP UDP" dir=in action=allow service=$serviceName profile=any protocol=udp localport=$CgpPort | Out-Null

                #Delete any existing rules for Citrix SSL Service
                netsh advfirewall firewall delete rule name="Citrix SSL Service" | Out-Null

                #Delete any existing rules for Citrix DTLS Service
                netsh advfirewall firewall delete rule name="Citrix DTLS Service" | Out-Null
            }
            else
            {
                Write-Host "Firewall configuration skipped."
            }

            #Turning off SSL by setting SSLEnabled key to 0
            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $ENABLE_SSL_KEY -Value 0 -Type DWord -Confirm:$false

            Write-Host "SSL to VDA has been disabled."
        }

        "EnableMode"
        {
            $RegistryKeysSet = $ACLsSet = $FirewallConfigured = $False

            $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
            $Store.Open("ReadOnly")
        
            if ($Store.Certificates.Count -eq 0)
            {
                Write-Host "No certificates found in the Personal Local Machine Certificate Store. Please install a certificate and try again."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }
            elseif ($Store.Certificates.Count -eq 1)
            {
                if ($CertificateThumbPrint)
                {
                    $Certificate = $Store.Certificates[0]
                    $Thumbprint = $Certificate.GetCertHashString()
                    if ($Thumbprint -ne $CertificateThumbPrint)
                    {
                        Write-Host "No certificate found in the certificate store with thumbprint $CertificateThumbPrint"
                        Write-Host "`nEnabling SSL to VDA failed."
                        $Store.Close()
                        break
                    }
                }
                else
                {
                    $Certificate = $Store.Certificates[0]
                }
            }
            elseif ($CertificateThumbPrint)
            {
                $Certificate = $Store.Certificates | where {$_.GetCertHashString() -eq $CertificateThumbPrint}
                if (!$Certificate)
                {
                    Write-Host "No certificate found in the certificate store with thumbprint $CertificateThumbPrint"
                    Write-Host "`nEnabling SSL to VDA failed."
                    $Store.Close()
                    break
                }
            }
            else
            {
                $ComputerName = "CN="+[System.Net.Dns]::GetHostByName((hostname)).HostName+","
                $Certificate = $Store.Certificates | where {$_.Subject -match $ComputerName}
                if (!$Certificate)
                {
                    Write-Host "No certificate found in the certificate store with Subject $ComputerName, please specify the thumbprint using -CertificateThumbPrint option."
                    Write-Host "`nEnabling SSL to VDA failed."
                    $Store.Close()
                    break
                }
            }
                
            #Validate the certificate

            #Validate expiration date
            $ValidTo = [DateTime]::Parse($Certificate.GetExpirationDateString())
            if($ValidTo -lt [DateTime]::UtcNow)
            {
                Write-Host "The certificate is expired. Please install a valid certificate and try again."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            #Check certificate trust
            if(!$Certificate.Verify())
            {
                Write-Host "Verification of the certificate failed. Please install a valid certificate and try again."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            #Check private key availability
            try
            {
                $PrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
				# both legacy CSP and new KSP certificate PrivateKey object obtained as above is of type RSACng
				# the Key.UniqueName returned for CSP certificate is actually the CspKeyContainerInfo.UniqueKeyContainerName
				$UniqueName = $PrivateKey.Key.UniqueName 
				Write-Host "`nRSA CNG unique key name : $UniqueName"
            }
            catch
            {
                Write-Host "Unable to access the Private Key of the Certificate or one of its fields."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            if(!$PrivateKey -or !$UniqueName)
            {
                Write-Host "Unable to access the Private Key of the Certificate or one of its fields."
                Write-Host "`nEnabling SSL to VDA failed."
                $Store.Close()
                break
            }

            if ($PSCmdlet.ShouldProcess("This will grant $serviceName read access to the certificate.", "Are you sure you want to perform this action?`nThis will grant $serviceName read access to the certificate.", "Configure ACLs"))
            {
				[System.Security.Cryptography.AsymmetricAlgorithm] $PrivateKey = $Certificate.PrivateKey
				if ($PrivateKey) # Legacy CSP Certificate
				{
					$unique_name = $PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
					$dir= $env:ProgramData + '\Microsoft\Crypto\RSA\MachineKeys\'
				}
				else # KSP Certificate
				{
					$PrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
					$unique_name = $PrivateKey.Key.UniqueName
					$dir= $env:ProgramData + '\Microsoft\Crypto\Keys\'
				}

				$keypath = $dir+$unique_name
				Write-Host "`nkeypath: $keypath"
				icacls $keypath /grant `"$username`"`:RX | Out-Null

                Write-Host "ACLs set."
                Write-Host ""
                $ACLsSet = $True
            }
            else
            {
                Write-Host "ACL configuration skipped."
            }

            if($PSCmdlet.ShouldProcess("This will delete any existing firewall rules for port $SSLPort and disable rules for ICA, CGP and Websocket services.", "Are you sure you want to perform this action?`nThis will delete any existing firewall rules for port $SSLPort and disable rules for ICA, CGP and Websocket services.", "Configure Firewall"))
            {
                #Delete any existing rules for the SSLPort
                netsh advfirewall firewall delete rule name=all protocol=tcp localport=$SSLPort | Out-Null

                #Delete any existing rules for the DTLSPort
                netsh advfirewall firewall delete rule name=all protocol=udp localport=$SSLPort | Out-Null
                        
                #Delete any existing rules for Citrix SSL Service
                netsh advfirewall firewall delete rule name="Citrix SSL Service" | Out-Null

                #Delete any existing rules for Citrix DTLS Service
                netsh advfirewall firewall delete rule name="Citrix DTLS Service" | Out-Null
                        
                #Creating firewall rule for Citrix SSL Service
                netsh advfirewall firewall add rule name="Citrix SSL Service"  dir=in action=allow service=$serviceName profile=any protocol=tcp localport=$SSLPort | Out-Null

                #Creating firewall rule for Citrix DTLS Service
                netsh advfirewall firewall add rule name="Citrix DTLS Service" dir=in action=allow service=$serviceName profile=any protocol=udp localport=$SSLPort | Out-Null

                #Disable any existing rules for ICA, CGP and HTML5 ports
                netsh advfirewall firewall set rule name="Citrix ICA Service"        protocol=tcp localport=$IcaPort new enable=no | Out-Null
                netsh advfirewall firewall set rule name="Citrix CGP Server Service" protocol=tcp localport=$CgpPort new enable=no | Out-Null
                netsh advfirewall firewall set rule name="Citrix Websocket Service"  protocol=tcp localport=$Html5Port new enable=no | Out-Null

                #Disable existing rules for UDP-ICA, UDP-CGP
                netsh advfirewall firewall set rule name="Citrix ICA UDP" protocol=udp localport=$IcaPort new enable=no | Out-Null          
                netsh advfirewall firewall set rule name="Citrix CGP UDP" protocol=udp localport=$CgpPort new enable=no | Out-Null

                Write-Host "Firewall configured."
                $FirewallConfigured = $True
            }
            else
            {
                Write-Host "Firewall configuration skipped."
            }

            # Create registry keys to enable SSL to the VDA
            Write-Host "Setting registry keys..."
            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CERT_HASH_KEY -Value $Certificate.GetCertHash() -Type Binary -Confirm:$False 
            switch($SSLMinVersion)
            {
                "SSL_3.0"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 1 -Type DWord -Confirm:$False
                }
                "TLS_1.0"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 2 -Type DWord -Confirm:$False
                }
                "TLS_1.1"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 3 -Type DWord -Confirm:$False
                }
                "TLS_1.2"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 4 -Type DWord -Confirm:$False
                }
		        "TLS_1.3"
		        {
		            #check if this OS support TLS 1.3 or not
                    
                    $osVersion = (Get-WMIObject win32_operatingsystem) | Select Version | Out-String
                    $osVersion = $osVersion.trim()
                    $buildNum = [int]$osVersion.Split(".")[2]
                    if ($buildNum -lt 20348)
                    {
	                    Write-Host "Enabling SSL to VDA failed. TLS 1.3 is only supported in Windows 2k22 / Windows 11 and above."
                        $Store.Close()
                        Exit
                    }

                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_MINVERSION_KEY -Value 5 -Type DWord -Confirm:$False
		        }
            }

            switch($SSLCipherSuite)
            {
                "GOV"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 1 -Type DWord -Confirm:$False
                }    
                "COM"
                {
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 2 -Type DWord -Confirm:$False
                }
                "ALL"
                { 
                    Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_CIPHERSUITE_KEY -Value 3 -Type DWord -Confirm:$False
                }
            }

            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $SSL_PORT_KEY -Value $SSLPort -Type DWord -Confirm:$False

            #Backup DH Cipher Suite and set Enabled:0 if SSL is enabled
            if (!(Test-Path $ICA_CIPHER_SUITE))
            {
                New-Item -Path $ICA_CIPHER_SUITE -Force | Out-Null
                New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0 -PropertyType DWORD -Force | Out-Null
                New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value 1 -PropertyType DWORD -Force | Out-Null
            }
            else
            {
                $back_enabled_exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -ErrorAction SilentlyContinue
                if ($back_enabled_exists -eq $null)
                {
                    $exists = Get-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -ErrorAction SilentlyContinue
                    if ($exists -ne $null)
                    {
                        New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value $exists.Enabled -PropertyType DWORD -Force | Out-Null
                        Set-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0
                    }
                    else
                    {
                        New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $DHEnabled -Value 0 -PropertyType DWORD -Force | Out-Null
                        New-ItemProperty -Path $ICA_CIPHER_SUITE -Name $BACK_DHEnabled -Value 1 -PropertyType DWORD -Force | Out-Null
                    }
                }
            }

            # NOTE: This must be the last thing done when enabling SSL as the Citrix Service
            #       will use this as a signal to try and start the Citrix SSL Listener!!!!
            Set-ItemProperty -Path $ICA_LISTENER_PATH -name $ENABLE_SSL_KEY -Value 1 -Type DWord -Confirm:$False
        
            Write-Host "Registry keys set."
            Write-Host ""
            $RegistryKeysSet = $True

            $Store.Close()

            if ($RegistryKeysSet -and $ACLsSet -and $FirewallConfigured)
            {
                Write-Host "`nSSL to VDA enabled.`n"
            }
            else
            {
                Write-Host "`n"

                if (!$RegistryKeysSet)
                {
                    Write-Host "Configure registry manually or re-run the script to complete enabling SSL to VDA."
                }

                if (!$ACLsSet)
                {
                    Write-Host "Configure ACLs manually or re-run the script to complete enabling SSL to VDA."
                }
                    
                if (!$FirewallConfigured)
                {
                    Write-Host "Configure firewall manually or re-run the script to complete enabling SSL to VDA."
                }
            }
        }
    }

# SIG # Begin signature block
# MIInTgYJKoZIhvcNAQcCoIInPzCCJzsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUo53TkQRzA9gx2Cln3vwtNEkd
# 0jKggiDRMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTla
# MEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UE
# AxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIV
# WMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9Yr
# IBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5x
# XsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4
# KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUd
# vJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZ
# BzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02ke
# fGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1
# x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhv
# ltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPs
# CvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQAB
# o4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T
# 5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1P
# ijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09
# SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5
# j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXT
# UOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08z
# jdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9N
# UvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg2
# 1Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44Owde
# OVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZr
# uhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7
# KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywG
# Ru9BHvDwX+Db2a2QgESvgBBBijCCBxAwggT4oAMCAQICEAWS5PVF0WM8IiEcogV0
# HLQwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2ln
# bmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTAeFw0yMjA5MTMwMDAwMDBaFw0y
# NDA5MTIyMzU5NTlaMIGUMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHRmxvcmlkYTEY
# MBYGA1UEBxMPRm9ydCBMYXVkZXJkYWxlMR0wGwYDVQQKExRDaXRyaXggU3lzdGVt
# cywgSW5jLjEbMBkGA1UECxMSQ2l0cml4IFNIQTI1NiAyMDIyMR0wGwYDVQQDExRD
# aXRyaXggU3lzdGVtcywgSW5jLjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoC
# ggGBANQrHDK/VNT3B2QOOURSnbqhQLusUmpej1X5idWpTEQqBHdB7niY8shATc8L
# 83/2UIXN5hFLaC8mFAmaIURRorxGmLNlKjBgRNjK/gerAOfy74yn3Ty5NNYK+xq9
# UaqCCNbkQOt0onwCQRMUoBOeKKQFwbwDPEKeScOSCyTxbTG7/Pcd2FgdWqo+XczY
# lioKdj5h/Yd9uurLwvDtGYL2IGEwbg4My3XURI5MUmSUG3lQ0HRKdjj8liVE8Hnu
# MzRHmG482TCC+vCXvmle7zNntpx71t95rjBu0FJw1Srylbu1DyOxnTy84YC1MZC/
# Ru5aZAfQpn8yHvEUpJJcaN5YFwraN4zJgEeF7m2O5mhbc9gh2z1gbUn0JUW+tPDj
# Lb9Xc9DLKBwFnm2hWsOzOrElQF1GkkFAWxhjXf5mIyUo1/yyAtAJoXkEN7pducAX
# sSxeYCcliiPmuwfoQqc8iYumf2c/SBFVQ+Ze3IkUZOgqyf7Xc4mK0EMgUhqbPl9g
# ip31AwIDAQABo4ICBjCCAgIwHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0
# TkIwHQYDVR0OBBYEFKwyulWi8nAdh1VMypLuJfzImIDiMA4GA1UdDwEB/wQEAwIH
# gDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmlu
# Z1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hB
# Mzg0MjAyMUNBMS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggrBgEFBQcC
# ARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGUBggrBgEFBQcBAQSBhzCB
# hDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwGCCsGAQUF
# BzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNydDAMBgNVHRMBAf8E
# AjAAMA0GCSqGSIb3DQEBCwUAA4ICAQCKGwl3OeOtURgc3BIYpGO4DuqntD6wRRmh
# N5o3NfmsdV0F+wktkbqIqPyX7p7cP0H4nzHewNdBMWBlufxiOZPD+YMVmcHMbUz6
# NismlV/g0xZcONefxkZjn9Ol/LuSJvYkAQoud/5drYprDMwBeHBxxpwvaI+/mgmf
# xa1sBQCt0+zK3a64TZLTIMvKuLNPhWxs97W73EgwzBTP1CY3WTecTxyAszRRz+hu
# RKVowMgE7h79p5BFI3lUCm4fvn+OIM4T6I/6gKpGrbgoUlQfXh11ONIWInrEisFj
# 3T2tA4fum4TNfL0AdXd5VC19VACU0eRq+oeX2SW6jGbXaD5b5LBGMSnAOahA0+py
# qpJ4I6tNeBlcvXqxkCnGqggruU1H5GB7wh6+InnlNphK/k5mKR51IsjKw/7R7UW0
# zbXukvJJsHVnCw91MxzW1u1tGLEse9ffjCb57hRQ7ayDIMg4Xe1xCx1ayvhEzdeo
# kzPdvhDH1rA30rjHO4F8RE4bYQgNEaEBitrGxGro21XQxWqvkFCculomXensjLYY
# H2dQ3kQ4pl85cDfIII1i4FbPOSqIbwb+34mJPHmQq3zsw1n3o/FD/E00zAa6euIq
# VNG3ZR5UPudimglfFHArqbzuyMre7i4LVbiIjctQ+vGjJQQ6tN00BRfrEY5f5/S6
# rHx+bXAeNDGCBecwggXjAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUg
# U2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQBZLk9UXRYzwiIRyiBXQc
# tDAJBgUrDgMCGgUAoIGcMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTpxhHQ73qM
# M62kUDLSVQG1BAaQ0DA8BgorBgEEAYI3AgEMMS4wLKAQgA4AUwBjAHIAaQBwAHQA
# c6EYgBZodHRwOi8vd3d3LmNpdHJpeC5jb20gMA0GCSqGSIb3DQEBAQUABIIBgAX9
# ogy/2qA5k4ONi/od18Xu7yfj7C0oCY+9+GSmQS2SSYHw6JHmsooTqpmEg4/9YciM
# +AoyVlZMBMooGDvm2eYnBwBH59p/liCj85D1DjCMW8szuCmvz9pGtojIcu+gKvhq
# qfrOQRD02jB9uf6Kyi7hZXZkbCfoOniScTax+AdyqE/Mg36sa2T7O72hhR/Bqbjh
# MaG9M1HooWI4bvJMfpYO3ztLfdaeiOgn4YGeB8aoqauYgpg7nrPxjEOJjH3c5d7k
# ynfXEIupLslnLA7aqIiQBfnUCxsDnD5viti5CyyOrsy47X1015RNN5ETphG2dBoe
# iS9zKcVe+oU93HCAZGoomMVbTnDz9UtmuOOxdfERFsr2PoF+G2XkKtwVSDXCaezk
# jBTeE/zsEzH4FY3VRC+IPy0QUmge593joc+jH5tU2NbWlJeLzRMl3kXHFOU5claA
# OWzr8DoAfjoAbehvnZW3mdO+5wRJb7+ZNfMULLE2mHruKbzGcoUkERU/RRH4tKGC
# AyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/b
# P1/lYRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNDA0MDkxOTQwMjRaMC8GCSqGSIb3DQEJBDEiBCDj
# 9yGTl9ho9kPOcYKzqOEH1tvpK7TDn1XPcJZccazUgTANBgkqhkiG9w0BAQEFAASC
# AgAWKG9EGb7uKPQvt+Rju0UoulqXnjmKO/gxaXDEvKNxOahQ5myURoDBRQExLn8/
# UXNeTWuQTVT1QUgaQNGX+CgaPNEuxnETWQYs3+7l9mf1AHo00ooEJfKt0Plc00w8
# j2GODgbzJYHkwPtTj8w0lPk1kaQmvQID4M3IrnjJd96vvWor8qdV/szMUtKVJrFg
# dHtd7uCQqA47n6l+qRLsLXfV/DjEi1xJuWsyENZvrSE1I9+CaE/+KUJI2abQNThh
# n9ihH3HirjFHqVDuXIuwqKAXS8Y+40i+hCQp8iH31fOdNRhIguY17F+dTTdDSH0E
# SdnoXLgQ4EODY76BCUoCRjpnyAq1mpSnzjd+4/xmzl9tcv83kJs34sXxJ2MZf3y/
# 8uK819uvkz5jevERfjmBFoIpRAudbvdxpSNXUrJqllUohsYi1O0Mblnqej5UOZWt
# Qve/KQe5ukUwVgA/O6JsVVCNHMm35U5UUupCI5FEYf6nP7cQOPIkFZgNmNqT3BwN
# WQFUK+v4EqYZ3AUZgemSvJvoOX2TvtZ2KNwOWgLmyy3EXvc2oYnIEpWUIE25xIuE
# tByd/vFF6owE4j2YCB74Co+blF9QDBOPERss/P2iKoaKpyBrcyLzwWmjF6fdm7VV
# /h9yJZnHQEd2ZK7ui8dDZmmKStmd+FprItaSzQUnHjtTHg==
# SIG # End signature block

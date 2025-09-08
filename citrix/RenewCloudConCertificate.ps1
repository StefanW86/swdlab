# Parameter
$ipPort = "10.0.0.7:443"          # IP-Adresse und Port, auf dem SSL gebunden ist
$certSubject = "CN=azcloudcon1.swdlab.de"  # Suchkriterium für das neue Zertifikat
$renewThresholdDays = 5          # Tage vor Ablauf zur Erneuerung

$ErrorActionPreference = 'SilentlyContinue'

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info","Error")]
        [string]$Type = "Info",
        [string]$LogFile = "$(Get-Location)\RenewCloudConCertfificate-Log.txt"
    )

    # Erstelle Verzeichnis für Logdatei, falls nicht vorhanden
    $logDir = Split-Path $LogFile
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # Erzeuge Logzeile mit Timestamp und Typ
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"

    # Schreibe in Logdatei
    Add-Content -Path $LogFile -Value $logEntry

    # Ausgabe auf Konsole farbig je nach Typ
    if ($Type -eq "Error") {
        Write-Host $logEntry -ForegroundColor Red
    } else {
        Write-Host $logEntry -ForegroundColor Green
    }
}

Write-Log "---------------- Script gestartet -----------------"

function Get-BoundSSLCertificate {
    param([string]$ipPort)
    $bindings = netsh http show sslcert | Select-String -Pattern $ipPort -Context 0,20
    if ($bindings) {
        $index = $bindings.Context.PostContext | Select-String "Certificate Hash"
        if ($index) {
            $thumbprint = ($index -replace ".*:\s*", "").Trim()
            return $thumbprint
        }
    }
    return $null
}

function Get-CertificateByThumbprintOrSubject {
    param([string]$search)
    # Suchen im lokalen Computer-Zertifikatsspeicher - My
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
    $store.Open("ReadOnly")
    $cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $search -or $_.Subject -like "*$search*" } | Sort-Object NotAfter -Descending | Select-Object -First 1
    $store.Close()
    return $cert
}

function Renew-SSLCertificateBinding {
    param([string]$ipPort, [string]$newCertThumbprint)
    Write-Log "Entferne alte SSL-Bindung an $ipPort"
    netsh http delete sslcert ipport=$ipPort
    Write-Log "Binde neues Zertifikat mit Thumbprint $newCertThumbprint an $ipPort"
    netsh http add sslcert ipport=$ipPort certhash=$newCertThumbprint appid='{00112233-4455-6677-8899-AABBCCDDEEFF}' 
}

$boundThumbprint = Get-BoundSSLCertificate $ipPort
if (-not $boundThumbprint) {
    Write-Log "Kein SSL-Zertifikat auf $ipPort gefunden." -Type Error
    $newCert = Get-CertificateByThumbprintOrSubject $certSubject
    Renew-SSLCertificateBinding -ipPort $ipPort -newCertThumbprint $newCert.Thumbprint
    exit 0
}

$currentCert = Get-CertificateByThumbprintOrSubject $boundThumbprint
if (-not $currentCert) {
    Write-Log "Gebundenes Zertifikat mit Thumbprint $boundThumbprint nicht gefunden." -Type Error
    $newCert = Get-CertificateByThumbprintOrSubject $certSubject
    Renew-SSLCertificateBinding -ipPort $ipPort -newCertThumbprint $newCert.Thumbprint
    Write-Log "Nicht vorhandenes Zertifikat ersetzt."
    exit 0
}

Write-Log "Aktuell gebundenes Zertifikat läuft ab am: $($currentCert.NotAfter)"

$daysLeft = ($currentCert.NotAfter - (Get-Date)).Days
if ($daysLeft -le $renewThresholdDays) {
    Write-Log "Zertifikat läuft in $daysLeft Tagen ab. Suche neues Zertifikat..."
    $newCert = Get-CertificateByThumbprintOrSubject $certSubject
    if (-not $newCert) {
        Write-Log "Kein neues Zertifikat mit Subject '$certSubject' gefunden." -Type Error
        exit 1
    }
    if ($newCert.Thumbprint -eq $boundThumbprint) {
        Write-Log "Das neue Zertifikat ist identisch mit dem aktuellen. Keine Erneuerung notwendig."
        exit 0
    }
    Renew-SSLCertificateBinding -ipPort $ipPort -newCertThumbprint $newCert.Thumbprint
    Write-Log "Erneuerung abgeschlossen."
} else {
    Write-Log "Zertifikat ist noch gültig für $daysLeft Tage. Keine Erneuerung notwendig."
}

Write-Log "---------------- Script beendet -----------------"

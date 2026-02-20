# Windows 11 Master Image 

Im folgenden werden Schritte für eine Windows 11 Master Image Bereitstellung dokumentiert

## Office Installation

Erstellung von configuration.xml Datei

``` xml
<Configuration>
  <Add OfficeClientEdition="64" Channel="Current" SourcePath="c:\Temp" AllowCdnFallback="TRUE">
    <Product ID="O365BusinessEEANoTeamsRetail">
      <Language ID="MatchOS" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Lync" />
      <ExcludeApp ID="OneDrive" />
      <ExcludeApp ID="OutlookForWindows" />
    </Product>
  </Add>
  <Updates Enabled="FALSE" />
  <AppSettings>
    <User Key="software\microsoft\office\16.0\excel\options" Name="defaultformat" Value="51" Type="REG_DWORD" App="excel16" Id="L_SaveExcelfilesas" />
    <User Key="software\microsoft\office\16.0\powerpoint\options" Name="defaultformat" Value="27" Type="REG_DWORD" App="ppt16" Id="L_SavePowerPointfilesas" />
    <User Key="software\microsoft\office\16.0\word\options" Name="defaultformat" Value="" Type="REG_SZ" App="word16" Id="L_SaveWordfilesas" />
  </AppSettings>
  <Display Level="Full" AcceptEULA="TRUE" />
</Configuration>


oder

<Configuration>
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-US" />
      <Language ID="MatchOS" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Lync" />
      <ExcludeApp ID="OneDrive" />
      <ExcludeApp ID="Teams" />
    </Product>
  </Add>
  <RemoveMSI/>
  <Updates Enabled="FALSE"/>
  <Display Level="None" AcceptEULA="TRUE" />
  <Logging Level="Standard" Path="%temp%\WVDOfficeInstall" />
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/>
  <Property Name="SharedComputerLicensing" Value="1"/>
</Configuration>


```

Es wird das Office Deployment Toolkit benötigt.
https://www.microsoft.com/en-gb/download/details.aspx?id=49117&msockid=3f9669d62306697a17a87f79224d68e2

Die URL ändert sich leider, daher kann es nur über die Page URL heruntergeladen werden

Anschließend ausführen

``` bash
setup.exe /configure configuration.xml
```

## OneDrive per Machine installieren

``` powershell

$url  = "https://go.microsoft.com/fwlink/?linkid=2324845"
$ziel = ".\OneDriveSetup.exe"
$old = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'


Invoke-WebRequest -Uri $url -OutFile $ziel

$ProgressPreference = $old

.\OneDriveSetup.exe /uninstall
```

Run this command to install OneDrive in per-machine mode:

``` powershell
".\OneDriveSetup.exe" /allusers
```

Run this command to configure OneDrive to start at sign in for all users:

``` bash
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "C:\Program Files\Microsoft OneDrive\OneDrive.exe /background" /f
```
Enable Silently configure user account by running the following command.

``` bash
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "SilentAccountConfig" /t REG_DWORD /d 1 /
```

Automatische Erstellung von per User scheduled Tasks verhindern. Dafür muss der RegKey EnableTHDFFeatures auf 0 gesetzt werden.
Ebenfalls, damit OneDrive sich nicht als per User installiert das Setup aus dem run entfernen
``` powershell
Reg Load HKEY_Users\Default "C:\Users\Default\NTUser.dat" 

Remove-ItemProperty -Path "Registry::HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -ErrorAction SilentlyContinue 

Set-ItemProperty -Path "Registry::HKU\Default\SOFTWARE\Microsoft\OneDrive" -Name "EnableTHDFFeatures" -Value "0" 

Reg Unload HKEY_Users\Default 
```

Damit OneDrive sich nicht automatich updated

``` powershell
Disable-ScheduledTask -TaskName "OneDrive Per-Machine Standalone Update Task"
Set-Service -Name "OneDrive Updater Service" -StartupType Disabled
```

Anschließend die Windows integrierte OneDriveSetup.exe unter c:\windows\system32 entfernen

``` powershell
$path = 'C:\Windows\System32\OneDriveSetup.exe'
if (Test-Path $path) {
    takeown /F $path
    icacls $path /grant *S-1-5-32-544:F
    Remove-Item $path -Force
}
```

## Teams Installation

Teams kann wie folgt installiert werden. Mit dem Parameter --installTMA wird das Teams Outlook Plugin 

``` powershell
$bootstrapper = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"
$msix = "https://go.microsoft.com/fwlink/?linkid=2196106"

$old = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

Invoke-WebRequest -Uri $bootstrapper -OutFile ".\bootstrapper.exe"
Invoke-WebRequest -Uri $msix -OutFile ".\MSTeams-x64.msix"

$ProgressPreference = $old

$cwd  = (Get-Location).Path
$msix = Join-Path $cwd 'MSTeams-x64.msix'

.\bootstrapper.exe -p -o $msix --installTMA
```

Auto Update von Teams deaktivieren. Der Update Button lässt sich nicht ausblenden. Stand 19.02.2026

```powershell
If (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Teams")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" -Type DWord -Value 1
```


## Windows Updates im bereitgestellten Image deaktivieren

Um die Windows Updates im bereitgestellten Image zu deaktivieren empfiehlt sich

1. Specify intranet Microsoft update service location
Enable - Enter anything for the server name such as http://void:8530
Configure Automatic Updates
Find whatever here that either makes the process manual or prevents automatic installation
Do not connect to any Windows Update Internet locations
Enabled

BITS deaktivieren

Delivery Optimization deaktivieren

Im Test!

```powershell
Stop-Service wuauserv
Set-Service wuauserv -StartupType disabled
Stop-Service BITS
Set-Service BITS -StartupType disabled

```

## Defender und Antivirus exclusions

Defender per Gruppenrichtlinie konfigurieren. Wichtig, vorab einen zentralen Speicherort erstellen, wo die Signaturupdates abgelegt werden können.
auf einem zentralen Server das folgende Script verwenden, um die Signaturupdates upzudaten.

```powershell
$vdmpathbase = "\\drevefiler03.dreve.local\DreveProfiles\2_DefenderUpdates\{00000000-0000-0000-0000-"
$vdmpathtime = Get-Date -format "yMMddHHmmss"
$vdmpath = $vdmpathbase + $vdmpathtime + '}'
$vdmpackage = $vdmpath + '\mpam-fe.exe'

New-Item -ItemType Directory -Force -Path $vdmpath | Out-Null

Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64' -OutFile $vdmpackage

Start-Process -FilePath $vdmpackage -WorkingDirectory $vdmpath -ArgumentList "/x"
```

Tamper Protection kann nur manuell über die GUI im Master Image deaktiviert werden. Muss aber nicht.

## Webview und Edge Update ?

Deaktivieren des sautomatischen Edge Updates, dafür müssen die folgenden Services deaktiviert werden:

```powershell
Set-Service -Name edgeupdate -StartupType Disabled
Set-Service -Name edgeupdatem -StartupType Disabled
Set-Service -Name MicrosoftEdgeElevationService -StartupType Disabled

```

Edge Download und installieren, sowie für VDI anpassen

```powershell
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Microsoft Edge - Silent Install + Auto-Update deaktivieren
.DESCRIPTION
    Lädt den Edge Enterprise MSI herunter, installiert ihn silent
    und deaktiviert alle automatischen Updates via Registry & Policies.
#>

# ─── Konfiguration ────────────────────────────────────────────────────────────
$EdgeMsiUrl    = "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/e2d06b69-9e44-45d1-bec4-8b733e851b03/MicrosoftEdgeEnterpriseX64.msi"
$DownloadPath  = "$env:TEMP\MicrosoftEdgeEnterprise.msi"
$LogPath       = "$env:TEMP\EdgeInstall.log"

# ─── 1. Edge MSI herunterladen ────────────────────────────────────────────────
Write-Host "[1/3] Lade Microsoft Edge Enterprise MSI herunter..." -ForegroundColor Cyan

try {
    $ProgressPreference = 'SilentlyContinue'   # deutlich schnellerer Download
    Invoke-WebRequest -Uri $EdgeMsiUrl -OutFile $DownloadPath -UseBasicParsing
    Write-Host "      Download abgeschlossen: $DownloadPath" -ForegroundColor Green
} catch {
    Write-Error "Download fehlgeschlagen: $_"
    exit 1
}

# ─── 2. Silent-Installation ───────────────────────────────────────────────────
Write-Host "[2/3] Installiere Microsoft Edge silent..." -ForegroundColor Cyan

$MsiArgs = @(
    "/i",  $DownloadPath,
    "/qn",                          # kein UI
    "/norestart",                   # kein Neustart
    "/l*v", $LogPath,               # ausführliches Log
    "DONOTCREATEDESKTOPSHORTCUT=TRUE"
)

$Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArgs -Wait -PassThru

if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
    Write-Host "      Installation erfolgreich (ExitCode: $($Process.ExitCode))" -ForegroundColor Green
} else {
    Write-Error "Installation fehlgeschlagen! ExitCode: $($Process.ExitCode) – Log: $LogPath"
    exit 1
}

# ─── 3. Automatische Updates vollständig deaktivieren ────────────────────────
Write-Host "[3/3] Deaktiviere alle automatischen Edge-Updates..." -ForegroundColor Cyan

## 3a – Edge Update Service deaktivieren (edgeupdate + edgeupdatem)
$UpdateServices = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
foreach ($svc in $UpdateServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        Stop-Service  -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service   -Name $svc -StartupType Disabled
        Write-Host "      Service deaktiviert: $svc" -ForegroundColor Green
    }
}

## 3b – Geplante Aufgaben für Edge-Update deaktivieren
$EdgeTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*MicrosoftEdge*" -or $_.TaskName -like "*Edge*Update*" }
foreach ($task in $EdgeTasks) {
    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue | Out-Null
    Write-Host "      Scheduled Task deaktiviert: $($task.TaskName)" -ForegroundColor Green
}

## 3c – Group Policy / Registry (verhindert Re-Aktivierung durch Edge selbst)
$PolicyPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
)

foreach ($path in $PolicyPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# Update komplett sperren (0 = Updates deaktiviert)
$EdgeUpdatePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
Set-ItemProperty -Path $EdgeUpdatePolicy -Name "UpdateDefault"                        -Value 0 -Type DWord -Force
Set-ItemProperty -Path $EdgeUpdatePolicy -Name "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0 -Type DWord -Force  # Edge Stable
Set-ItemProperty -Path $EdgeUpdatePolicy -Name "AutoUpdateCheckPeriodMinutes"         -Value 0 -Type DWord -Force
Set-ItemProperty -Path $EdgeUpdatePolicy -Name "DisableAutoUpdateChecksCheckboxValue" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $EdgeUpdatePolicy -Name "InstallDefault"                       -Value 0 -Type DWord -Force

# Edge selbst: Browser-seitige Update-UI und Benachrichtigungen sperren
$EdgePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
Set-ItemProperty -Path $EdgePolicy -Name "UpdatePolicyOverride"  -Value 0 -Type DWord -Force   # 0 = Updates deaktiviert
Set-ItemProperty -Path $EdgePolicy -Name "EdgeUpdatePoliciesEnabled" -Value 0 -Type DWord -Force

## 3d – MicrosoftEdgeUpdate.exe umbenennen (Fallback-Schutz)
$EdgeUpdateExe = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
if (Test-Path $EdgeUpdateExe) {
    Rename-Item -Path $EdgeUpdateExe -NewName "MicrosoftEdgeUpdate.exe.bak" -Force -ErrorAction SilentlyContinue
    Write-Host "      EdgeUpdate.exe umbenannt (Fallback-Schutz)" -ForegroundColor Green
}

# ─── Aufräumen ────────────────────────────────────────────────────────────────
Remove-Item -Path $DownloadPath -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "✔  Fertig! Edge ist installiert und alle Auto-Updates sind deaktiviert." -ForegroundColor Green
Write-Host "   Installations-Log: $LogPath" -ForegroundColor Gray

```


## TO DO Citrix PVS Entra ID Hybrid Join

Laut PVS Doku sollen bei Windows 11 die folgenden Registry Keys gesetzt werden
https://docs.citrix.com/en-us/provisioning/current-release/configure/create-hybrid-joined-catalogs.html

````
For windows 11 master devices, add the following registry values to the registry key HKLM\Software\AzureAD\VirtualDesktop:

Value: Type [DWORD]: 1 for non-persistent VM and 2 for persistent VM
Value: User [DWORD]: 1 for single session and 2 for multi-session
````

*Achtung*: https://support.citrix.com/external/article/CTX475187/windows-11-vda-machines-stuck-at-initial.html


## Windows DMA deaktivieren

DMA mit dem vivetool deaktivieren, damit die Meldung continue to sign in nicht erscheint.
Damit funktioniert die Anmeldung in Teams automatisch. 
https://call4cloud.nl/fix-continue-to-sign-in-prompt-dma-sso-compliance/

```powershell
$downloadUrl = "https://github.com/thebookisclosed/ViVe/releases/download/v0.3.3/ViVeTool-v0.3.3.zip"  # URL to download ViVe tool
$tempPath = "C:\Windows\Temp"
$viveToolZip = "$tempPath\ViVeTool.zip"
$viveToolDir = "$tempPath\ViVeTool"
New-Item -Path $viveToolDir -ItemType Directory -Force | Out-Null

$viveToolExe = "$viveToolDir\ViVeTool.exe"
$featureIds = @(47557358, 45317806)


# Ensure ViVeTool exists
if (-not (Test-Path $viveToolExe)) {
    Invoke-WebRequest -Uri $downloadUrl -OutFile "$tempPath\ViVeTool.zip"
    Expand-Archive -Path "$tempPath\ViVeTool.zip" -DestinationPath $viveToolDir -Force
    Write-host "Downloaded and extracted ViVeTool."
} else {
    Write-host "ViVeTool already exists."
}
# disable features
foreach ($featureId in $featureIds) {
    Write-host "Enabling feature with ID $featureId."
& "$viveToolDir\ViveTool.exe" /disable /id:$featureId
}
 
# Query status of features
foreach ($featureId in $featureIds) {  
$queryresult = & "$viveToolDir\ViveTool.exe" /query /id:$featureId  
Write-host $queryresult  
}
```


## Disable Last Access Timestamp

```bash
fsutil behavior set disablelastaccess 1
```

## Defrag Task deaktivieren

Damit die Targets nicht nach dem Boot die auto defragmentierung starten, sollte der Task deaktiviert werden
```powershell
# Geplanten Defrag-Task deaktivieren
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag"
```

Im Master Image vorm versiegeln könnte man defrag ausführen

```bash
%windir%\system32\defrag.exe -c -h -k -g -$
```

Die Parameter sind so vom Task übernommen

## Eventlogs umleiten

Damit die Eventlogs nicht permanent in den Schreibcache schreiben könnte man diese umleiten.

```bash

wevtutil sl Application /lfn:"D:\Logs\Application.evtx"
wevtutil sl System /lfn:"D:\Logs\System.evtx"
wevtutil sl Application /ms:104857600
wevtutil sl System /ms:104857600

```
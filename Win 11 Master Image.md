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


## Windows Updates im bereitgestellten Image deaktivieren

Um die Windows Updates im bereitgestellten Image zu deaktivieren empfiehlt sich

1. Specify intranet Microsoft update service location
Enable - Enter anything for the server name such as http://void:8530
Configure Automatic Updates
Find whatever here that either makes the process manual or prevents automatic installation
Do not connect to any Windows Update Internet locations
Enabled
1. asdsad


## Defender und Antivirus exclusions

...

## Webview und Edge Update ?


## Citrix PVS Entra ID Hybrid Join

Laut PVS Doku sollen bei Windows 11 die folgenden Registry Keys gesetzt werden
https://docs.citrix.com/en-us/provisioning/current-release/configure/create-hybrid-joined-catalogs.html

````
For windows 11 master devices, add the following registry values to the registry key HKLM\Software\AzureAD\VirtualDesktop:

Value: Type [DWORD]: 1 for non-persistent VM and 2 for persistent VM
Value: User [DWORD]: 1 for single session and 2 for multi-session
````

*Achtung*: https://support.citrix.com/external/article/CTX475187/windows-11-vda-machines-stuck-at-initial.html





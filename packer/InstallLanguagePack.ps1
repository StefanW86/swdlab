
##Language Iso Windows 2022
$filename = "c:\temp\lp2022_de-de.cab"
Invoke-WebRequest -Uri "https://stswd001.blob.core.windows.net/software/lp2022_de-de.cab?sp=r&st=2025-09-03T07:00:06Z&se=2026-09-03T15:15:06Z&spr=https&sv=2024-11-04&sr=c&sig=cUWj9MA1bfyPIavP2afKcMIKE5wqLkwJ2DeWbiQgqLM%3D" -OutFile $filename

cmd /c lpksetup /i de-de /p "c:\temp\" /r /s

Set-WinUILanguageOverride -Language de-de
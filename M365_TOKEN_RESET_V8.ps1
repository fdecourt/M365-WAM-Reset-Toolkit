################################################################################
# SCRIPT:        M365_TOKEN_RESET_V8.ps1
# DESCRIPTION:   Full Microsoft 365 token and WAM reset with locked file handling
# AUTHOR:        fdecourt
# VERSION:       V8
# DATE:          2025-06-17
# COMPATIBILITY: Windows 10/11 – PowerShell 5.x+
# LICENSE:       CC BY 4.0 – https://creativecommons.org/licenses/by/4.0/
#
# DISCLAIMER:
# This script is provided "as is", without any warranty of any kind.
# Use it at your own risk. The author cannot be held liable for any damage.
################################################################################

# Force UTF-8 encoding for consistent console output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  MICROSOFT 365 TOKEN FULL RESET - VERSION V8" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# Function: schedule deletion on reboot
function Schedule-DeleteOnReboot {
    param ([string]$PathToDelete)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $pendingValue = Get-ItemProperty -Path $regPath -Name PendingFileRenameOperations -ErrorAction SilentlyContinue

    if ($pendingValue -eq $null) {
        $list = @("\??\$PathToDelete")
    } else {
        $list = @($pendingValue.PendingFileRenameOperations)
        $list += "\??\$PathToDelete"
    }

    Set-ItemProperty -Path $regPath -Name PendingFileRenameOperations -Value ([string[]]$list)
    Write-Host ("Scheduled for deletion on reboot: {0}" -f $PathToDelete)
}

# Robust admin rights check
function Test-IsAdmin {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# Check admin rights
if (-not (Test-IsAdmin)) {
    Write-Host "? The script could not verify administrative rights." -ForegroundColor Yellow
    Write-Host "If you are running as administrator, you may continue manually." -ForegroundColor Yellow
    Pause
}

Write-Host "Starting advanced Microsoft 365 reset (V8 full WAM clean)" -ForegroundColor Cyan

# Close Office applications
Write-Host "Closing Office/M365 applications..." -ForegroundColor Yellow
Get-Process -Name "WINWORD","EXCEL","POWERPNT","OUTLOOK","ONENOTE","Teams","OneDrive","OfficeClickToRun" -ErrorAction SilentlyContinue | Stop-Process -Force

# Purge Credential Manager
Write-Host "Purging Credential Manager..." -ForegroundColor Yellow
try {
    cmdkey /list | ForEach-Object {
        if ($_ -match "MicrosoftOffice") {
            $target = ($_ -split ":")[1].Trim()
            cmdkey /delete:$target
        }
    }
} catch {
    Write-Host ("Credential Manager error: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

# Purge Identity & IdentityCache
Write-Host "Purging Identity & IdentityCache..." -ForegroundColor Yellow
$identityPaths = @("$env:LOCALAPPDATA\Microsoft\Identity", "$env:LOCALAPPDATA\Microsoft\IdentityCache")
foreach ($path in $identityPaths) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Host ("Deleted: {0}" -f $path)
        } catch {
            Write-Host ("Locked, scheduled for deletion: {0}" -f $path) -ForegroundColor Yellow
            Schedule-DeleteOnReboot -PathToDelete $path
        }
    } else { Write-Host ("Not found: {0}" -f $path) }
}

# Purge WAM Token Broker (100% safe file-by-file cleanup)
Write-Host "Purging Token Broker (WAM)..." -ForegroundColor Yellow
$wamPaths = @(
    "$env:LOCALAPPDATA\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy",
    "$env:LOCALAPPDATA\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy"
)

foreach ($path in $wamPaths) {
    if (Test-Path $path) {
        try {
            Get-ChildItem -Path $path -Recurse -Force | Sort-Object FullName -Descending | ForEach-Object {
                try {
                    if ($_.PSIsContainer) {
                        Remove-Item $_.FullName -Force -Recurse -ErrorAction Stop
                        Write-Host ("Folder deleted: {0}" -f $_.FullName)
                    } else {
                        Remove-Item $_.FullName -Force -ErrorAction Stop
                        Write-Host ("File deleted: {0}" -f $_.FullName)
                    }
                } catch {
                    Write-Host ("Locked, scheduled for deletion: {0}" -f $_.FullName) -ForegroundColor Yellow
                    Schedule-DeleteOnReboot -PathToDelete $_.FullName
                }
            }

            # Delete parent directory if empty
            if (-not (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue)) {
                Remove-Item $path -Force -Recurse
                Write-Host ("Parent directory deleted: {0}" -f $path)
            } else {
                Write-Host ("Directory still partially locked: {0}" -f $path) -ForegroundColor Yellow
                Schedule-DeleteOnReboot -PathToDelete $path
            }
        } catch {
            Write-Host ("Error on {0}: {1}" -f $path, $_.Exception.Message) -ForegroundColor Red
        }
    } else { Write-Host ("Not found: {0}" -f $path) }
}

# dsregcmd /leave
Write-Host "Leaving AzureAD / Workplace Join..." -ForegroundColor Yellow
try { dsregcmd /leave } catch { Write-Host ("dsregcmd error: {0}" -f $_.Exception.Message) -ForegroundColor Red }

# Purge Workplace Join certificates
Write-Host "Deleting Workplace Join certificates..." -ForegroundColor Yellow
try {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","CurrentUser")
    $store.Open("ReadWrite")
    $certs = $store.Certificates | Where-Object {
        $_.Issuer -like "*Microsoft*" -or $_.Subject -like "*Workplace Join*" -or $_.Issuer -like "*MS-Organization-Access*"
    }
    foreach ($cert in $certs) {
        Write-Host ("Deleting certificate: {0}" -f $cert.Subject) -ForegroundColor Red
        $store.Remove($cert)
    }
    $store.Close()
} catch {
    Write-Host ("Certificate deletion error: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

# Reset OneDrive
Write-Host "Resetting OneDrive..." -ForegroundColor Yellow
$oneDriveExe = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
if (Test-Path $oneDriveExe) {
    try { Start-Process $oneDriveExe "/reset"; Write-Host "OneDrive reset launched" }
    catch { Write-Host ("OneDrive reset error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
} else { Write-Host "OneDrive not found." -ForegroundColor Magenta }

# End
Write-Host "`nFull reset completed (V8). Please reboot now to apply all scheduled deletions." -ForegroundColor Green
Pause

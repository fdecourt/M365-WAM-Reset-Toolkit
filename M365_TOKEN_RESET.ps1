################################################################################
# SCRIPT:        M365_TOKEN_RESET_V92_EN.ps1
# DESCRIPTION:   Safe-by-default Microsoft 365 token reset with optional ForceReauth
# AUTHOR:        fdecourt
# VERSION:       V9.2
# DATE:          2026-02-06
# COMPATIBILITY: Windows 10/11 – PowerShell 5.1+ (PowerShell 7 compatible)
# LICENSE:       CC BY 4.0 – https://creativecommons.org/licenses/by/4.0/
#
# DISCLAIMER:
# This script is provided "as is", without any warranty of any kind.
# Use it at your own risk. The author cannot be held liable for any damage.
################################################################################

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet("Safe", "ForceReauth")]
    [string]$Mode = "Safe",

    [switch]$DryRun,

    # ForceReauth clears Teams caches by default (can be disabled)
    [switch]$SkipTeams,

    # OneDrive reset is generally safe but can be skipped
    [switch]$SkipOneDriveReset
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Prefer UTF-8 output (best-effort)
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# Normalize env vars to strict strings (prevents Join-Path binding issues)
$LocalAppData = [string]$env:LOCALAPPDATA
$AppData      = [string]$env:APPDATA
$TempDir      = [string]$env:TEMP

# --------------------------
# Logging
# --------------------------
$StartTs = Get-Date
$LogRoot = Join-Path $TempDir "M365-Reset"
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
$LogFile   = Join-Path $LogRoot ("M365_TOKEN_RESET_V92_{0:yyyyMMdd_HHmmss}.log" -f $StartTs)
$TransFile = Join-Path $LogRoot ("M365_TOKEN_RESET_V92_{0:yyyyMMdd_HHmmss}.transcript.txt" -f $StartTs)

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","STEP","DEBUG")]
        [string]$Level = "INFO",
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $line
}

function Step([string]$m){ Write-Log -Message $m -Level "STEP" -Color Cyan }
function Ok  ([string]$m){ Write-Log -Message $m -Level "SUCCESS" -Color Green }
function Warn([string]$m){ Write-Log -Message $m -Level "WARN" -Color Yellow }
function Err ([string]$m){ Write-Log -Message $m -Level "ERROR" -Color Red }
function Dbg ([string]$m){ Write-Log -Message $m -Level "DEBUG" -Color DarkGray }

function Pause-Console([string]$Message="Press Enter to continue..."){
    [void](Read-Host $Message)
}

# --------------------------
# Admin elevation
# --------------------------
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Ensure-AdminOrExit {
    if (Test-IsAdmin) { return }

    Warn "Not running as Administrator. Attempting UAC self-elevation..."
    $ps = (Get-Process -Id $PID).Path
    if (-not $ps) { $ps = "powershell.exe" }

    $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"","-Mode",$Mode)
    if ($DryRun) { $args += "-DryRun" }
    if ($SkipTeams) { $args += "-SkipTeams" }
    if ($SkipOneDriveReset) { $args += "-SkipOneDriveReset" }

    try {
        Start-Process -FilePath $ps -ArgumentList $args -Verb RunAs | Out-Null
        Ok "Relaunched as Administrator. You can close this window."
        exit 0
    } catch {
        Err "Self-elevation failed or was denied: $($_.Exception.Message)"
        Err "Please re-run PowerShell as 'Run as administrator'."
        exit 1
    }
}
Ensure-AdminOrExit

try { Start-Transcript -Path $TransFile -Force | Out-Null } catch {}

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " MICROSOFT 365 TOKEN RESET - V9.2 (SAFE / FORCEREAUTH)   " -ForegroundColor Cyan
Write-Host (" Mode: {0} | DryRun: {1}" -f $Mode, $DryRun) -ForegroundColor Cyan
Write-Host (" Logs: {0}" -f $LogFile) -ForegroundColor Cyan
Write-Host (" Transcript: {0}" -f $TransFile) -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

if ($DryRun) { Warn "DRY-RUN: no changes will be made." }

function Should-Do([string]$Target, [string]$Action){
    if ($DryRun) { Dbg ("DRY-RUN => {0} : {1}" -f $Action, $Target); return $false }
    return $PSCmdlet.ShouldProcess($Target, $Action)
}

# --------------------------
# Schedule delete on reboot (directories only)
# --------------------------
function Add-PendingDeleteOnRebootDir {
    param([Parameter(Mandatory)][string]$DirPath)

    # PendingFileRenameOperations expects MULTI_SZ pairs: source, destination (empty = delete)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $name = "PendingFileRenameOperations"
    $ntPath = "\??\" + $DirPath

    try {
        $existing = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue).$name
        $list = @()
        if ($existing) { $list += @($existing) }

        $list += $ntPath
        $list += ""

        if (Should-Do "$regPath\$name" "Schedule delete-on-reboot (directory)") {
            Set-ItemProperty -Path $regPath -Name $name -Value ([string[]]$list)
            Warn ("Scheduled for deletion on reboot (directory): {0}" -f $DirPath)
        }
    } catch {
        Warn ("Could not schedule deletion on reboot ({0}): {1}" -f $DirPath, $_.Exception.Message)
    }
}

# --------------------------
# Safe remove helpers (delete now; if locked => schedule parent dir)
# --------------------------
function Remove-DirContentsOrSchedule {
    param([Parameter(Mandatory)][string]$DirPath)

    if (-not (Test-Path -LiteralPath $DirPath)) { Dbg ("Missing: {0}" -f $DirPath); return }

    try {
        $items = Get-ChildItem -LiteralPath $DirPath -Force -Recurse -ErrorAction Stop |
                 Sort-Object FullName -Descending

        foreach($it in $items){
            try {
                if ($it.PSIsContainer) {
                    if (Should-Do $it.FullName "Remove directory") {
                        Remove-Item -LiteralPath $it.FullName -Force -Recurse -ErrorAction Stop
                    }
                } else {
                    if (Should-Do $it.FullName "Remove file") {
                        Remove-Item -LiteralPath $it.FullName -Force -ErrorAction Stop
                    }
                }
            } catch {
                # Avoid flooding PendingFileRenameOperations with files
                Dbg ("Locked (will be handled via parent/reboot): {0}" -f $it.FullName)
            }
        }

        $remaining = Get-ChildItem -LiteralPath $DirPath -Force -Recurse -ErrorAction SilentlyContinue
        if (-not $remaining) {
            if (Should-Do $DirPath "Remove parent directory") {
                Remove-Item -LiteralPath $DirPath -Force -Recurse -ErrorAction SilentlyContinue
                Ok ("Deleted: {0}" -f $DirPath)
            }
        } else {
            Warn ("Still locked/has remaining items: {0} -> scheduling for reboot" -f $DirPath)
            Add-PendingDeleteOnRebootDir -DirPath $DirPath
        }
    } catch {
        Warn ("Error cleaning {0}: {1} -> scheduling for reboot" -f $DirPath, $_.Exception.Message)
        Add-PendingDeleteOnRebootDir -DirPath $DirPath
    }
}

function Remove-PathNowOrScheduleDir {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { Dbg ("Missing: {0}" -f $Path); return }

    try {
        if (Should-Do $Path "Remove path") {
            Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction Stop
            Ok ("Deleted: {0}" -f $Path)
        }
    } catch {
        Warn ("Locked: {0} -> scheduling directory for reboot" -f $Path)
        Add-PendingDeleteOnRebootDir -DirPath $Path
    }
}

# --------------------------
# Step 0: Device join diagnostic (informational)
# --------------------------
Step "0) Device join status (informational)"
try {
    $ds = dsregcmd /status 2>$null
    if ($ds) {
        $aadJoined = ($ds | Select-String -Pattern "AzureAdJoined\s*:\s*YES" -Quiet)
        $wjJoined  = ($ds | Select-String -Pattern "WorkplaceJoined\s*:\s*YES" -Quiet)
        $djJoined  = ($ds | Select-String -Pattern "DomainJoined\s*:\s*YES" -Quiet)
        Write-Log -Message ("DomainJoined={0} | AzureAdJoined={1} | WorkplaceJoined={2}" -f $djJoined, $aadJoined, $wjJoined) -Level "INFO" -Color Gray

        if ($aadJoined -or $wjJoined) {
            Warn "This device appears Entra/AzureAD/Workplace-registered: some sign-ins may still occur silently via Windows SSO."
            Warn "ForceReauth maximizes interactive prompts by purging TokenBroker Accounts + Office identity subkeys."
        }
    } else {
        Warn "dsregcmd /status returned no output (non-blocking)."
    }
} catch {
    Warn ("dsregcmd /status unavailable: {0}" -f $_.Exception.Message)
}

# --------------------------
# Step 1: Stop apps + stabilize Click-to-Run
# --------------------------
Step "1) Closing Office/Teams/OneDrive apps + stabilizing Click-to-Run"
$procNames = @("WINWORD","EXCEL","POWERPNT","OUTLOOK","ONENOTE","Teams","ms-teams","MSTeams","OneDrive")
foreach($p in $procNames){
    Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
        if (Should-Do ("{0} (PID {1})" -f $_.ProcessName, $_.Id) "Stop-Process") {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Ok ("Stopped: {0} (PID {1})" -f $_.ProcessName, $_.Id)
            } catch {}
        }
    }
}

# Ensure ClickToRunSvc is not disabled (helps prevent 0x426-0x0 surprises)
try {
    $c2r = Get-Service ClickToRunSvc -ErrorAction SilentlyContinue
    if ($c2r) {
        if (Should-Do "ClickToRunSvc" "Set startup type to Automatic") {
            Set-Service ClickToRunSvc -StartupType Automatic -ErrorAction SilentlyContinue
        }
        if ($c2r.Status -ne "Running") {
            if (Should-Do "ClickToRunSvc" "Start service") {
                Start-Service ClickToRunSvc -ErrorAction SilentlyContinue
                Ok "ClickToRunSvc started."
            }
        } else {
            Dbg "ClickToRunSvc is already running."
        }
    } else {
        Warn "ClickToRunSvc not found (rare). If Office fails to start, run Microsoft 365 Online Repair."
    }
} catch {
    Warn ("ClickToRunSvc handling error: {0}" -f $_.Exception.Message)
}

# --------------------------
# Step 2: Credential Manager cleanup
# --------------------------
Step "2) Cleaning Credential Manager (cmdkey) - M365 patterns"
function Get-CmdKeyTargets {
    $raw = cmdkey /list 2>$null
    if (-not $raw) { return @() }
    $targets = @()
    foreach ($line in $raw) {
        if ($line -match '^\s*(Target|Cible)\s*:\s*(.+)$') {
            $targets += $Matches[2].Trim()
        }
    }
    return $targets
}

try {
    $targets = Get-CmdKeyTargets
    $patterns = @(
        "MicrosoftOffice","Office","ADAL","MSOID","OneDrive","Teams",
        "login.microsoftonline.com","microsoftaccount","AzureAD",
        "SSO_POP_Device","SSO_POP_User","AzureSSO","OneAuth","Cloud"
    )

    $toDelete = $targets | Where-Object {
        $t = $_
        foreach($pat in $patterns){
            if ($t -like "*$pat*") { return $true }
        }
        return $false
    } | Select-Object -Unique

    if (-not $toDelete -or $toDelete.Count -eq 0) {
        Write-Log -Message "No cmdkey entries matched the M365 patterns." -Level "INFO" -Color Gray
    } else {
        foreach($t in $toDelete){
            if (Should-Do $t "cmdkey /delete") {
                cmdkey /delete:$t | Out-Null
                Ok ("Deleted (cmdkey): {0}" -f $t)
            }
        }
    }
} catch {
    Warn ("cmdkey cleanup error: {0}" -f $_.Exception.Message)
}

# --------------------------
# Step 3: Identity caches
# --------------------------
Step "3) Clearing Identity & IdentityCache (LOCALAPPDATA)"
$identityPaths = @(
    "$LocalAppData\Microsoft\Identity",
    "$LocalAppData\Microsoft\IdentityCache"
)
foreach($p in $identityPaths){
    if (Test-Path -LiteralPath $p) {
        Remove-PathNowOrScheduleDir -Path $p
    } else {
        Dbg ("Not found: {0}" -f $p)
    }
}

# --------------------------
# Step 4: WAM Token Broker
# --------------------------
Step "4) Clearing WAM Token Broker (safe++)"
$brokerPkg = "$LocalAppData\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"
$cehPkg    = "$LocalAppData\Packages\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy"

$wamCoreTargets = @(
    "AC\TokenBroker\Cache",
    "AC\TokenBroker\TokenBrokerCache",
    "AC\INetCache",
    "AC\INetCookies",
    "LocalCache",
    "LocalState"
)

# Force targets like V8 often trigger reauth
$wamForceTargets = @(
    "AC\TokenBroker\Accounts",
    "AC\TokenBroker\Account"
)

foreach($pkg in @($brokerPkg, $cehPkg)){
    if (-not (Test-Path -LiteralPath $pkg)) { Dbg ("Package missing: {0}" -f $pkg); continue }
    Write-Log -Message ("Detected package: {0}" -f $pkg) -Level "INFO" -Color Gray

    foreach($sub in $wamCoreTargets){
        $t = "$pkg\$sub"
        if (Test-Path -LiteralPath $t){
            Write-Log -Message ("Cleaning: {0}" -f $t) -Level "INFO" -Color Gray
            Remove-DirContentsOrSchedule -DirPath $t
        }
    }

    if ($Mode -eq "ForceReauth") {
        foreach($sub in $wamForceTargets){
            $t = "$pkg\$sub"
            if (Test-Path -LiteralPath $t){
                Warn ("ForceReauth: critical purge (reauth trigger): {0}" -f $t)
                Remove-DirContentsOrSchedule -DirPath $t
                Remove-PathNowOrScheduleDir -Path $t
            }
        }
    }
}

# --------------------------
# Step 5: Office Identity registry (ForceReauth only)
# --------------------------
if ($Mode -eq "ForceReauth") {
    Step "5) ForceReauth: clearing Office Identity registry (with backup)"

    $officeIdentityKey = "HKCU\Software\Microsoft\Office\16.0\Common\Identity"
    $backupReg = Join-Path $LogRoot ("OfficeIdentityBackup_{0:yyyyMMdd_HHmmss}.reg" -f (Get-Date))

    try {
        reg.exe export "$officeIdentityKey" "$backupReg" /y | Out-Null
        Ok ("Registry backup created: {0}" -f $backupReg)
    } catch {
        Warn ("Could not export Office Identity registry key (non-blocking): {0}" -f $_.Exception.Message)
    }

    # Remove only subkeys that commonly store identities/tokens
    $subKeysToRemove = @("Identities","Profiles","ServiceAuth","AuthTokens","Registrations")

    foreach($sk in $subKeysToRemove){
        $psPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\$sk"
        try {
            if (Test-Path $psPath) {
                Warn ("Removing registry key: {0}" -f $psPath)
                if (Should-Do $psPath "Remove registry key") {
                    Remove-Item -Path $psPath -Recurse -Force -ErrorAction SilentlyContinue
                    Ok ("Removed registry key: {0}" -f $sk)
                }
            } else {
                Dbg ("Registry key not present: {0}" -f $psPath)
            }
        } catch {
            Warn ("Failed to remove registry key {0}: {1}" -f $sk, $_.Exception.Message)
        }
    }
} else {
    Step "5) Safe: Office Identity registry not modified"
}

# --------------------------
# Step 6: Teams caches (optional; ForceReauth by default)
# --------------------------
if (($Mode -eq "ForceReauth") -and (-not $SkipTeams)) {
    Step "6) ForceReauth: clearing Teams caches (Classic + New Teams)"

    $teamsClassic = "$AppData\Microsoft\Teams"
    if (Test-Path -LiteralPath $teamsClassic) {
        Warn ("Teams Classic cache: {0}" -f $teamsClassic)
        Remove-PathNowOrScheduleDir -Path $teamsClassic
    } else {
        Dbg "Teams Classic cache not found."
    }

    $teamsNew = "$LocalAppData\Packages\MSTeams_8wekyb3d8bbwe\LocalCache"
    if (Test-Path -LiteralPath $teamsNew) {
        Warn ("New Teams cache: {0}" -f $teamsNew)
        Remove-DirContentsOrSchedule -DirPath $teamsNew
    } else {
        Dbg "New Teams cache not found."
    }
} else {
    Step "6) Teams cache cleanup skipped (Safe mode or -SkipTeams)"
}

# --------------------------
# Step 7: OneDrive reset (optional)
# --------------------------
Step "7) OneDrive reset (optional)"
if (-not $SkipOneDriveReset) {
    $oneDriveExe = "$LocalAppData\Microsoft\OneDrive\OneDrive.exe"
    if (Test-Path -LiteralPath $oneDriveExe) {
        try {
            if (Should-Do $oneDriveExe "Start OneDrive /reset") {
                Start-Process -FilePath $oneDriveExe -ArgumentList "/reset" | Out-Null
                Ok "OneDrive /reset started."
            }
        } catch {
            Warn ("OneDrive /reset failed: {0}" -f $_.Exception.Message)
        }
    } else {
        Warn "OneDrive.exe not found."
    }
} else {
    Dbg "OneDrive reset skipped (-SkipOneDriveReset)."
}

# --------------------------
# Final: ensure ClickToRun is healthy + reboot recommendation
# --------------------------
Step "Final: ensuring ClickToRunSvc + recommending reboot"
try {
    $c2r = Get-Service ClickToRunSvc -ErrorAction SilentlyContinue
    if ($c2r) {
        if (Should-Do "ClickToRunSvc" "Ensure Automatic + Running") {
            Set-Service ClickToRunSvc -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service ClickToRunSvc -ErrorAction SilentlyContinue
        }
        Ok "ClickToRunSvc is OK (or already OK)."
    }
} catch {
    Warn ("Final ClickToRunSvc check failed: {0}" -f $_.Exception.Message)
}

Write-Log -Message ("Mode={0} | DryRun={1} | Logs={2}" -f $Mode, $DryRun, $LogFile) -Level "INFO" -Color Gray
Write-Log -Message ("Transcript={0}" -f $TransFile) -Level "INFO" -Color Gray

Ok "Done. A reboot is strongly recommended (some deletions may be scheduled for reboot)."
Warn "After reboot, start Word/Outlook/Teams: in ForceReauth you will typically be prompted to sign in again."

try { Stop-Transcript | Out-Null } catch {}
Pause-Console

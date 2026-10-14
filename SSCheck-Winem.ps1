#Requires -Version 5.1
<#
    SS CHECK - Made by Winem. DM @null.mood for assistance.
    Run in an elevated PowerShell window.

    Colors:  GREEN  = normal / not found
             RED    = disabled, missing, stopped or RESTARTED service
             PURPLE = tamper indicator (suspended threads, token changes, deleted BAM keys,
                      event log hits, PSReadLine / history tampering, recycle bin activity)
             YELLOW = informational / needs a human look
             GRAY   = context (older than this boot)

    Everything is scoped to the CURRENT BOOT where it makes sense. Older records are only
    shown as gray context.
#>

$ErrorActionPreference = 'SilentlyContinue'
$Purple = 'Magenta'
$RestartToleranceSec = 300      # service started later than boot + this = "restarted"
$BamGapMinutes = 10             # BAM key modified this long after newest entry = possible deleted entries
$script:Flags = New-Object System.Collections.Generic.List[object]
$script:BootTime = (Get-Date).AddDays(-1)

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Fmt { param($d) if ($d) { ([datetime]$d).ToString('MM/dd/yyyy hh:mm:ss tt') } else { 'N/A' } }
function Fmt-Short { param($d) if ($d) { ([datetime]$d).ToString('MM/dd HH:mm:ss') } else { 'N/A' } }
function Format-Size {
    param([long]$b)
    if ($b -ge 1GB) { return ('{0:N2} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
    if ($b -ge 1KB) { return ('{0:N1} KB' -f ($b / 1KB)) }
    return "$b B"
}
function Trunc { param([string]$s, [int]$n) if ($s.Length -gt $n) { $s.Substring(0, $n - 3) + '...' } else { $s } }
function Add-Flag { param([string]$Text, [string]$Color = 'Magenta') $script:Flags.Add([pscustomobject]@{ Text = $Text; Color = $Color }) }

function Write-Banner {
    Write-Host ""
    Write-Host "  SS CHECK" -NoNewline -ForegroundColor Magenta
    Write-Host "  |  made by Winem  |  DM null.mood for assistance" -ForegroundColor DarkGray
    Write-Host ("  " + ('-' * 66)) -ForegroundColor DarkMagenta
    Write-Host "  " -NoNewline
    Write-Host "GREEN" -NoNewline -ForegroundColor Green;   Write-Host " ok   " -NoNewline -ForegroundColor DarkGray
    Write-Host "RED" -NoNewline -ForegroundColor Red;       Write-Host " disabled/restarted   " -NoNewline -ForegroundColor DarkGray
    Write-Host "PURPLE" -NoNewline -ForegroundColor Magenta; Write-Host " tamper   " -NoNewline -ForegroundColor DarkGray
    Write-Host "YELLOW" -NoNewline -ForegroundColor Yellow; Write-Host " info" -ForegroundColor DarkGray
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "[ " -NoNewline -ForegroundColor DarkGray
    Write-Host $Title -NoNewline -ForegroundColor Cyan
    Write-Host " ]" -ForegroundColor DarkGray
}

function Write-Item {
    param([string]$Label, [string]$Value, [string]$Color = 'White')
    Write-Host ("  {0,-20}" -f $Label) -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $Color
}

function Write-Rule { Write-Host ("  " + ('-' * 66)) -ForegroundColor DarkGray }

# ----------------------------------------------------------------------------
# Native helpers: process token privileges + registry key last-write time
# ----------------------------------------------------------------------------
$nativeOk = $true
try {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SSCheck {
    public static class Native {
        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr tok);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeName(string sys, ref long luid, StringBuilder name, ref int cch);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll, IntPtr newState, int len, IntPtr prev, IntPtr retLen);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern int RegOpenKeyEx(IntPtr hKey, string sub, int opt, int sam, out IntPtr res);
        [DllImport("advapi32.dll")] static extern int RegQueryInfoKey(IntPtr hKey, IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, out long lastWrite);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr h);

        public static bool EnableDebug() {
            IntPtr tok;
            if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return false;
            long luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) { CloseHandle(tok); return false; }
            IntPtr buf = Marshal.AllocHGlobal(16);
            Marshal.WriteInt32(buf, 0, 1);
            Marshal.WriteInt64(buf, 4, luid);
            Marshal.WriteInt32(buf, 12, 2);
            bool ok = AdjustTokenPrivileges(tok, false, buf, 16, IntPtr.Zero, IntPtr.Zero);
            Marshal.FreeHGlobal(buf);
            CloseHandle(tok);
            return ok;
        }

        // returns "PrivilegeName:attributes" (1=default, 2=enabled, 4=removed), or null if unreadable
        public static string[] GetPrivileges(int pid) {
            IntPtr hp = OpenProcess(0x1000, false, pid);
            if (hp == IntPtr.Zero) return null;
            IntPtr tok;
            if (!OpenProcessToken(hp, 0x8, out tok)) { CloseHandle(hp); return null; }
            List<string> res = new List<string>();
            IntPtr buf = IntPtr.Zero;
            try {
                int len;
                GetTokenInformation(tok, 3, IntPtr.Zero, 0, out len);
                if (len <= 0) return null;
                buf = Marshal.AllocHGlobal(len);
                if (!GetTokenInformation(tok, 3, buf, len, out len)) return null;
                int count = Marshal.ReadInt32(buf);
                for (int i = 0; i < count; i++) {
                    int off = 4 + i * 12;
                    long luid = Marshal.ReadInt64(buf, off);
                    int attr = Marshal.ReadInt32(buf, off + 8);
                    StringBuilder sb = new StringBuilder(64);
                    int cch = 64;
                    LookupPrivilegeName(null, ref luid, sb, ref cch);
                    res.Add(sb.ToString() + ":" + attr);
                }
                return res.ToArray();
            } finally {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                CloseHandle(tok);
                CloseHandle(hp);
            }
        }

        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenThread(uint access, bool inherit, int tid);
        [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h, int cls, out IntPtr info, int len, IntPtr ret);

        // Win32 start address of a thread (what System Informer shows), 0 on failure
        public static long GetThreadStart(int tid) {
            IntPtr h = OpenThread(0x40, false, tid);
            if (h == IntPtr.Zero) h = OpenThread(0x800, false, tid);
            if (h == IntPtr.Zero) return 0;
            IntPtr addr;
            int st = NtQueryInformationThread(h, 9, out addr, IntPtr.Size, IntPtr.Zero);
            CloseHandle(h);
            if (st != 0) return 0;
            return addr.ToInt64();
        }

        // returns "NAME|attributes" per token group (1 mandatory, 2 enabled-by-default, 4 enabled, 8 owner, 0x10 deny-only)
        public static string[] GetGroups(int pid) {
            IntPtr hp = OpenProcess(0x1000, false, pid);
            if (hp == IntPtr.Zero) return null;
            IntPtr tok;
            if (!OpenProcessToken(hp, 0x8, out tok)) { CloseHandle(hp); return null; }
            IntPtr buf = IntPtr.Zero;
            try {
                int len;
                GetTokenInformation(tok, 2, IntPtr.Zero, 0, out len);
                if (len <= 0) return null;
                buf = Marshal.AllocHGlobal(len);
                if (!GetTokenInformation(tok, 2, buf, len, out len)) return null;
                int count = Marshal.ReadInt32(buf);
                int first = IntPtr.Size;
                int step = IntPtr.Size * 2;
                List<string> res = new List<string>();
                for (int i = 0; i < count; i++) {
                    IntPtr sidPtr = Marshal.ReadIntPtr(buf, first + i * step);
                    int attr = Marshal.ReadInt32(buf, first + i * step + IntPtr.Size);
                    string name = "?";
                    try {
                        System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(sidPtr);
                        name = sid.Value;
                        try { name = sid.Translate(typeof(System.Security.Principal.NTAccount)).Value; } catch { }
                    } catch { }
                    res.Add(name + "|" + attr);
                }
                return res.ToArray();
            } finally {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                CloseHandle(tok);
                CloseHandle(hp);
            }
        }

        // HKLM subkey last write time as FILETIME (0 on failure)
        public static long GetKeyLastWrite(string subKey) {
            IntPtr h;
            long lw = 0;
            if (RegOpenKeyEx(new IntPtr(unchecked((int)0x80000002)), subKey, 0, 0x20119, out h) != 0) return 0;
            RegQueryInfoKey(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out lw);
            RegCloseKey(h);
            return lw;
        }
    }
}
"@ -ErrorAction Stop
} catch { $nativeOk = $false }

# ----------------------------------------------------------------------------
# Admin check
# ----------------------------------------------------------------------------
Write-Banner

$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  Administrator privileges REQUIRED. Re-run this script as Administrator." -ForegroundColor Red
    exit
}
if ($nativeOk) { [void][SSCheck.Native]::EnableDebug() }

# ----------------------------------------------------------------------------
# Interactive users (used by BAM, PSReadLine and recycle bin checks)
# ----------------------------------------------------------------------------
$script:ctxUsers = @{}
function Add-CtxUser {
    param([string]$Sid)
    if (-not $Sid -or $script:ctxUsers.ContainsKey($Sid)) { return }
    $name = $Sid
    try { $name = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
    $prof = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid").ProfileImagePath
    $script:ctxUsers[$Sid] = [pscustomobject]@{ Sid = $Sid; Name = $name; Profile = $prof }
}
Add-CtxUser ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
foreach ($ep in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'")) {
    $o = Invoke-CimMethod -InputObject $ep -MethodName GetOwnerSid
    if ($o -and $o.Sid) { Add-CtxUser ([string]$o.Sid) }
}

# ----------------------------------------------------------------------------
# System overview (boot time first)
# ----------------------------------------------------------------------------
Write-Section 'SYSTEM'
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$bt = $os.LastBootUpTime
if ($bt) {
    $script:BootTime = $bt
    $uptime = (Get-Date) - $bt
    Write-Item 'PC' $env:COMPUTERNAME 'White'
    Write-Item 'USER(S)' (($script:ctxUsers.Values | ForEach-Object { $_.Name }) -join ', ') 'White'
    Write-Item 'OS' ("{0} (build {1})" -f $os.Caption, $os.BuildNumber) 'Gray'
    Write-Item 'BOOTED AT' $bt.ToString('yyyy-MM-dd hh:mm:ss tt') 'Cyan'
    Write-Item 'UPTIME' ('{0}d {1:D2}h {2:D2}m {3:D2}s' -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) 'Cyan'
} else {
    Write-Host "  Unable to retrieve boot time (assuming 24h ago)" -ForegroundColor Red
}
$bootTime = $script:BootTime
$cutoff = $bootTime.AddSeconds($RestartToleranceSec)

$driveText = @()
foreach ($dk in (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 })) {
    $driveText += ("{0}({1})" -f $dk.DeviceID, $dk.FileSystem)
}
Write-Item 'DRIVES' ($driveText -join '  ') 'Green'

# ----------------------------------------------------------------------------
# Recycle bin (parses the $I metadata files for names, original paths and delete times)
# ----------------------------------------------------------------------------
function Get-RecycleBinItems {
    $items = New-Object System.Collections.Generic.List[object]
    $latest = $null
    $binFound = $false
    foreach ($dk in (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in 2, 3 })) {
        $root = $dk.DeviceID + '\$Recycle.Bin'
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $binFound = $true
        $rootItem = Get-Item -LiteralPath $root -Force
        if (-not $latest -or $rootItem.LastWriteTime -gt $latest) { $latest = $rootItem.LastWriteTime }
        foreach ($sd in (Get-ChildItem -LiteralPath $root -Directory -Force)) {
            if ($sd.LastWriteTime -gt $latest) { $latest = $sd.LastWriteTime }
            $files = @(Get-ChildItem -LiteralPath $sd.FullName -File -Force)
            $names = @{}
            foreach ($f in $files) { $names[$f.Name] = $f }
            foreach ($f in $files) {
                if ($f.LastWriteTime -gt $latest) { $latest = $f.LastWriteTime }
                if ($f.Name -like '$I*') {
                    $name = $f.Name; $orig = ''; $size = 0; $del = $null
                    try {
                        $b = [System.IO.File]::ReadAllBytes($f.FullName)
                        if ($b.Length -ge 24) {
                            $ver = [BitConverter]::ToInt64($b, 0)
                            $size = [BitConverter]::ToInt64($b, 8)
                            $ft = [BitConverter]::ToInt64($b, 16)
                            if ($ft -gt 0) { $del = [DateTime]::FromFileTime($ft) }
                            if ($ver -eq 2 -and $b.Length -ge 28) {
                                $len = [BitConverter]::ToInt32($b, 24)
                                $n = [Math]::Min($len * 2, $b.Length - 28)
                                $orig = [System.Text.Encoding]::Unicode.GetString($b, 28, $n)
                            } else {
                                $n = [Math]::Min(520, $b.Length - 24)
                                $orig = [System.Text.Encoding]::Unicode.GetString($b, 24, $n)
                            }
                            $orig = $orig.TrimEnd([char]0)
                            if ($orig) { $name = Split-Path -Path $orig -Leaf }
                        }
                    } catch {}
                    if (-not $del) { $del = $f.LastWriteTime }
                    $items.Add([pscustomobject]@{ Name = $name; Original = $orig; Size = $size; Deleted = $del; Drive = $dk.DeviceID; Orphan = $false })
                } elseif ($f.Name -like '$R*') {
                    $mate = '$I' + $f.Name.Substring(2)
                    if (-not $names.ContainsKey($mate)) {
                        $items.Add([pscustomobject]@{ Name = $f.Name; Original = '(metadata file deleted)'; Size = $f.Length; Deleted = $f.LastWriteTime; Drive = $dk.DeviceID; Orphan = $true })
                    }
                }
            }
        }
    }
    [pscustomobject]@{ Found = $binFound; Latest = $latest; Items = $items }
}

Write-Section 'RECYCLE BIN'
$rb = Get-RecycleBinItems
if (-not $rb.Found) {
    Write-Item 'STATUS' 'Recycle Bin folder not found' 'Yellow'
} else {
    $rbItems = @($rb.Items | Sort-Object Deleted -Descending)
    $sinceBoot = @($rbItems | Where-Object { $_.Deleted -gt $bootTime })
    $orphans = @($rbItems | Where-Object { $_.Orphan })
    if ($rb.Latest -and $rb.Latest -gt $bootTime) {
        Write-Item 'LAST MODIFIED' ((Fmt $rb.Latest) + '   << after boot') $Purple
        Add-Flag ("Recycle Bin modified after boot ({0})" -f (Fmt $rb.Latest))
    } else {
        Write-Item 'LAST MODIFIED' ((Fmt $rb.Latest) + '   (before boot)') 'Green'
    }
    $cnt = 'White'; if ($sinceBoot.Count -gt 0) { $cnt = $Purple }
    Write-Item 'ITEMS' ("{0} total, {1} deleted since boot" -f $rbItems.Count, $sinceBoot.Count) $cnt
    if ($sinceBoot.Count -gt 0) { Add-Flag ("Recycle Bin: {0} item(s) deleted since boot" -f $sinceBoot.Count) }
    if ($rbItems.Count -eq 0 -and $rb.Latest -gt $bootTime) {
        Write-Item '' 'Bin is EMPTY but was modified after boot (emptied?)' $Purple
        Add-Flag 'Recycle Bin emptied after boot'
    }
    if ($orphans.Count -gt 0) {
        Write-Item 'ORPHANED' ("{0} file(s) with no metadata (possible tampering)" -f $orphans.Count) $Purple
        Add-Flag ("Recycle Bin: {0} orphaned `$R file(s)" -f $orphans.Count)
    }
    if ($rbItems.Count -gt 0) {
        Write-Host ""
        Write-Host ("  {0,-20}{1,-11}{2}" -f 'DELETED', 'SIZE', 'NAME  <-  ORIGINAL LOCATION') -ForegroundColor DarkGray
        Write-Rule
        foreach ($it in ($rbItems | Select-Object -First 25)) {
            $col = 'Gray'; if ($it.Deleted -gt $bootTime) { $col = $Purple }
            $line = Trunc $it.Name 38
            if ($it.Original) { $line = "{0}  <-  {1}" -f (Trunc $it.Name 38), (Trunc $it.Original 60) }
            Write-Host ("  {0,-20}{1,-11}{2}" -f (Fmt-Short $it.Deleted), (Format-Size $it.Size), $line) -ForegroundColor $col
        }
        if ($rbItems.Count -gt 25) { Write-Host ("  ... and {0} older item(s) not shown" -f ($rbItems.Count - 25)) -ForegroundColor DarkGray }
    }
}

# ----------------------------------------------------------------------------
# Services (state, start time, restart detection)
# ----------------------------------------------------------------------------
Write-Section 'SERVICES'

$serviceNames = @('SysMain','DiagTrack','PcaSvc','DPS','EventLog','Schedule','WSearch','Bam',
                  'DusmSvc','Appinfo','CDPSvc','CDPUserSvc_*','DcomLaunch','PlugPlay')

$cimMap = @{}
foreach ($c in (Get-CimInstance -ClassName Win32_Service)) { $cimMap[$c.Name] = $c }

# Service Control Manager events since boot (7036 state change, 7040 start type change,
# 7034/7031 crash/unexpected termination)
$scmEvents = @(Get-WinEvent -FilterHashtable @{
    LogName = 'System'; ProviderName = 'Service Control Manager'
    Id = 7036, 7040, 7034, 7031; StartTime = $bootTime } -ErrorAction SilentlyContinue)
$scmLabels = @{ 7036 = 'state change'; 7040 = 'start type changed'; 7034 = 'crashed'; 7031 = 'crashed (recovery)' }

# user services (CDPUserSvc_xxxxx) start at logon, so compare against explorer start
$logonTime = (Get-Process -Name explorer | Sort-Object StartTime | Select-Object -First 1).StartTime

$resolved = @()
foreach ($n in $serviceNames) {
    $found = @(Get-Service -Name $n)
    if ($found.Count -eq 0) { $resolved += [pscustomobject]@{ Name = $n; Svc = $null } }
    else { foreach ($f in $found) { $resolved += [pscustomobject]@{ Name = $f.Name; Svc = $f } } }
}

function Write-SvcRow {
    param([string]$Tag, [string]$TagColor, [string]$Name, [string]$State, [string]$StateColor,
          [string]$Start, [string]$Started, [string]$RowColor = 'Gray')
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host $Tag -NoNewline -ForegroundColor $TagColor
    Write-Host "] " -NoNewline -ForegroundColor DarkGray
    Write-Host ("{0,-18}" -f $Name) -NoNewline -ForegroundColor White
    Write-Host ("{0,-10}" -f $State) -NoNewline -ForegroundColor $StateColor
    Write-Host ("{0,-10}" -f $Start) -NoNewline -ForegroundColor DarkGray
    Write-Host $Started -ForegroundColor $RowColor
}

Write-Host ("  {0,-7}{1,-18}{2,-10}{3,-10}{4}" -f 'STATUS', 'SERVICE', 'STATE', 'START', 'LAST STARTED') -ForegroundColor DarkGray
Write-Rule

$svcPids = @{}
$cntOk = 0; $cntRestart = 0; $cntBad = 0
foreach ($r in $resolved) {
    $svc = $r.Svc
    $name = $r.Name

    if (-not $svc) {
        if ($name -eq 'Bam') {
            $bamStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam').Start
            if ($null -eq $bamStart) {
                Write-SvcRow 'N/A ' 'Red' $name 'Not found' 'Red' 'driver' '' 'Red'
                Add-Flag 'BAM service/driver not found' 'Red'; $cntBad++
            } elseif ($bamStart -eq 4) {
                Write-SvcRow 'DISB' 'Red' $name 'Disabled' 'Red' 'driver' '' 'Red'
                Add-Flag 'BAM driver disabled' 'Red'; $cntBad++
            } else {
                Write-SvcRow ' OK ' 'Green' $name 'Present' 'Green' 'driver' '-'
                $cntOk++
            }
        } else {
            Write-SvcRow 'N/A ' 'Yellow' $name 'Not found' 'Yellow' '-' '-'
        }
        continue
    }

    $cim = $cimMap[$svc.Name]
    $procId = 0
    if ($cim) { $procId = [int]$cim.ProcessId }
    $proc = $null; $started = $null
    if ($procId -gt 0) { $proc = Get-Process -Id $procId; if ($proc) { $started = $proc.StartTime } }

    $state = [string]$svc.Status
    $stateColor = 'Green'
    $tag = ' OK '; $tagColor = 'Green'
    $notes = New-Object System.Collections.Generic.List[string]

    if ($svc.StartType -eq 'Disabled') {
        $state = 'Disabled'; $stateColor = 'Red'; $tag = 'DISB'; $tagColor = 'Red'
        Add-Flag "$($svc.Name) service is DISABLED" 'Red'
    } elseif ($svc.Status -ne 'Running') {
        $stateColor = 'Red'; $tag = 'STOP'; $tagColor = 'Red'
        Add-Flag "$($svc.Name) service is $($svc.Status)" 'Red'
    }

    # restart detection
    $baseline = $cutoff
    if ($svc.Name -like '*_*' -and $logonTime -and $logonTime -gt $bootTime) { $baseline = $logonTime.AddSeconds($RestartToleranceSec) }
    $restarted = $false
    if ($started -and $started -gt $baseline) {
        $restarted = $true
        $notes.Add(("process started {0} after boot (PID {1})" -f ('{0:hh\:mm\:ss}' -f ($started - $bootTime)), $procId))
    }
    $allMine = @($scmEvents | Where-Object {
        $_.Properties.Count -gt 0 -and $_.Properties[0].Value -eq $svc.DisplayName })
    # crashes / start type changes / anything after the tolerance window
    $myEvents = @($allMine | Where-Object { $_.TimeCreated -gt $baseline -or $_.Id -ne 7036 })
    # an auto-start service logs exactly ONE state change per boot (it entering "running").
    # More than one means it was stopped/started again, even inside the tolerance window.
    if ($svc.StartType -eq 'Automatic') {
        $stateChanges = @($allMine | Where-Object { $_.Id -eq 7036 })
        if ($stateChanges.Count -gt 1) { $myEvents = $allMine }
    }
    foreach ($e in ($myEvents | Select-Object -First 4)) {
        $restarted = $true
        $detail = $scmLabels[[int]$e.Id]
        if ($e.Id -eq 7036 -and $e.Properties.Count -gt 1) { $detail = "{0}: {1}" -f $detail, $e.Properties[1].Value }
        $notes.Add(("SCM event {0} ({1}) at {2}" -f $e.Id, $detail, (Fmt $e.TimeCreated)))
    }

    $startText = 'N/A'
    if ($started) { $startText = $started.ToString('MM/dd HH:mm:ss') }
    $display = $svc.Name -replace '_[0-9a-fA-F]+$', '_*'

    if ($restarted) {
        Write-SvcRow 'RSTR' 'Red' $display $state 'Red' ([string]$svc.StartType) ($startText + '   << RESTARTED') 'Red'
        foreach ($note in $notes) { Write-Host ("          - {0}" -f $note) -ForegroundColor Red }
        Add-Flag "$($svc.Name) restarted after boot" 'Red'
        $cntRestart++
    } else {
        Write-SvcRow $tag $tagColor $display $state $stateColor ([string]$svc.StartType) $startText
        if ($tag -eq ' OK ') { $cntOk++ } else { $cntBad++ }
    }

    if ($procId -gt 0) { $svcPids[$svc.Name] = $procId }
}
Write-Rule
$sumColor = 'Green'; if ($cntRestart -gt 0 -or $cntBad -gt 0) { $sumColor = 'Red' }
Write-Host ("  {0} ok   {1} restarted   {2} stopped/disabled/missing" -f $cntOk, $cntRestart, $cntBad) -ForegroundColor $sumColor

# ----------------------------------------------------------------------------
# Suspended threads in service processes (only prints when something is found)
# ----------------------------------------------------------------------------
Write-Section 'SERVICE THREADS'
$hostMap = @{}
foreach ($kv in $svcPids.GetEnumerator()) {
    if (-not $hostMap.ContainsKey($kv.Value)) { $hostMap[$kv.Value] = New-Object System.Collections.Generic.List[string] }
    $hostMap[$kv.Value].Add($kv.Key)
}
$suspFound = $false
foreach ($hostPid in $hostMap.Keys) {
    $hp = Get-Process -Id $hostPid
    if (-not $hp) { continue }
    $suspThreads = @($hp.Threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' })
    if ($suspThreads.Count -eq 0) { continue }
    $suspFound = $true
    $mods = @()
    try { $mods = @($hp.Modules) } catch {}
    Write-Host ("  {0} (PID {1}) hosting: {2}" -f $hp.ProcessName, $hostPid, ($hostMap[$hostPid] -join ', ')) -ForegroundColor $Purple
    foreach ($t in $suspThreads) {
        $start = 0
        if ($nativeOk) { $start = [SSCheck.Native]::GetThreadStart($t.Id) }
        $where = 'unknown start address'
        if ($start -ne 0) {
            $where = ('0x{0:X}' -f $start)
            foreach ($m in $mods) {
                $base = $m.BaseAddress.ToInt64()
                if ($start -ge $base -and $start -lt ($base + $m.ModuleMemorySize)) {
                    $where = ('{0}+0x{1:X}' -f $m.ModuleName, ($start - $base))
                    break
                }
            }
        }
        Write-Host ("    TID {0}: {1}  << SUSPENDED" -f $t.Id, $where) -ForegroundColor $Purple
        Add-Flag ("Suspended thread in {0} (PID {1}): {2}" -f $hp.ProcessName, $hostPid, $where)
    }
}
if (-not $suspFound) { Write-Host '  No suspended threads in service processes.' -ForegroundColor Green }

# ----------------------------------------------------------------------------
# DPS token (privileges + groups)
# ----------------------------------------------------------------------------
Write-Section 'DPS TOKEN'
if (-not $nativeOk) {
    Write-Host '  Native helper failed to compile, token check skipped.' -ForegroundColor Yellow
} elseif (-not $svcPids.ContainsKey('DPS')) {
    Write-Host '  DPS process not found (service not running?)' -ForegroundColor Red
} else {
    $dpsPid = [int]$svcPids['DPS']
    $privs  = [SSCheck.Native]::GetPrivileges($dpsPid)
    $groups = [SSCheck.Native]::GetGroups($dpsPid)
    if ($null -eq $privs -or $null -eq $groups) {
        Write-Host '  DPS : unable to read token' -ForegroundColor Yellow
    } else {
        $problems = @()
        $map = @{}
        foreach ($p in $privs) {
            $i = $p.LastIndexOf(':')
            $map[$p.Substring(0, $i)] = [int]$p.Substring($i + 1)
        }
        foreach ($need in @('SeChangeNotifyPrivilege', 'SeCreateGlobalPrivilege')) {
            if (-not $map.ContainsKey($need)) { $problems += "privilege $need missing" }
        }
        foreach ($k in $map.Keys) {
            $a = $map[$k]
            # enabled by default (1) but not enabled now (2) = "Enabled (modified)" -> disabled
            if (($a -band 1) -ne 0 -and ($a -band 2) -eq 0) { $problems += "privilege $k disabled" }
            if (($a -band 4) -ne 0) { $problems += "privilege $k removed" }
        }
        foreach ($g in $groups) {
            $i = $g.LastIndexOf('|')
            $gname = $g.Substring(0, $i)
            $a = [int]$g.Substring($i + 1)
            # enabled by default (2), not enabled now (4), not deny-only (0x10)
            if (($a -band 2) -ne 0 -and ($a -band 4) -eq 0 -and ($a -band 0x10) -eq 0) {
                $tag = ''
                if (($a -band 8) -ne 0) { $tag = ' (Owner)' }
                $problems += "group $gname$tag disabled"
            }
        }

        if ($problems.Count -gt 0) {
            foreach ($pr in $problems) {
                Write-Host ("  DPS : {0}" -f $pr) -ForegroundColor $Purple
                Add-Flag "DPS token: $pr"
            }
        } else {
            Write-Host '  DPS : token privileges and groups OK' -ForegroundColor Green
        }
    }
}

# ----------------------------------------------------------------------------
# BAM integrity - deleted keys only
# ----------------------------------------------------------------------------
Write-Section 'BAM INTEGRITY (deleted keys)'
$bamSvcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam'
$bamBase = @('SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
             'SYSTEM\CurrentControlSet\Services\bam\UserSettings') |
           Where-Object { Test-Path "HKLM:\$_" } | Select-Object -First 1

if (-not (Test-Path $bamSvcKey)) {
    Write-Host '  bam service key is MISSING (deleted)' -ForegroundColor $Purple
    Add-Flag 'BAM service key deleted'
} elseif (-not $bamBase) {
    Write-Host '  bam UserSettings key is MISSING (deleted)' -ForegroundColor $Purple
    Add-Flag 'BAM UserSettings key deleted'
} else {
    Write-Host '  bam UserSettings key present.' -ForegroundColor Green
    $existing = @{}
    foreach ($k in (Get-ChildItem -LiteralPath "HKLM:\$bamBase")) { $existing[$k.PSChildName] = $k }

    # the interactive user(s) must have a SID key, otherwise it was deleted
    foreach ($u in $script:ctxUsers.Values) {
        if (-not $existing.ContainsKey($u.Sid)) {
            Write-Host ("  {0}: SID key MISSING (deleted)" -f $u.Name) -ForegroundColor $Purple
            Add-Flag ("BAM SID key deleted for {0}" -f $u.Name)
        }
    }

    foreach ($sid in $existing.Keys) {
        $k = $existing[$sid]
        $who = $sid
        try { $who = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch {}

        $valueNames = @($k.GetValueNames() | Where-Object { $_ -notin 'Version', 'SequenceNumber' })
        $newest = $null; $oldest = $null
        foreach ($vn in $valueNames) {
            $v = $k.GetValue($vn)
            if ($v -is [byte[]] -and $v.Length -ge 8) {
                $ft = [BitConverter]::ToInt64($v, 0)
                if ($ft -gt 0) {
                    $dt = [DateTime]::FromFileTime($ft)
                    if (-not $newest -or $dt -gt $newest) { $newest = $dt }
                    if (-not $oldest -or $dt -lt $oldest) { $oldest = $dt }
                }
            }
        }
        $lwTicks = 0
        if ($nativeOk) { $lwTicks = [SSCheck.Native]::GetKeyLastWrite("$bamBase\$sid") }
        $lastWrite = $null
        if ($lwTicks -gt 0) { $lastWrite = [DateTime]::FromFileTime($lwTicks) }

        Write-Host ("  {0}" -f $who) -ForegroundColor White
        Write-Item '  ENTRIES' "$($valueNames.Count)" 'White'
        Write-Item '  OLDEST / NEWEST' ("{0}  /  {1}" -f (Fmt-Short $oldest), (Fmt-Short $newest)) 'Gray'
        Write-Item '  KEY LAST MODIFIED' (Fmt-Short $lastWrite) 'Gray'

        if ($valueNames.Count -eq 0) {
            Write-Host "  << NO ENTRIES (BAM cleared or never populated)" -ForegroundColor $Purple
            Add-Flag "BAM has no entries for $who"
        }
        if ($lastWrite -and $newest -and ($lastWrite - $newest).TotalMinutes -gt $BamGapMinutes) {
            Write-Host ("  << key modified {0:N0} min after newest entry (entries possibly deleted)" -f ($lastWrite - $newest).TotalMinutes) -ForegroundColor $Purple
            Add-Flag "BAM key for $who modified after newest entry (possible deletion)"
        }
    }
}

# ----------------------------------------------------------------------------
# Windows settings
# ----------------------------------------------------------------------------
Write-Section 'WINDOWS SETTINGS'

$settings = @(
    @{ Name = 'CMD';                 Path = 'HKCU:\Software\Policies\Microsoft\Windows\System'; Key = 'DisableCMD'
       Bad = @(1, 2); BadText = 'Disabled'; GoodText = 'Available'; AbsentText = 'Available'; AbsentColor = 'Green' },
    @{ Name = 'Activities Cache';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'EnableActivityFeed'
       Bad = @(0); BadText = 'Disabled'; GoodText = 'Enabled'; AbsentText = 'Enabled (default)'; AbsentColor = 'Green' },
    @{ Name = 'Prefetch';            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'; Key = 'EnablePrefetcher'
       Bad = @(0); BadText = 'Disabled'; GoodText = 'Enabled'; AbsentText = 'Enabled (default)'; AbsentColor = 'Green' },
    @{ Name = 'Jump Lists / Recent'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Key = 'Start_TrackDocs'
       Bad = @(0); BadText = 'Disabled'; GoodText = 'Enabled'; AbsentText = 'Enabled (default)'; AbsentColor = 'Green' }
)

foreach ($s in $settings) {
    $val = (Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue).$($s.Key)
    if ($null -eq $val) {
        Write-Item $s.Name $s.AbsentText $s.AbsentColor
    } elseif ($s.Bad -contains [int]$val) {
        Write-Item $s.Name $s.BadText 'Red'
        Add-Flag "$($s.Name) $($s.BadText)" 'Red'
    } else {
        Write-Item $s.Name $s.GoodText 'Green'
    }
}

# DisablePCA
$detected = @()
foreach ($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat', 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppCompat')) {
    $v = Get-ItemProperty -Path $p -Name 'DisablePCA' -ErrorAction SilentlyContinue
    if ($null -ne $v -and $v.DisablePCA -eq 1) { $detected += $p }
}
if ($detected.Count -gt 0) {
    Write-Item 'DisablePCA' 'Detected' 'Red'
    foreach ($p in $detected) { Write-Item '  Path' $p 'Yellow' }
    Add-Flag 'DisablePCA set' 'Red'
} else {
    Write-Item 'DisablePCA' 'Not detected' 'Green'
}

# jump list / recent files folders
$recent = "$env:APPDATA\Microsoft\Windows\Recent"
$autoDest = Join-Path $recent 'AutomaticDestinations'
$custDest = Join-Path $recent 'CustomDestinations'
if (Test-Path $recent) {
    $lnk = @(Get-ChildItem -Path $recent -Filter *.lnk -Force)
    $lastLnk = $lnk | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Item 'Recent .lnk files' ("{0} (newest {1})" -f $lnk.Count, (Fmt-Short $lastLnk.LastWriteTime)) 'White'
    $ad = @(Get-ChildItem -Path $autoDest -Force)
    $cd = @(Get-ChildItem -Path $custDest -Force)
    $adNew = $ad | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Item 'Jump lists (auto/cust)' ("{0} / {1} (newest auto {2})" -f $ad.Count, $cd.Count, (Fmt-Short $adNew.LastWriteTime)) 'White'
    if ($ad.Count -eq 0 -and $cd.Count -eq 0) {
        Write-Item '' 'Jump list folders are EMPTY (cleared or tracking disabled)' $Purple
        Add-Flag 'Jump list folders empty'
    }
}

# ----------------------------------------------------------------------------
# PowerShell logging (policies + PSReadLine + command history file)
# ----------------------------------------------------------------------------
Write-Section 'POWERSHELL LOGGING'

function Get-PolValue { param([string]$Path, [string]$Name) (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name }
function Show-Policy {
    param([string]$Label, [string]$Path, [string]$Name, [switch]$FlagOff)
    $v = Get-PolValue $Path $Name
    if ($null -eq $v) { Write-Item $Label 'Not configured' 'Yellow' }
    elseif ([int]$v -eq 0) {
        Write-Item $Label 'Disabled' 'Red'
        if ($FlagOff) { Add-Flag "$Label disabled" 'Red' }
    } else { Write-Item $Label 'Enabled' 'Green' }
}
$polRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Show-Policy 'Script block logging' "$polRoot\ScriptBlockLogging" 'EnableScriptBlockLogging' -FlagOff
Show-Policy 'Module logging' "$polRoot\ModuleLogging" 'EnableModuleLogging' -FlagOff
Show-Policy 'Transcription' "$polRoot\Transcription" 'EnableTranscripting'

$psLog = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue
if ($psLog) {
    if ($psLog.IsEnabled) { Write-Item 'PS Operational log' ("Enabled ({0} records)" -f $psLog.RecordCount) 'Green' }
    else { Write-Item 'PS Operational log' 'DISABLED' 'Red'; Add-Flag 'PowerShell Operational event log disabled' 'Red' }
}

# PSReadLine module
$psrl = Get-Module -ListAvailable -Name PSReadLine | Sort-Object Version -Descending | Select-Object -First 1
if ($psrl) {
    Write-Item 'PSReadLine module' ("Installed (v{0})" -f $psrl.Version) 'Green'
    try {
        Import-Module PSReadLine -ErrorAction Stop
        $opt = Get-PSReadLineOption
        if ($opt) {
            $hs = [string]$opt.HistorySaveStyle
            if ($hs -eq 'SaveNothing') {
                Write-Item 'History save style' "$hs  << history NOT saved" $Purple
                Add-Flag 'PSReadLine HistorySaveStyle = SaveNothing'
            } else {
                Write-Item 'History save style' $hs 'Green'
            }
        }
    } catch {
        Write-Item 'History save style' 'could not load PSReadLine in this host' 'Yellow'
    }
} else {
    Write-Item 'PSReadLine module' 'NOT FOUND (command history not logged)' 'Red'
    Add-Flag 'PSReadLine module not found' 'Red'
}

# profile scripts that disable or redirect history
$profFiles = New-Object System.Collections.Generic.List[string]
$profNames = @('profile.ps1', 'Microsoft.PowerShell_profile.ps1', 'Microsoft.VSCode_profile.ps1')
foreach ($n in $profNames) {
    $profFiles.Add((Join-Path $PSHOME $n))
    $profFiles.Add((Join-Path "$env:ProgramFiles\PowerShell\7" $n))
}
foreach ($u in $script:ctxUsers.Values) {
    if (-not $u.Profile) { continue }
    foreach ($docs in @("$($u.Profile)\Documents", "$($u.Profile)\OneDrive\Documents")) {
        foreach ($dir in @('WindowsPowerShell', 'PowerShell')) {
            foreach ($n in $profNames) { $profFiles.Add((Join-Path (Join-Path $docs $dir) $n)) }
        }
    }
}
$profPattern = 'HistorySaveStyle|SaveNothing|HistorySavePath|MaximumHistoryCount|Remove-Module\s+PSReadLine|Set-PSReadLineOption|Clear-History|ConsoleHost_history|Set-PSReadlineKeyHandler'
$profHit = $false
foreach ($pf in ($profFiles | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $pf)) { continue }
    $hits = @(Select-String -LiteralPath $pf -Pattern $profPattern)
    if ($hits.Count -gt 0) {
        $profHit = $true
        Write-Host ("  PROFILE touches history: {0}" -f $pf) -ForegroundColor $Purple
        foreach ($h in ($hits | Select-Object -First 4)) { Write-Host ("      {0}" -f (Trunc $h.Line.Trim() 100)) -ForegroundColor $Purple }
        Add-Flag ("PowerShell profile modifies PSReadLine/history: {0}" -f $pf)
    }
    $pfi = Get-Item -LiteralPath $pf -Force
    if ($pfi.LastWriteTime -gt $bootTime) {
        Write-Host ("  PROFILE modified after boot: {0} ({1})" -f $pf, (Fmt-Short $pfi.LastWriteTime)) -ForegroundColor Yellow
    }
}
if (-not $profHit) { Write-Item 'Profile scripts' 'No history overrides found' 'Green' }

# history files per interactive user
$histPattern = 'Invoke-Expression|\biex\b|\biwr\b|\birm\b|Invoke-WebRequest|DownloadString|DownloadFile|FromBase64String|EncodedCommand|\s-enc\b|Set-MpPreference|Add-MpPreference|wevtutil|Clear-EventLog|Remove-EventLog|fsutil\s+usn|vssadmin|Stop-Service|Set-Service|bcdedit|Set-ExecutionPolicy|Remove-Item.*(Prefetch|Recent|\.pf)|reg(\.exe)?\s+(delete|add)'
foreach ($u in $script:ctxUsers.Values) {
    if (-not $u.Profile) { continue }
    Write-Host ""
    Write-Host ("  History: {0}" -f $u.Name) -ForegroundColor White
    $dir = Join-Path $u.Profile 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
    if (-not (Test-Path -LiteralPath $dir)) {
        Write-Item '  FOLDER' 'PSReadLine folder not found (never used, or deleted)' 'Yellow'
        continue
    }
    $main = Join-Path $dir 'ConsoleHost_history.txt'
    if (-not (Test-Path -LiteralPath $main)) {
        Write-Item '  ConsoleHost_history' 'MISSING (folder exists, file deleted?)' $Purple
        Add-Flag ("ConsoleHost_history.txt missing for {0}" -f $u.Name)
    }
    foreach ($hf in @(Get-ChildItem -LiteralPath $dir -Filter '*_history.txt' -Force)) {
        Write-Item ('  ' + (Trunc $hf.Name 18)) '' 'White'
        $modColor = 'Green'; $modText = 'before boot'
        if ($hf.LastWriteTime -gt $bootTime) { $modText = 'after boot'; $modColor = 'Gray' }
        Write-Item '    CREATED' (Fmt $hf.CreationTime) 'Gray'
        Write-Item '    LAST MODIFIED' ("{0}  ({1})" -f (Fmt $hf.LastWriteTime), $modText) $modColor
        $lines = @(Get-Content -LiteralPath $hf.FullName -ErrorAction SilentlyContinue)
        Write-Item '    SIZE / LINES' ("{0} / {1}" -f (Format-Size $hf.Length), $lines.Count) 'Gray'

        if ($hf.Length -eq 0) {
            Write-Item '    CONTENT' 'EMPTY (cleared?)' $Purple
            Add-Flag ("{0} is empty for {1}" -f $hf.Name, $u.Name)
        }
        $attrBad = $hf.Attributes -band ([System.IO.FileAttributes]::ReadOnly -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
        if ($attrBad) {
            Write-Item '    ATTRIBUTES' ("{0}  << history locked/hidden" -f $hf.Attributes) $Purple
            Add-Flag ("{0} attributes: {1} ({2})" -f $hf.Name, $hf.Attributes, $u.Name)
        } else {
            Write-Item '    ATTRIBUTES' ([string]$hf.Attributes) 'Green'
        }
        $acl = Get-Acl -LiteralPath $hf.FullName
        $deny = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
        if ($deny.Count -gt 0) {
            Write-Item '    ACL' ("{0} DENY rule(s) on history file" -f $deny.Count) $Purple
            Add-Flag ("{0} has DENY ACL rules ({1})" -f $hf.Name, $u.Name)
        }
        $sus = @($lines | Where-Object { $_ -match $histPattern -and $_ -notmatch 'SSCheck|SS-services' })
        if ($sus.Count -gt 0) {
            Write-Item '    SUSPICIOUS CMDS' ("{0} line(s)" -f $sus.Count) $Purple
            foreach ($sl in ($sus | Select-Object -Last 6)) { Write-Host ("      > {0}" -f (Trunc $sl.Trim() 110)) -ForegroundColor $Purple }
            Add-Flag ("{0}: {1} suspicious command(s) in history" -f $hf.Name, $sus.Count)
        }
    }
}

# ----------------------------------------------------------------------------
# Event log checks - CURRENT BOOT ONLY (older records shown as gray context)
# ----------------------------------------------------------------------------
Write-Section 'EVENT LOG CHECKS (this boot)'

function Show-Event {
    param([string]$Log, [int[]]$Ids, [string]$Label, [string]$Provider, [switch]$Flag, [switch]$ShowId, [switch]$Info)
    $f = @{ LogName = $Log; Id = $Ids }
    if ($Provider) { $f.ProviderName = $Provider }
    if (-not $Info) { $f.StartTime = $script:BootTime }
    $evs = @(Get-WinEvent -FilterHashtable $f -MaxEvents 100 -ErrorAction SilentlyContinue)
    Write-Host ("  {0,-44}" -f $Label) -NoNewline -ForegroundColor Gray
    if ($evs.Count -gt 0) {
        $e = $evs[0]
        $txt = Fmt $e.TimeCreated
        if ($ShowId) { $txt = "{0}  (ID {1})" -f $txt, $e.Id }
        if ($evs.Count -gt 1 -and -not $Info) { $txt = "{0}  x{1}" -f $txt, $evs.Count }
        $color = $Purple; if ($Info) { $color = 'Yellow' }
        Write-Host $txt -ForegroundColor $color
        if ($Flag) { Add-Flag ("{0} {1}" -f $Label, (Fmt $e.TimeCreated)) }
    } else {
        Write-Host 'none this boot' -NoNewline -ForegroundColor Green
        if (-not $Info) {
            $f.Remove('StartTime')
            $old = Get-WinEvent -FilterHashtable $f -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($old) { Write-Host ("   (last: {0})" -f (Fmt $old.TimeCreated)) -NoNewline -ForegroundColor DarkGray }
        }
        Write-Host ''
    }
}

$pnp = 'Microsoft-Windows-Kernel-PnP/Configuration'
Show-Event -Log 'Application' -Ids 3079 -Label 'USN Journal deleted' -Flag
Show-Event -Log 'System'      -Ids 104  -Label 'System log cleared' -Flag -ShowId
Show-Event -Log 'Security'    -Ids 1102 -Label 'Security log cleared' -Flag -ShowId
Show-Event -Log 'Security'    -Ids 4616 -Label 'System time changed' -Flag
Show-Event -Log 'System'      -Ids 7045 -Provider 'Service Control Manager' -Label 'Service / driver installed' -Flag
Show-Event -Log 'System'      -Ids 157  -Provider 'disk' -Label 'Disk surprise-removed' -Flag
Show-Event -Log $pnp          -Ids 420  -Label 'Device deleted (Kernel-PnP)' -Flag
Show-Event -Log 'Microsoft-Windows-VHDMP-Operational' -Ids (1..60) -Label 'Virtual disk (VHD/ISO) activity' -Flag
Show-Event -Log 'Microsoft-Windows-TaskScheduler/Operational' -Ids 106, 141, 142 -Label 'Scheduled task created/deleted/disabled' -Flag
Show-Event -Log 'Microsoft-Windows-Windows Defender/Operational' -Ids 5001, 5010, 5012 -Label 'Defender protection disabled' -Flag
Show-Event -Log 'Microsoft-Windows-Windows Defender/Operational' -Ids 1116 -Label 'Defender threat detected' -Flag
Show-Event -Log 'Microsoft-Windows-CodeIntegrity/Operational' -Ids 3001, 3002, 3003, 3004 -Label 'Code Integrity (unsigned/blocked driver)' -Flag
Show-Event -Log 'System'      -Ids 1074 -Label 'Previous shutdown/restart (info)' -Info
Show-Event -Log 'System'      -Ids 6005 -Label 'Event Log service started (info)' -Info

# ----------------------------------------------------------------------------
# Prefetch integrity
# ----------------------------------------------------------------------------
Write-Section 'PREFETCH FILES INTEGRITY'
$pfPath = "$env:SystemRoot\Prefetch"
if (-not (Test-Path $pfPath)) {
    Write-Host '  Could not find the Prefetch folder' -ForegroundColor Red
} else {
    $files = @(Get-ChildItem -Path $pfPath -Filter *.pf -Force)
    if ($files.Count -eq 0) {
        Write-Host '  No prefetch files found. Check the folder.' -ForegroundColor Yellow
        Add-Flag 'Prefetch folder has no .pf files' 'Yellow'
    } else {
        $hashTable = @{}
        $suspicious = @{}
        $hidden = @(); $ro = @(); $both = @()
        foreach ($f in $files) {
            $isH = $f.Attributes -band [System.IO.FileAttributes]::Hidden
            $isR = $f.Attributes -band [System.IO.FileAttributes]::ReadOnly
            if ($isH -and $isR) { $both += $f; $suspicious[$f.Name] = 'Hidden and Read-only' }
            elseif ($isH)       { $hidden += $f; $suspicious[$f.Name] = 'Hidden' }
            elseif ($isR)       { $ro += $f; $suspicious[$f.Name] = 'Read-only' }

            $h = Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
            if ($h) {
                if (-not $hashTable.ContainsKey($h.Hash)) { $hashTable[$h.Hash] = New-Object System.Collections.Generic.List[string] }
                $hashTable[$h.Hash].Add($f.Name)
            }
        }

        if ($both.Count -gt 0)   { Write-Host "  Hidden & Read-only files: $($both.Count)" -ForegroundColor Yellow; $both | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor White } }
        if ($hidden.Count -gt 0) { Write-Host "  Hidden files: $($hidden.Count)" -ForegroundColor Yellow; $hidden | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor White } }
        else { Write-Host '  No hidden files found in Prefetch.' -ForegroundColor Green }
        if ($ro.Count -gt 0)     { Write-Host "  Read-only files: $($ro.Count)" -ForegroundColor Yellow; $ro | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor White } }
        else { Write-Host '  No read-only files found in Prefetch.' -ForegroundColor Green }

        $dups = @($hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })
        if ($dups.Count -gt 0) {
            Write-Host "  Duplicate files: $($dups.Count) set(s)" -ForegroundColor Yellow
            foreach ($d in $dups) {
                foreach ($n in $d.Value) { if (-not $suspicious.ContainsKey($n)) { $suspicious[$n] = 'Duplicate' } }
                Write-Host ("    Duplicate set: {0}" -f ($d.Value -join ', ')) -ForegroundColor White
            }
        } else {
            Write-Host '  No duplicate files found in Prefetch.' -ForegroundColor Green
        }

        if ($suspicious.Count -gt 0) {
            Write-Host ("`n  SUSPICIOUS FILES: {0}/{1}" -f $suspicious.Count, $files.Count) -ForegroundColor Yellow
            Add-Flag "Prefetch: $($suspicious.Count) suspicious file(s)" 'Yellow'
            foreach ($e in ($suspicious.GetEnumerator() | Sort-Object Key)) {
                Write-Host ("    {0} : {1}" -f $e.Key, $e.Value) -ForegroundColor White
            }
        } else {
            Write-Host ("  Prefetch integrity: clean ({0} files checked)" -f $files.Count) -ForegroundColor Green
        }
    }
}

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
Write-Section 'SUMMARY'
if ($script:Flags.Count -eq 0) {
    Write-Host '  No flags raised.' -ForegroundColor Green
} else {
    Write-Host ("  {0} flag(s) raised:" -f $script:Flags.Count) -ForegroundColor $Purple
    foreach ($fl in $script:Flags) { Write-Host ("   - {0}" -f $fl.Text) -ForegroundColor $fl.Color }
}
Write-Host ""
Write-Host "  Flags are indicators, not proof. Verify manually before a verdict." -ForegroundColor DarkGray

# ----------------------------------------------------------------------------
# Event log parser window (optional)
# ----------------------------------------------------------------------------
function Escape-Like {
    param([string]$s)
    $s = $s -replace "'", "''"
    $s = $s -replace '\[', '[[]'
    $s = $s -replace '%', '[%]'
    $s = $s -replace '\*', '[*]'
    return $s
}

function Invoke-EvtQuery {
    param($q)
    $f = @{ LogName = $q.Log }
    if ($q.Ids) { $f.Id = [int[]]$q.Ids }
    if ($q.Provider) { $f.ProviderName = $q.Provider }
    if (-not $q.NoBoot) { $f.StartTime = $script:BootTime }
    $max = 300; if ($q.Max) { $max = [int]$q.Max }
    $fetch = $max; if ($q.Fetch) { $fetch = [int]$q.Fetch }
    $evs = @(Get-WinEvent -FilterHashtable $f -MaxEvents $fetch -ErrorAction SilentlyContinue)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $evs) {
        $msg = $e.Message
        if (-not $msg) { $msg = (($e.Properties | ForEach-Object { $_.Value }) -join ' | ') }
        $msg = ($msg -replace '\s+', ' ').Trim()
        if ($msg.Length -gt 1500) { $msg = $msg.Substring(0, 1500) + '...' }
        if ($q.Match -and $msg -notmatch $q.Match) { continue }
        if ($q.Exclude -and $msg -match $q.Exclude) { continue }
        $imp = $false
        if ($q.Imp) { $imp = $true }
        if ($q.ImpIds -and ($q.ImpIds -contains [int]$e.Id)) { $imp = $true }
        if ($q.ImpMatch -and $msg -match $q.ImpMatch) { $imp = $true }
        $out.Add([pscustomobject]@{ Time = $e.TimeCreated; Id = [int]$e.Id; Source = $e.ProviderName; Details = $msg; Important = $imp })
        if ($out.Count -ge $max) { break }
    }
    return $out
}

function Get-EventCategories {
    $pnpLog = 'Microsoft-Windows-Kernel-PnP/Configuration'
    $cats = [ordered]@{}
    $cats['Tampering'] = @(
        @{ Log = 'System';      Ids = @(104);        Imp = $true },
        @{ Log = 'Security';    Ids = @(1102, 4719); Imp = $true },
        @{ Log = 'Application'; Ids = @(3079);       Imp = $true },
        @{ Log = 'Security';    Ids = @(4616);       Imp = $true },
        @{ Log = 'System'; Provider = 'Microsoft-Windows-Kernel-General'; Ids = @(1) }
    )
    $cats['Disks & drivers'] = @(
        @{ Log = 'System'; Provider = 'disk'; Ids = @(7, 11, 15, 51, 52, 153, 157); ImpIds = @(157) },
        @{ Log = $pnpLog; Ids = @(400, 410, 420, 430); ImpIds = @(420); Max = 400 },
        @{ Log = 'Microsoft-Windows-Partition/Diagnostic'; Ids = @(1006) },
        @{ Log = 'System'; Provider = 'Service Control Manager'; Ids = @(7045); Imp = $true }
    )
    $cats['USB'] = @(
        @{ Log = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'; Ids = @(2003, 2100, 2101, 2102, 2105, 2106); Imp = $true; Max = 200 },
        @{ Log = $pnpLog; Ids = @(400, 410, 420); Match = 'USB'; Imp = $true; Fetch = 2000; Max = 200 }
    )
    $cats['Virtual mounts'] = @(
        @{ Log = 'Microsoft-Windows-VHDMP-Operational'; Imp = $true },
        @{ Log = 'Microsoft-Windows-Partition/Diagnostic'; Ids = @(1006); Match = 'Virtual|VHD|Msft|ISO|CD-ROM'; Imp = $true; Fetch = 1000 },
        @{ Log = $pnpLog; Ids = @(400, 410, 420); Match = 'Msft|Virtual[ _]Disk|VHD|ISO'; Imp = $true; Fetch = 2000; Max = 200 }
    )
    $cats['Services'] = @(
        @{ Log = 'System'; Provider = 'Service Control Manager'; Ids = @(7045, 7040, 7034, 7031, 7030); Imp = $true; Max = 200 },
        @{ Log = 'System'; Provider = 'Service Control Manager'; Ids = @(7036);
           Match = 'SysMain|Superfetch|Diagnostic Policy|Diagnostic Service Host|Diagnostic System Host|Program Compatibility|Windows Event Log|Task Scheduler|Background Activity|Data Usage|Connected Devices|DCOM Server|Plug and Play|Windows Search|Application Information|Telemetry';
           ImpMatch = 'stopped'; Fetch = 3000; Max = 200 }
    )
    $cats['Security'] = @(
        @{ Log = 'Security'; Ids = @(4720, 4722, 4724, 4726, 4732, 4738, 4698, 4699, 4702); Imp = $true },
        @{ Log = 'Security'; Ids = @(4625); Max = 100 },
        @{ Log = 'Security'; Ids = @(4688); Max = 300; ImpMatch = 'wevtutil|fsutil|vssadmin|certutil|bitsadmin|mshta|regsvr32|rundll32' }
    )
    $cats['Scheduled tasks'] = @(
        @{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 140, 141, 142); Imp = $true }
    )
    $cats['Defender'] = @(
        @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012); ImpIds = @(1116, 1117, 5001, 5007, 5010, 5012) }
    )
    $cats['Code integrity'] = @(
        @{ Log = 'Microsoft-Windows-CodeIntegrity/Operational'; Ids = @(3001, 3002, 3003, 3004, 3023, 3033, 3034); Imp = $true }
    )
    $cats['PowerShell'] = @(
        @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4104);
           Match = '\b(iex|iwr|irm)\b|Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|FromBase64String|EncodedCommand|Set-MpPreference|Add-MpPreference|wevtutil|Clear-EventLog|fsutil|Reflection\.Assembly|VirtualAlloc';
           Exclude = 'SSCheck|Winem|SS CHECK|Invoke-EvtQuery|Get-EventCategories'; Imp = $true; Fetch = 3000; Max = 200 }
    )
    $cats['App crashes'] = @(
        @{ Log = 'Application'; Ids = @(1000, 1002); Max = 150; ImpMatch = 'javaw?\.exe|explorer\.exe|svchost\.exe' }
    )
    $cats['Boot / power'] = @(
        @{ Log = 'System'; Ids = @(41, 1074, 6005, 6006, 6008); NoBoot = $true; Max = 30 },
        @{ Log = 'System'; Provider = 'Microsoft-Windows-Kernel-General'; Ids = @(12, 13); NoBoot = $true; Max = 20 }
    )
    return $cats
}

function Show-EventParser {
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        Write-Host "  This PowerShell host is not STA. Re-run with: powershell.exe -STA" -ForegroundColor Yellow
        return
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $cats = Get-EventCategories
    $tables = [ordered]@{}
    $i = 0
    foreach ($name in $cats.Keys) {
        $i++
        Write-Progress -Activity 'Parsing event logs (this boot)' -Status $name -PercentComplete ([int](100 * $i / ($cats.Count + 1)))
        $dt = New-Object System.Data.DataTable
        [void]$dt.Columns.Add('Time', [datetime])
        [void]$dt.Columns.Add('Id', [int])
        [void]$dt.Columns.Add('Source', [string])
        [void]$dt.Columns.Add('Details', [string])
        [void]$dt.Columns.Add('Important', [bool])
        foreach ($q in $cats[$name]) {
            foreach ($r in (Invoke-EvtQuery $q)) {
                [void]$dt.Rows.Add($r.Time, $r.Id, $r.Source, $r.Details, $r.Important)
            }
        }
        if ($name -eq 'USB' -and $nativeOk) {
            $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
            foreach ($dev in @(Get-ChildItem -Path $root)) {
                foreach ($inst in @(Get-ChildItem -LiteralPath $dev.PSPath)) {
                    $sub = "SYSTEM\CurrentControlSet\Enum\USBSTOR\{0}\{1}" -f $dev.PSChildName, $inst.PSChildName
                    $lw = [SSCheck.Native]::GetKeyLastWrite($sub)
                    if ($lw -le 0) { continue }
                    $t = [DateTime]::FromFileTime($lw)
                    $friendly = (Get-ItemProperty -LiteralPath $inst.PSPath).FriendlyName
                    $detail = "{0}  |  serial {1}  |  registry key last write (not event-based)" -f $friendly, $inst.PSChildName
                    [void]$dt.Rows.Add($t, 0, 'Registry USBSTOR', $detail, ($t -gt $script:BootTime))
                }
            }
        }
        $tables[$name] = $dt
    }
    Write-Progress -Activity 'Parsing event logs (this boot)' -Completed

    # "Important" overview tab = every flagged row from all tabs
    $imp = New-Object System.Data.DataTable
    [void]$imp.Columns.Add('Time', [datetime])
    [void]$imp.Columns.Add('Id', [int])
    [void]$imp.Columns.Add('Source', [string])
    [void]$imp.Columns.Add('Details', [string])
    [void]$imp.Columns.Add('Important', [bool])
    foreach ($name in $tables.Keys) {
        foreach ($row in $tables[$name].Rows) {
            if ($row['Important']) {
                [void]$imp.Rows.Add($row['Time'], $row['Id'], ("[{0}] {1}" -f $name, $row['Source']), $row['Details'], $true)
            }
        }
    }
    $all = [ordered]@{}
    $all['Important'] = $imp
    foreach ($name in $tables.Keys) { $all[$name] = $tables[$name] }

    # ---- window
    $bg   = [System.Drawing.Color]::FromArgb(20, 22, 28)
    $bg2  = [System.Drawing.Color]::FromArgb(31, 36, 48)
    $fg   = [System.Drawing.Color]::FromArgb(230, 232, 238)
    $impB = [System.Drawing.Color]::FromArgb(74, 22, 32)
    $impF = [System.Drawing.Color]::FromArgb(255, 179, 189)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'SS CHECK - Event Log Parser (current boot)'
    $form.Size = New-Object System.Drawing.Size(1320, 780)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = $bg
    $form.ForeColor = $fg
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $script:evViews = New-Object System.Collections.Generic.List[object]
    $script:evNames = New-Object System.Collections.Generic.List[string]

    foreach ($name in $all.Keys) {
        $dtab = $all[$name]
        $dv = New-Object System.Data.DataView($dtab)
        $dv.Sort = 'Time DESC'
        $script:evViews.Add($dv)
        $script:evNames.Add($name)

        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock = 'Fill'
        $grid.ReadOnly = $true
        $grid.AllowUserToAddRows = $false
        $grid.AllowUserToDeleteRows = $false
        $grid.RowHeadersVisible = $false
        $grid.SelectionMode = 'FullRowSelect'
        $grid.BorderStyle = 'None'
        $grid.BackgroundColor = $bg
        $grid.GridColor = $bg2
        $grid.EnableHeadersVisualStyles = $false
        $grid.ColumnHeadersDefaultCellStyle.BackColor = $bg2
        $grid.ColumnHeadersDefaultCellStyle.ForeColor = $fg
        $grid.ColumnHeadersHeight = 28
        $grid.DefaultCellStyle.BackColor = $bg
        $grid.DefaultCellStyle.ForeColor = $fg
        $grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(52, 74, 130)
        $grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
        $grid.DataSource = $dv
        $grid.AutoSizeColumnsMode = 'None'
        $grid.Columns['Time'].Width = 160
        $grid.Columns['Time'].DefaultCellStyle.Format = 'MM/dd/yyyy hh:mm:ss tt'
        $grid.Columns['Id'].Width = 60
        $grid.Columns['Source'].Width = 240
        $grid.Columns['Important'].Visible = $false
        $grid.Columns['Details'].AutoSizeMode = 'Fill'
        $grid.Add_DataBindingComplete({
            param($s, $e)
            foreach ($r in $s.Rows) {
                $item = $r.DataBoundItem
                if ($item -and $item['Important'] -eq $true) {
                    $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(74, 22, 32)
                    $r.DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255, 179, 189)
                }
            }
        })
        $grid.Add_CellDoubleClick({
            param($s, $e)
            if ($e.RowIndex -ge 0) {
                $txt = "{0}`r`nID {1} - {2}`r`n`r`n{3}" -f $s.Rows[$e.RowIndex].Cells['Time'].Value, $s.Rows[$e.RowIndex].Cells['Id'].Value, $s.Rows[$e.RowIndex].Cells['Source'].Value, $s.Rows[$e.RowIndex].Cells['Details'].Value
                [void][System.Windows.Forms.MessageBox]::Show($txt, 'Event details')
            }
        })

        $page = New-Object System.Windows.Forms.TabPage
        $page.Text = ("{0} ({1})" -f $name, $dtab.Rows.Count)
        $page.BackColor = $bg
        $page.Controls.Add($grid)
        $tabs.TabPages.Add($page)
    }

    $top = New-Object System.Windows.Forms.Panel
    $top.Dock = 'Top'
    $top.Height = 48
    $top.BackColor = $bg2

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.AutoSize = $true
    $lbl.Location = New-Object System.Drawing.Point(12, 15)
    $lbl.Text = ("Boot: {0}   |   important: {1}" -f $script:BootTime.ToString('yyyy-MM-dd hh:mm tt'), $imp.Rows.Count)
    $top.Controls.Add($lbl)

    $filterBox = New-Object System.Windows.Forms.TextBox
    $filterBox.Location = New-Object System.Drawing.Point(430, 12)
    $filterBox.Width = 300
    $filterBox.BackColor = $bg
    $filterBox.ForeColor = $fg
    $top.Controls.Add($filterBox)

    $hint = New-Object System.Windows.Forms.Label
    $hint.AutoSize = $true
    $hint.Location = New-Object System.Drawing.Point(738, 15)
    $hint.Text = '<- filter (source / details / id)'
    $hint.ForeColor = [System.Drawing.Color]::Gray
    $top.Controls.Add($hint)

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = 'Export tab to CSV'
    $btn.Width = 130
    $btn.Location = New-Object System.Drawing.Point(1000, 10)
    $btn.FlatStyle = 'Flat'
    $btn.BackColor = $bg
    $btn.ForeColor = $fg
    $top.Controls.Add($btn)

    $script:evFilterBox = $filterBox
    $script:evTabs = $tabs
    $filterBox.Add_TextChanged({
        $t = Escape-Like $script:evFilterBox.Text
        foreach ($v in $script:evViews) {
            if ($t) { $v.RowFilter = "Details LIKE '%$t%' OR Source LIKE '%$t%' OR Convert(Id, 'System.String') LIKE '%$t%'" }
            else { $v.RowFilter = '' }
        }
    })

    $btn.Add_Click({
        $idx = $script:evTabs.SelectedIndex
        if ($idx -lt 0) { return }
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter = 'CSV (*.csv)|*.csv'
        $dlg.FileName = ("SSCheck_{0}.csv" -f ($script:evNames[$idx] -replace '[^A-Za-z0-9]+', '_'))
        if ($dlg.ShowDialog() -eq 'OK') {
            $rows = foreach ($r in $script:evViews[$idx]) {
                [pscustomobject]@{ Time = $r['Time']; Id = $r['Id']; Source = $r['Source']; Details = $r['Details']; Important = $r['Important'] }
            }
            $rows | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8
        }
    })

    # the Fill control is added first, then the Top panel, so docking resolves correctly
    $form.Controls.Add($tabs)
    $form.Controls.Add($top)
    [void]$form.ShowDialog()
    $form.Dispose()
}

Write-Host ""
Write-Host "  Parse event logs now? A window will open with disk/USB/virtual-mount" -ForegroundColor Cyan
Write-Host "  and other system, security and application events from THIS BOOT." -ForegroundColor Cyan
$ans = Read-Host "  (Y/N)"
if ($ans -match '^\s*(y|yes)\s*$') {
    Show-EventParser
}

Write-Host ""
Write-Host "Check complete. Made by Winem. DM null.mood for assistance." -ForegroundColor Magenta
Write-Host ""

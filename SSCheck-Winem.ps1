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

    The console shows the classic event log summary. Everything else from the event logs
    (disks, USB, virtual mounts, services, defender, code integrity, ...) lives in the
    Event Logs Parser window at the end.
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
    $w = 54
    $edge = '+' + ('-' * $w) + '+'
    $l1 = '   M A D E   B Y   W I N E M'
    $l2 = '   DM null.mood for assistance'
    Write-Host ""
    Write-Host $edge -ForegroundColor DarkMagenta
    Write-Host '|' -NoNewline -ForegroundColor DarkMagenta
    Write-Host $l1.PadRight($w) -NoNewline -ForegroundColor Magenta
    Write-Host '|' -ForegroundColor DarkMagenta
    Write-Host '|' -NoNewline -ForegroundColor DarkMagenta
    Write-Host $l2.PadRight($w) -NoNewline -ForegroundColor White
    Write-Host '|' -ForegroundColor DarkMagenta
    Write-Host $edge -ForegroundColor DarkMagenta
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
# Banner + admin check
# ----------------------------------------------------------------------------
Write-Banner

Write-Section 'ADMIN CHECK'
$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Administrator privileges REQUIRED. Re-run this script as Administrator.' -ForegroundColor Red
    exit
}
Write-Host 'Administrator privileges confirmed.' -ForegroundColor Green
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
# PowerShell logging (clear status + policies + PSReadLine + command history file)
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
$sblVal = Get-PolValue "$polRoot\ScriptBlockLogging" 'EnableScriptBlockLogging'
$modVal = Get-PolValue "$polRoot\ModuleLogging" 'EnableModuleLogging'
$psLog = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue

# one clear verdict first
$logOff = New-Object System.Collections.Generic.List[string]
if ($null -ne $sblVal -and [int]$sblVal -eq 0) { $logOff.Add('script block logging policy is set to 0') }
if ($null -ne $modVal -and [int]$modVal -eq 0) { $logOff.Add('module logging policy is set to 0') }
if ($psLog -and -not $psLog.IsEnabled) { $logOff.Add('PowerShell Operational event log is disabled') }
if (-not $psLog) {
    Write-Item 'LOGGING STATUS' 'UNKNOWN (could not query the Operational log)' 'Yellow'
} elseif ($logOff.Count -gt 0) {
    Write-Item 'LOGGING STATUS' 'DISABLED' 'Red'
    foreach ($lo in $logOff) { Write-Item '' ("- {0}" -f $lo) 'Red' }
} else {
    Write-Item 'LOGGING STATUS' 'ENABLED' 'Green'
    if ($null -eq $sblVal) { Write-Item '' '- script block logging not configured (Windows default)' 'Yellow' }
}
Write-Host ""

Show-Policy 'Script block logging' "$polRoot\ScriptBlockLogging" 'EnableScriptBlockLogging' -FlagOff
Show-Policy 'Module logging' "$polRoot\ModuleLogging" 'EnableModuleLogging' -FlagOff
Show-Policy 'Transcription' "$polRoot\Transcription" 'EnableTranscripting'

if ($psLog) {
    if ($psLog.IsEnabled) { Write-Item 'PS Operational log' ("Enabled ({0} records)" -f $psLog.RecordCount) 'Green' }
    else { Write-Item 'PS Operational log' 'DISABLED' 'Red'; Add-Flag 'PowerShell Operational event log disabled' 'Red' }
}

# PSReadLine module
$histOff = $false
$psrl = Get-Module -ListAvailable -Name PSReadLine | Sort-Object Version -Descending | Select-Object -First 1
if ($psrl) {
    Write-Item 'PSReadLine module' ("Installed (v{0})" -f $psrl.Version) 'Green'
    try {
        Import-Module PSReadLine -ErrorAction Stop
        $opt = Get-PSReadLineOption
        if ($opt) {
            $hs = [string]$opt.HistorySaveStyle
            if ($hs -eq 'SaveNothing') {
                $histOff = $true
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
    $histOff = $true
    Write-Item 'PSReadLine module' 'NOT FOUND (command history not logged)' 'Red'
    Add-Flag 'PSReadLine module not found' 'Red'
}
if ($histOff) { Write-Item 'HISTORY LOGGING' 'DISABLED' 'Red' }
else { Write-Item 'HISTORY LOGGING' 'ENABLED' 'Green' }

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
# Event log checks - classic summary (everything else is in the parser window)
# ----------------------------------------------------------------------------
Write-Section 'EVENT LOG CHECKS'

function Show-LastEvent {
    param([string]$Log, [int[]]$Ids, [string]$Found, [string]$None, [string]$Provider,
          [ValidateSet('Tamper', 'Info')][string]$Kind = 'Tamper')
    $f = @{ LogName = $Log; Id = $Ids }
    if ($Provider) { $f.ProviderName = $Provider }
    $e = Get-WinEvent -FilterHashtable $f -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $e) {
        Write-Host $None -ForegroundColor Green
        return
    }
    $t = $e.TimeCreated
    $text = "{0} {1}" -f $Found, (Fmt $t)
    if ($Kind -eq 'Info') {
        Write-Host $text -ForegroundColor Cyan
    } elseif ($t -gt $script:BootTime) {
        Write-Host ($text + '   << after boot') -ForegroundColor $Purple
        Add-Flag ("{0} {1}" -f $Found.TrimEnd(':'), (Fmt $t))
    } else {
        Write-Host $text -ForegroundColor Yellow
    }
}

Show-LastEvent -Log 'Application' -Ids 3079 -Found 'USN Journal last deleted at:' -None 'USN Journal last deleted - no records found'
Show-LastEvent -Log 'System'      -Ids 104  -Found 'Event Logs last cleared (System log) (Event ID: 104) at:' -None 'Event Logs last cleared (System log) - no records found'
Show-LastEvent -Log 'Security'    -Ids 1102 -Found 'Security log last cleared at:' -None 'Security log last cleared - no records found'
Show-LastEvent -Log 'System'      -Ids 1074 -Found 'User recent PC shutdown at:' -None 'User recent PC shutdown - no records found' -Kind Info
Show-LastEvent -Log 'Security'    -Ids 4616 -Found 'System time changed at:' -None 'System time changed - no records found'
Show-LastEvent -Log 'System'      -Ids 6005 -Found 'Event Log Service started at:' -None 'Event Log Service started - no records found' -Kind Info
Show-LastEvent -Log 'Microsoft-Windows-Kernel-PnP/Configuration' -Ids 400 -Found 'Device configuration changed at:' -None 'Device configuration changed - no records found' -Kind Info

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
# Event Logs Parser window (optional)
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

# ---- GUI helpers (script scope so event handlers can reach them) -------------
function Rgb { param([int]$r, [int]$g, [int]$b) [System.Drawing.Color]::FromArgb($r, $g, $b) }

function Update-EvStatus {
    $name = $script:evCurrent
    if (-not $name) { return }
    $shown = $script:evViews[$name].Count
    $total = $script:evTables[$name].Rows.Count
    $script:evStatus.Text = ("  {0}   |   showing {1} of {2} event(s)   |   Ctrl+F search   |   click a column header to sort" -f $name, $shown, $total)
}

function Update-EvDetail {
    $g = $script:evGrid
    $row = $g.CurrentRow
    if (-not $row -or -not $row.DataBoundItem) {
        $script:evDetail.Text = 'Select an event to see its full details here.'
        return
    }
    $r = $row.DataBoundItem
    $flag = ''
    if ($r['Important'] -eq $true) { $flag = '    [IMPORTANT]' }
    $script:evDetail.Text = ("{0}    |    Event ID {1}    |    {2}{3}`r`n`r`n{4}" -f ([datetime]$r['Time']).ToString('MM/dd/yyyy hh:mm:ss tt'), $r['Id'], $r['Source'], $flag, $r['Details'])
}

function Update-EvFilter {
    $t = Escape-Like $script:evSearch.Text
    $parts = @()
    if ($t) { $parts += "(Details LIKE '%$t%' OR Source LIKE '%$t%' OR Convert(Id, 'System.String') LIKE '%$t%')" }
    if ($script:evImpOnly.Checked) { $parts += 'Important = true' }
    $flt = $parts -join ' AND '
    foreach ($k in $script:evViews.Keys) {
        $script:evViews[$k].RowFilter = $flt
        $script:evBtns[$k].Count = [string]$script:evViews[$k].Count
        $script:evBtns[$k].Invalidate()
    }
    Update-EvStatus
    Update-EvDetail
}

function Set-EvTab {
    param([string]$Name)
    $script:evCurrent = $Name
    foreach ($k in $script:evBtns.Keys) {
        $script:evBtns[$k].Active = ($k -eq $Name)
        $script:evBtns[$k].Invalidate()
    }
    $script:evGrid.DataSource = $script:evViews[$Name]
    Update-EvStatus
    Update-EvDetail
}

function Export-EvTab {
    $name = $script:evCurrent
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = ("EventLogs_{0}.csv" -f ($name -replace '[^A-Za-z0-9]+', '_'))
    if ($dlg.ShowDialog() -eq 'OK') {
        $rows = foreach ($r in $script:evViews[$name]) {
            [pscustomobject]@{ Time = $r['Time']; Id = $r['Id']; Source = $r['Source']; Details = $r['Details']; Important = $r['Important'] }
        }
        $rows | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8
    }
}

function Export-EvAll {
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = 'EventLogs_All.csv'
    if ($dlg.ShowDialog() -eq 'OK') {
        $rows = foreach ($name in $script:evTables.Keys) {
            if ($name -eq 'Important') { continue }
            foreach ($r in $script:evTables[$name].Rows) {
                [pscustomobject]@{ Category = $name; Time = $r['Time']; Id = $r['Id']; Source = $r['Source']; Details = $r['Details']; Important = $r['Important'] }
            }
        }
        $rows | Sort-Object Time -Descending | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8
    }
}

$script:UiSource = @'
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace SSCheck {
    public static class Gfx {
        public static GraphicsPath Round(RectangleF r, float rad) {
            GraphicsPath p = new GraphicsPath();
            float d = rad * 2f;
            if (rad <= 0f || d > r.Width || d > r.Height) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static void Glow(Graphics g, float cx, float cy, float rad, Color c, int alpha) {
            using (GraphicsPath gp = new GraphicsPath()) {
                gp.AddEllipse(cx - rad, cy - rad, rad * 2f, rad * 2f);
                using (PathGradientBrush pb = new PathGradientBrush(gp)) {
                    pb.CenterColor = Color.FromArgb(alpha, c);
                    pb.SurroundColors = new Color[] { Color.FromArgb(0, c) };
                    g.FillPath(pb, gp);
                }
            }
        }
    }

    // Animated holographic purple background with the window header painted on it
    public class HoloPanel : Panel {
        public float Phase = 0f;
        public string Title = "";
        public string Subtitle = "";
        public string[] Chips = new string[0];

        public HoloPanel() {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e) {
            Graphics g = e.Graphics;
            Rectangle rc = ClientRectangle;
            if (rc.Width < 4 || rc.Height < 4) return;
            float w = rc.Width, h = rc.Height;

            // iridescent base: deep indigo -> violet -> magenta -> icy cyan glint -> violet
            g.SmoothingMode = SmoothingMode.None;
            using (LinearGradientBrush b = new LinearGradientBrush(rc, Color.Black, Color.Black, 24f)) {
                ColorBlend cb = new ColorBlend();
                cb.Colors = new Color[] {
                    Color.FromArgb(14, 8, 34), Color.FromArgb(48, 18, 104), Color.FromArgb(110, 48, 200), Color.FromArgb(182, 74, 216),
                    Color.FromArgb(78, 176, 232), Color.FromArgb(124, 58, 212), Color.FromArgb(42, 14, 92), Color.FromArgb(14, 8, 34) };
                cb.Positions = new float[] { 0f, 0.16f, 0.34f, 0.5f, 0.62f, 0.78f, 0.9f, 1f };
                b.InterpolationColors = cb;
                b.WrapMode = WrapMode.TileFlipXY;
                b.TranslateTransform(Phase * w, 0f);
                g.FillRectangle(b, rc);
            }

            g.SmoothingMode = SmoothingMode.AntiAlias;
            Gfx.Glow(g, w * (0.16f + Phase), 30f, 280f, Color.FromArgb(255, 70, 200), 80);
            Gfx.Glow(g, w * (0.60f - Phase), 20f, 320f, Color.FromArgb(70, 210, 255), 62);
            Gfx.Glow(g, w * (0.92f + Phase * 0.5f), h * 0.85f, 360f, Color.FromArgb(150, 80, 255), 80);
            Gfx.Glow(g, w * 0.05f, h * 0.95f, 300f, Color.FromArgb(220, 80, 255), 60);

            // fine scanlines for the hologram feel
            g.SmoothingMode = SmoothingMode.None;
            using (Pen sp = new Pen(Color.FromArgb(34, 0, 0, 0), 1f)) {
                for (int y = 0; y < rc.Height; y += 3) g.DrawLine(sp, 0, y, rc.Width, y);
            }
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // title with soft glow and gradient fill
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
            using (GraphicsPath tp = new GraphicsPath()) {
                using (FontFamily ff = new FontFamily("Segoe UI")) {
                    tp.AddString(Title, ff, (int)FontStyle.Bold, 25f, new PointF(26f, 15f), StringFormat.GenericTypographic);
                }
                RectangleF tb = tp.GetBounds();
                using (Pen glow = new Pen(Color.FromArgb(70, 230, 130, 255), 7f)) {
                    glow.LineJoin = LineJoin.Round;
                    g.DrawPath(glow, tp);
                }
                if (tb.Width > 2f) {
                    using (LinearGradientBrush tg = new LinearGradientBrush(new RectangleF(tb.X, tb.Y, tb.Width, tb.Height + 1f), Color.White, Color.White, 0f)) {
                        ColorBlend tc = new ColorBlend();
                        tc.Colors = new Color[] { Color.FromArgb(240, 232, 255), Color.FromArgb(160, 232, 255), Color.FromArgb(196, 150, 255), Color.FromArgb(255, 150, 224) };
                        tc.Positions = new float[] { 0f, 0.35f, 0.7f, 1f };
                        tg.InterpolationColors = tc;
                        g.FillPath(tg, tp);
                    }
                }
            }

            using (Font sf = new Font("Segoe UI", 9.5f))
            using (SolidBrush sb = new SolidBrush(Color.FromArgb(222, 208, 255))) {
                g.DrawString(Subtitle, sf, sb, 28f, 64f);
            }

            // stat chips, right aligned
            float x = w - 26f;
            using (Font cf = new Font("Segoe UI Semibold", 9f)) {
                for (int i = Chips.Length - 1; i >= 0; i--) {
                    string t = Chips[i];
                    bool hot = t.StartsWith("!");
                    if (hot) t = t.Substring(1);
                    SizeF sz = g.MeasureString(t, cf);
                    float cw = sz.Width + 28f;
                    RectangleF cr = new RectangleF(x - cw, 22f, cw, 30f);
                    x -= cw + 10f;
                    using (GraphicsPath cp = Gfx.Round(cr, 15f)) {
                        using (SolidBrush fb = new SolidBrush(hot ? Color.FromArgb(160, 120, 18, 72) : Color.FromArgb(120, 14, 8, 36))) g.FillPath(fb, cp);
                        using (Pen bp = new Pen(hot ? Color.FromArgb(255, 110, 170) : Color.FromArgb(170, 150, 120, 255), 1.2f)) g.DrawPath(bp, cp);
                    }
                    using (SolidBrush ts = new SolidBrush(hot ? Color.FromArgb(255, 214, 232) : Color.FromArgb(238, 228, 255))) {
                        g.DrawString(t, cf, ts, cr.X + 14f, cr.Y + 6f);
                    }
                }
            }
        }
    }

    // Sidebar category pill (Side = true) or gradient action button (Side = false)
    public class HoloButton : Button {
        public string Caption = "";
        public string Count = "";
        public bool Active = false;
        public bool Side = false;
        public bool Hot = false;
        private bool hover = false;

        public HoloButton() {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            TabStop = false;
            Cursor = Cursors.Hand;
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnPaint(PaintEventArgs pe) {
            Graphics g = pe.Graphics;
            g.Clear(BackColor);
            if (Width < 8 || Height < 8) return;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            RectangleF r = new RectangleF(1f, 1f, Width - 3f, Height - 3f);
            Color accent = Hot ? Color.FromArgb(255, 96, 160) : Color.FromArgb(160, 100, 255);

            using (StringFormat sf = new StringFormat()) {
                sf.LineAlignment = StringAlignment.Center;
                sf.Trimming = StringTrimming.EllipsisCharacter;
                sf.FormatFlags = StringFormatFlags.NoWrap;

                if (Side) {
                    if (Active) {
                        using (GraphicsPath gp = Gfx.Round(r, 9f))
                        using (LinearGradientBrush lb = new LinearGradientBrush(r, Color.FromArgb(120, accent), Color.FromArgb(16, accent), 0f)) {
                            g.FillPath(lb, gp);
                        }
                        using (SolidBrush ab = new SolidBrush(accent)) { g.FillRectangle(ab, 1f, 8f, 3f, Height - 17f); }
                    } else if (hover) {
                        using (GraphicsPath gp = Gfx.Round(r, 9f))
                        using (SolidBrush hb = new SolidBrush(Color.FromArgb(26, 190, 160, 255))) {
                            g.FillPath(hb, gp);
                        }
                    }
                    Color tcol = Active ? Color.White : Color.FromArgb(198, 186, 238);
                    using (Font f = new Font("Segoe UI", 9.5f, Active ? FontStyle.Bold : FontStyle.Regular))
                    using (SolidBrush tbr = new SolidBrush(tcol)) {
                        g.DrawString(Caption, f, tbr, new RectangleF(16f, 0f, Width - 74f, Height), sf);
                    }
                    if (Count.Length > 0) {
                        bool zero = (Count == "0");
                        using (Font cf = new Font("Segoe UI Semibold", 8.5f))
                        using (StringFormat cs = new StringFormat()) {
                            cs.Alignment = StringAlignment.Center;
                            cs.LineAlignment = StringAlignment.Center;
                            SizeF sz = g.MeasureString(Count, cf);
                            float bw = Math.Max(28f, sz.Width + 14f);
                            RectangleF br = new RectangleF(Width - bw - 10f, (Height - 20f) / 2f, bw, 20f);
                            Color fill = zero ? Color.FromArgb(40, 150, 130, 200) : Color.FromArgb(Active ? 230 : 150, accent);
                            using (GraphicsPath bp = Gfx.Round(br, 10f))
                            using (SolidBrush bb = new SolidBrush(fill)) {
                                g.FillPath(bb, bp);
                            }
                            using (SolidBrush cb = new SolidBrush(zero ? Color.FromArgb(150, 140, 190) : Color.White)) {
                                g.DrawString(Count, cf, cb, br, cs);
                            }
                        }
                    }
                } else {
                    Color c1 = hover ? Color.FromArgb(152, 102, 255) : Color.FromArgb(118, 70, 230);
                    Color c2 = hover ? Color.FromArgb(236, 92, 214) : Color.FromArgb(190, 64, 190);
                    using (GraphicsPath gp = Gfx.Round(r, 10f))
                    using (LinearGradientBrush lb = new LinearGradientBrush(r, c1, c2, 0f)) {
                        g.FillPath(lb, gp);
                    }
                    sf.Alignment = StringAlignment.Center;
                    using (Font f = new Font("Segoe UI Semibold", 9.5f))
                    using (SolidBrush tb = new SolidBrush(Color.White)) {
                        g.DrawString(Caption, f, tb, new RectangleF(0f, 0f, Width, Height), sf);
                    }
                }
            }
        }
    }

    // Text box with a grey placeholder (cue banner)
    public class CueTextBox : TextBox {
        public string Cue = "";
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);
        protected override void OnHandleCreated(EventArgs e) {
            base.OnHandleCreated(e);
            if (Cue.Length > 0) SendMessage(Handle, 0x1501, (IntPtr)1, Cue);
        }
    }
}
'@

function Show-EventParser {
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        Write-Host "  This PowerShell host is not STA. Re-run with: powershell.exe -STA" -ForegroundColor Yellow
        return
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    if (-not ('SSCheck.HoloPanel' -as [type])) {
        try {
            Add-Type -TypeDefinition $script:UiSource -ReferencedAssemblies 'System.Windows.Forms', 'System.Drawing' -ErrorAction Stop
        } catch {
            Write-Host "  Could not build the parser window: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    # ---- collect events
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

    # "Important" overview = every flagged row from all tabs
    $imp = New-Object System.Data.DataTable
    [void]$imp.Columns.Add('Time', [datetime])
    [void]$imp.Columns.Add('Id', [int])
    [void]$imp.Columns.Add('Source', [string])
    [void]$imp.Columns.Add('Details', [string])
    [void]$imp.Columns.Add('Important', [bool])
    $totalEvents = 0
    foreach ($name in $tables.Keys) {
        $totalEvents += $tables[$name].Rows.Count
        foreach ($row in $tables[$name].Rows) {
            if ($row['Important']) {
                [void]$imp.Rows.Add($row['Time'], $row['Id'], ("[{0}] {1}" -f $name, $row['Source']), $row['Details'], $true)
            }
        }
    }
    $script:evTables = [ordered]@{}
    $script:evTables['Important'] = $imp
    foreach ($name in $tables.Keys) { $script:evTables[$name] = $tables[$name] }

    $script:evViews = [ordered]@{}
    foreach ($name in $script:evTables.Keys) {
        $dv = New-Object System.Data.DataView($script:evTables[$name])
        $dv.Sort = 'Time DESC'
        $script:evViews[$name] = $dv
    }

    # ---- palette
    $cBg     = Rgb 14 8 32
    $cCard   = Rgb 17 10 36
    $cSide   = Rgb 13 8 29
    $cField  = Rgb 32 21 64
    $cRow    = Rgb 21 13 43
    $cRowAlt = Rgb 26 17 51
    $cText   = Rgb 232 224 255
    $cDim    = Rgb 150 132 205

    # ---- window
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Event Logs Parser'
    $form.Size = New-Object System.Drawing.Size(1380, 840)
    $form.MinimumSize = New-Object System.Drawing.Size(1020, 640)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = $cBg
    $form.ForeColor = $cText
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.KeyPreview = $true

    # holographic background + header (painted by the control)
    $holo = New-Object SSCheck.HoloPanel
    $holo.Dock = 'Fill'
    $holo.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 22, 106, 22, 22
    $titleText = (('Event Logs Parser'.ToUpper() -split ' ' | ForEach-Object { ($_.ToCharArray() -join ' ') }) -join '   ')
    $holo.Title = $titleText
    $holo.Subtitle = 'Disks, USB, virtual mounts, services, security, Defender, PowerShell and more  -  events from the current boot'
    $holo.Chips = [string[]]@(
        ('BOOT  ' + $script:BootTime.ToString('MM/dd  hh:mm tt')),
        ('{0}  EVENTS' -f $totalEvents),
        ('!{0}  IMPORTANT' -f $imp.Rows.Count)
    )
    $script:evHolo = $holo

    # neon edge around the card
    $edge = New-Object System.Windows.Forms.Panel
    $edge.Dock = 'Fill'
    $edge.BackColor = Rgb 138 84 235
    $edge.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 1, 1, 1, 1

    $card = New-Object System.Windows.Forms.Panel
    $card.Dock = 'Fill'
    $card.BackColor = $cCard

    $root = New-Object System.Windows.Forms.TableLayoutPanel
    $root.Dock = 'Fill'
    $root.BackColor = $cCard
    $root.ColumnCount = 2
    $root.RowCount = 1
    [void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 232)))
    [void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    # ---- sidebar with categories
    $side = New-Object System.Windows.Forms.FlowLayoutPanel
    $side.Dock = 'Fill'
    $side.FlowDirection = 'TopDown'
    $side.WrapContents = $false
    $side.AutoScroll = $true
    $side.BackColor = $cSide
    $side.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 10, 14, 4, 10
    $side.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 0, 0, 0

    $sideHead = New-Object System.Windows.Forms.Label
    $sideHead.Text = 'CATEGORIES'
    $sideHead.AutoSize = $false
    $sideHead.Width = 192
    $sideHead.Height = 26
    $sideHead.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 8, 4, 0, 0
    $sideHead.BackColor = $cSide
    $sideHead.ForeColor = $cDim
    $sideHead.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 8)
    $side.Controls.Add($sideHead)

    $script:evBtns = [ordered]@{}
    foreach ($name in $script:evTables.Keys) {
        $b = New-Object SSCheck.HoloButton
        $b.Side = $true
        $b.Caption = $name
        $b.Count = [string]$script:evTables[$name].Rows.Count
        $b.Hot = ($name -eq 'Important')
        $b.Tag = $name
        $b.Width = 192
        $b.Height = 38
        $b.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 0, 0, 3
        $b.BackColor = $cSide
        $b.Add_Click({ Set-EvTab ([string]$this.Tag) })
        $script:evBtns[$name] = $b
        $side.Controls.Add($b)
    }

    # ---- main area (toolbar / grid / details / status)
    $main = New-Object System.Windows.Forms.TableLayoutPanel
    $main.Dock = 'Fill'
    $main.BackColor = $cCard
    $main.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 14, 10, 14, 6
    $main.ColumnCount = 1
    $main.RowCount = 4
    [void]$main.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 56)))
    [void]$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
    [void]$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 26)))

    # toolbar
    $tool = New-Object System.Windows.Forms.TableLayoutPanel
    $tool.Dock = 'Fill'
    $tool.BackColor = $cCard
    $tool.ColumnCount = 4
    $tool.RowCount = 1
    [void]$tool.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$tool.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 140)))
    [void]$tool.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 122)))
    [void]$tool.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 122)))
    [void]$tool.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $sbox = New-Object System.Windows.Forms.Panel
    $sbox.Dock = 'Fill'
    $sbox.BackColor = $cField
    $sbox.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 14, 11, 14, 4
    $sbox.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 4, 10, 4
    $search = New-Object SSCheck.CueTextBox
    $search.Cue = 'Search events by source, ID or details...'
    $search.Dock = 'Fill'
    $search.BorderStyle = 'None'
    $search.BackColor = $cField
    $search.ForeColor = $cText
    $search.Font = New-Object System.Drawing.Font('Segoe UI', 10.5)
    $sbox.Controls.Add($search)
    $script:evSearch = $search

    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = 'Important only'
    $chk.Dock = 'Fill'
    $chk.FlatStyle = 'Flat'
    $chk.BackColor = $cCard
    $chk.ForeColor = Rgb 255 170 205
    $chk.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
    $chk.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 4, 6, 4
    $script:evImpOnly = $chk

    $btnTab = New-Object SSCheck.HoloButton
    $btnTab.Caption = 'Export tab'
    $btnTab.Dock = 'Fill'
    $btnTab.BackColor = $cCard
    $btnTab.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 6, 8, 6
    $btnTab.Add_Click({ Export-EvTab })

    $btnAll = New-Object SSCheck.HoloButton
    $btnAll.Caption = 'Export all'
    $btnAll.Dock = 'Fill'
    $btnAll.BackColor = $cCard
    $btnAll.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 6, 0, 6
    $btnAll.Add_Click({ Export-EvAll })

    $tool.Controls.Add($sbox, 0, 0)
    $tool.Controls.Add($chk, 1, 0)
    $tool.Controls.Add($btnTab, 2, 0)
    $tool.Controls.Add($btnAll, 3, 0)

    # grid
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 4, 0, 6
    $grid.ReadOnly = $true
    $grid.AutoGenerateColumns = $false
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.MultiSelect = $false
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.BorderStyle = 'None'
    $grid.CellBorderStyle = 'SingleHorizontal'
    $grid.BackgroundColor = $cRow
    $grid.GridColor = Rgb 42 28 80
    $grid.EnableHeadersVisualStyles = $false
    $grid.ColumnHeadersBorderStyle = 'None'
    $grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $grid.ColumnHeadersHeight = 34
    $grid.RowTemplate.Height = 28
    $hs = $grid.ColumnHeadersDefaultCellStyle
    $hs.BackColor = Rgb 34 20 72
    $hs.ForeColor = Rgb 196 176 255
    $hs.SelectionBackColor = Rgb 34 20 72
    $hs.SelectionForeColor = Rgb 196 176 255
    $hs.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 8.5)
    $hs.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 8, 0, 0, 0
    $grid.DefaultCellStyle.BackColor = $cRow
    $grid.DefaultCellStyle.ForeColor = $cText
    $grid.DefaultCellStyle.SelectionBackColor = Rgb 104 58 205
    $grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 8, 0, 8, 0
    $grid.AlternatingRowsDefaultCellStyle.BackColor = $cRowAlt
    $grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = Rgb 104 58 205
    try { $grid.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'Instance,NonPublic').SetValue($grid, $true, $null) } catch {}

    $colDefs = @(
        @{ Name = 'Time';    Header = 'TIME';    Width = 176; Fmt = 'MM/dd/yyyy hh:mm:ss tt' },
        @{ Name = 'Id';      Header = 'ID';      Width = 64;  Fmt = '' },
        @{ Name = 'Source';  Header = 'SOURCE';  Width = 250; Fmt = '' },
        @{ Name = 'Details'; Header = 'DETAILS'; Width = 0;   Fmt = '' }
    )
    foreach ($cd in $colDefs) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $cd.Name
        $col.DataPropertyName = $cd.Name
        $col.HeaderText = $cd.Header
        if ($cd.Width -gt 0) { $col.Width = $cd.Width } else { $col.AutoSizeMode = 'Fill'; $col.MinimumWidth = 200 }
        if ($cd.Fmt) { $col.DefaultCellStyle.Format = $cd.Fmt }
        [void]$grid.Columns.Add($col)
    }
    $grid.Add_DataBindingComplete({
        param($s, $e)
        foreach ($r in $s.Rows) {
            $item = $r.DataBoundItem
            if ($item -and $item['Important'] -eq $true) {
                $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(62, 18, 52)
                $r.DefaultCellStyle.ForeColor = [System.Drawing.Color]::FromArgb(255, 190, 220)
                $r.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(176, 54, 140)
            }
        }
    })
    $grid.Add_SelectionChanged({ Update-EvDetail })
    $script:evGrid = $grid

    # details pane
    $dbox = New-Object System.Windows.Forms.Panel
    $dbox.Dock = 'Fill'
    $dbox.BackColor = Rgb 22 14 46
    $dbox.Padding = New-Object System.Windows.Forms.Padding -ArgumentList 16, 12, 16, 10
    $dbox.Margin = New-Object System.Windows.Forms.Padding -ArgumentList 0, 0, 0, 4
    $detail = New-Object System.Windows.Forms.TextBox
    $detail.Dock = 'Fill'
    $detail.Multiline = $true
    $detail.ReadOnly = $true
    $detail.ScrollBars = 'Vertical'
    $detail.BorderStyle = 'None'
    $detail.BackColor = Rgb 22 14 46
    $detail.ForeColor = Rgb 226 216 255
    $detail.Font = New-Object System.Drawing.Font('Consolas', 10)
    $dbox.Controls.Add($detail)
    $script:evDetail = $detail

    # status line
    $status = New-Object System.Windows.Forms.Label
    $status.Dock = 'Fill'
    $status.TextAlign = 'MiddleLeft'
    $status.BackColor = $cCard
    $status.ForeColor = $cDim
    $status.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
    $script:evStatus = $status

    $main.Controls.Add($tool, 0, 0)
    $main.Controls.Add($grid, 0, 1)
    $main.Controls.Add($dbox, 0, 2)
    $main.Controls.Add($status, 0, 3)

    $root.Controls.Add($side, 0, 0)
    $root.Controls.Add($main, 1, 0)
    $card.Controls.Add($root)
    $edge.Controls.Add($card)
    $holo.Controls.Add($edge)
    $form.Controls.Add($holo)

    # ---- events
    $search.Add_TextChanged({ Update-EvFilter })
    $chk.Add_CheckedChanged({ Update-EvFilter })
    $form.Add_KeyDown({
        param($s, $e)
        if ($e.Control -and $e.KeyCode -eq 'F') { $script:evSearch.Focus(); $e.SuppressKeyPress = $true }
    })

    # slow holographic drift
    $script:holoT = 0.0
    $script:evTimer = New-Object System.Windows.Forms.Timer
    $script:evTimer.Interval = 66
    $script:evTimer.Add_Tick({
        $script:holoT += 0.045
        $script:evHolo.Phase = [single](0.28 * [Math]::Sin($script:holoT))
        $script:evHolo.Invalidate($false)
    })
    $form.Add_FormClosed({ $script:evTimer.Stop(); $script:evTimer.Dispose() })

    Set-EvTab 'Important'
    Update-EvFilter
    $script:evTimer.Start()

    [void]$form.ShowDialog()
    $form.Dispose()
}

Write-Host ""
Write-Host "  Parse event logs now? The Event Logs Parser window will open with disk, USB," -ForegroundColor Cyan
Write-Host "  virtual mount and other system, security and application events from THIS BOOT." -ForegroundColor Cyan
$ans = Read-Host "  (Y/N)"
if ($ans -match '^\s*(y|yes)\s*$') {
    Show-EventParser
}

Write-Host ""
Write-Host "Check complete. Made by Winem. DM null.mood for assistance." -ForegroundColor Magenta
Write-Host ""

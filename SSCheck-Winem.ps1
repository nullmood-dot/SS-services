#Requires -Version 5.1
<#
    SS CHECK - Made by Winem. DM @null.mood for assistance.
    Run in an elevated PowerShell window.

    Colors:  GREEN  = normal / not found
             RED    = disabled, missing or misconfigured
             PURPLE = tamper indicator (restart, suspended threads, token changes,
                      event log hits, BAM changes)
             YELLOW = informational / needs a human look
#>

$ErrorActionPreference = 'SilentlyContinue'
$Purple = 'Magenta'
$RestartToleranceSec = 300      # service started later than boot + this = "restarted"
$BamGapMinutes = 10             # BAM key modified this long after newest entry = possible deletion
$script:Flags = New-Object System.Collections.Generic.List[string]

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Fmt { param($d) if ($d) { $d.ToString('MM/dd/yyyy hh:mm:ss tt') } else { 'N/A' } }
function Add-Flag { param([string]$Text) $script:Flags.Add($Text) }

function Write-Banner {
    $w = 54
    Write-Host ""
    Write-Host ("  +" + ("-" * $w) + "+") -ForegroundColor DarkMagenta
    Write-Host "  |" -NoNewline -ForegroundColor DarkMagenta
    Write-Host ("   M A D E   B Y   W I N E M").PadRight($w) -NoNewline -ForegroundColor Magenta
    Write-Host "|" -ForegroundColor DarkMagenta
    Write-Host "  |" -NoNewline -ForegroundColor DarkMagenta
    Write-Host ("   DM null.mood for assistance").PadRight($w) -NoNewline -ForegroundColor Gray
    Write-Host "|" -ForegroundColor DarkMagenta
    Write-Host ("  +" + ("-" * $w) + "+") -ForegroundColor DarkMagenta
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
    Write-Host ("  {0}" -f $Label) -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $Color
}

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
Write-Section 'ADMIN CHECK'
if (-not $isAdmin) {
    Write-Host "  Administrator privileges REQUIRED. Re-run this script as Administrator." -ForegroundColor Red
    exit
}
Write-Host "  Administrator privileges confirmed." -ForegroundColor Green
if ($nativeOk) { [void][SSCheck.Native]::EnableDebug() }

# ----------------------------------------------------------------------------
# Boot time
# ----------------------------------------------------------------------------
Write-Section 'PC BOOT TIME'
$bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
if ($bootTime) {
    $uptime = (Get-Date) - $bootTime
    Write-Item 'PC BOOTED AT: ' $bootTime.ToString('yyyy-MM-dd hh:mm tt') 'White'
    Write-Item 'UPTIME: ' ('{0} days, {1:D2}:{2:D2}:{3:D2}' -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) 'White'
} else {
    Write-Host "  Unable to retrieve boot time" -ForegroundColor Red
    $bootTime = (Get-Date).AddDays(-1)
}
$cutoff = $bootTime.AddSeconds($RestartToleranceSec)

# ----------------------------------------------------------------------------
# Recycle bin
# ----------------------------------------------------------------------------
Write-Section 'RECYCLE BIN'
$rbPath = "$env:SystemDrive" + '\$Recycle.Bin'
if (Test-Path -LiteralPath $rbPath) {
    $rb = Get-Item -LiteralPath $rbPath -Force
    $latest = $rb.LastWriteTime
    $count = 0
    foreach ($uf in (Get-ChildItem -LiteralPath $rbPath -Directory -Force)) {
        if ($uf.LastWriteTime -gt $latest) { $latest = $uf.LastWriteTime }
        $items = @(Get-ChildItem -LiteralPath $uf.FullName -File -Force)
        $count += $items.Count
        foreach ($i in $items) { if ($i.LastWriteTime -gt $latest) { $latest = $i.LastWriteTime } }
    }
    Write-Item 'LAST MODIFIED: ' (Fmt $latest) 'Yellow'
    Write-Item 'ITEMS: ' "$count" 'White'
} else {
    Write-Item 'Recycle Bin not found at: ' $rbPath 'Yellow'
}

# ----------------------------------------------------------------------------
# Drives
# ----------------------------------------------------------------------------
Write-Section 'CONNECTED DRIVES'
foreach ($d in (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 })) {
    Write-Item ("{0}: " -f $d.DeviceID) $d.FileSystem 'Green'
}

# ----------------------------------------------------------------------------
# Services (state, start time, restart detection, suspended threads)
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

$svcPids = @{}
foreach ($r in $resolved) {
    $svc = $r.Svc
    $name = $r.Name

    if (-not $svc) {
        if ($name -eq 'Bam') {
            $bamStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam').Start
            if ($null -eq $bamStart) { Write-Item ("{0,-14}: " -f $name) 'Not Found' 'Red'; Add-Flag 'BAM service/driver not found' }
            elseif ($bamStart -eq 4) { Write-Item ("{0,-14}: " -f $name) 'Disabled' 'Red'; Add-Flag 'BAM driver disabled' }
            else { Write-Item ("{0,-14}: " -f $name) "Present (driver, Start=$bamStart)" 'Green' }
        } else {
            Write-Item ("{0,-14}: " -f $name) 'Not Found' 'Yellow'
        }
        continue
    }

    $cim = $cimMap[$svc.Name]
    $procId = 0
    if ($cim) { $procId = [int]$cim.ProcessId }
    $proc = $null; $started = $null
    if ($procId -gt 0) { $proc = Get-Process -Id $procId; if ($proc) { $started = $proc.StartTime } }

    $state = [string]$svc.Status
    $color = 'Green'
    $notes = New-Object System.Collections.Generic.List[string]

    if ($svc.StartType -eq 'Disabled') {
        $state = 'Disabled'; $color = 'Red'
        Add-Flag "$($svc.Name) service is DISABLED"
    } elseif ($svc.Status -ne 'Running') {
        $color = 'Red'
        Add-Flag "$($svc.Name) service is $($svc.Status)"
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

    # print the row
    if ($svc.Name -eq 'Bam') { $startText = 'driver' }
    elseif ($started) { $startText = $started.ToString('MM/dd HH:mm:ss') }
    else { $startText = 'N/A' }

    if ($restarted) { $rowColor = $Purple } else { $rowColor = $color }
    Write-Host ("  {0,-14}: " -f $svc.Name) -NoNewline -ForegroundColor White
    Write-Host ("{0,-9}" -f $state) -NoNewline -ForegroundColor $rowColor
    Write-Host (" | started {0}" -f $startText) -NoNewline -ForegroundColor Gray
    if ($restarted) { Write-Host "  << RESTARTED" -NoNewline -ForegroundColor $Purple; Add-Flag "$($svc.Name) restarted after boot" }
    Write-Host ""
    foreach ($note in $notes) { Write-Host ("      - {0}" -f $note) -ForegroundColor $Purple }

    if ($procId -gt 0) { $svcPids[$svc.Name] = $procId }
}

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
# BAM integrity
# ----------------------------------------------------------------------------
Write-Section 'BAM INTEGRITY'
$bamBase = @('SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
             'SYSTEM\CurrentControlSet\Services\bam\UserSettings') |
           Where-Object { Test-Path "HKLM:\$_" } | Select-Object -First 1

if (-not $bamBase) {
    Write-Host "  BAM UserSettings key not found (deleted, or unsupported build)" -ForegroundColor $Purple
    Add-Flag 'BAM UserSettings key not found'
} else {
    # inheritance / deny rules on the parent keys
    foreach ($p in @("HKLM:\SYSTEM\CurrentControlSet\Services\bam", "HKLM:\$bamBase")) {
        $acl = Get-Acl -LiteralPath $p
        if ($acl) {
            $label = $p.Replace('HKLM:\SYSTEM\CurrentControlSet\Services\', '')
            if ($acl.AreAccessRulesProtected) {
                Write-Item ("{0}: " -f $label) 'inheritance DISABLED' $Purple
                Add-Flag "BAM key inheritance disabled ($label)"
            } else {
                Write-Item ("{0}: " -f $label) 'inheritance enabled' 'Green'
            }
            $deny = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
            if ($deny.Count -gt 0) {
                Write-Item ("{0}: " -f $label) ("{0} DENY rule(s) present" -f $deny.Count) $Purple
                Add-Flag "BAM key has deny ACEs ($label)"
            }
        }
    }

    foreach ($k in (Get-ChildItem -LiteralPath "HKLM:\$bamBase")) {
        $sid = $k.PSChildName
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
        Write-Item '    Entries: ' "$($valueNames.Count)" 'White'
        Write-Item '    Oldest entry: ' (Fmt $oldest) 'Gray'
        Write-Item '    Newest entry: ' (Fmt $newest) 'Gray'
        Write-Item '    Key last modified: ' (Fmt $lastWrite) 'Gray'

        if ($valueNames.Count -eq 0) {
            Write-Host "    << NO ENTRIES (BAM cleared or never populated)" -ForegroundColor $Purple
            Add-Flag "BAM has no entries for $who"
        }
        if ($lastWrite -and $newest -and ($lastWrite - $newest).TotalMinutes -gt $BamGapMinutes) {
            Write-Host ("    << key modified {0:N0} min after newest entry (possible deleted entries)" -f ($lastWrite - $newest).TotalMinutes) -ForegroundColor $Purple
            Add-Flag "BAM key for $who modified after newest entry (possible deletion)"
        }
        $kAcl = Get-Acl -LiteralPath $k.PSPath
        if ($kAcl -and $kAcl.AreAccessRulesProtected) {
            Write-Host "    << inheritance DISABLED on this SID key" -ForegroundColor $Purple
            Add-Flag "BAM SID key inheritance disabled ($who)"
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
    @{ Name = 'PowerShell Logging';  Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Key = 'EnableScriptBlockLogging'
       Bad = @(0); BadText = 'Disabled'; GoodText = 'Enabled'; AbsentText = 'Not configured'; AbsentColor = 'Yellow' },
    @{ Name = 'Activities Cache';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'EnableActivityFeed'
       Bad = @(0); BadText = 'Disabled'; GoodText = 'Enabled'; AbsentText = 'Enabled (default)'; AbsentColor = 'Green' },
    @{ Name = 'Prefetch';            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'; Key = 'EnablePrefetcher'
       Bad = @(0); BadText = 'Disabled'; GoodText = 'Enabled'; AbsentText = 'Enabled (default)'; AbsentColor = 'Green' },
    @{ Name = 'Jump Lists / Recent Files (Start_TrackDocs)'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Key = 'Start_TrackDocs'
       Bad = @(0); BadText = 'Disabled'; GoodText = 'Enabled'; AbsentText = 'Enabled (default)'; AbsentColor = 'Green' }
)

foreach ($s in $settings) {
    $val = (Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue).$($s.Key)
    if ($null -eq $val) {
        Write-Item ("{0}: " -f $s.Name) $s.AbsentText $s.AbsentColor
    } elseif ($s.Bad -contains [int]$val) {
        Write-Item ("{0}: " -f $s.Name) $s.BadText 'Red'
        Add-Flag "$($s.Name) $($s.BadText)"
    } else {
        Write-Item ("{0}: " -f $s.Name) $s.GoodText 'Green'
    }
}

# DisablePCA
$detected = @()
foreach ($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat', 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\AppCompat')) {
    $v = Get-ItemProperty -Path $p -Name 'DisablePCA' -ErrorAction SilentlyContinue
    if ($null -ne $v -and $v.DisablePCA -eq 1) { $detected += $p }
}
if ($detected.Count -gt 0) {
    Write-Item 'DisablePCA: ' 'Detected' 'Red'
    foreach ($p in $detected) { Write-Item '    Path: ' $p 'Yellow' }
    Add-Flag 'DisablePCA set'
} else {
    Write-Item 'DisablePCA: ' 'Not detected' 'Green'
}

# jump list / recent files folders
$recent = "$env:APPDATA\Microsoft\Windows\Recent"
$autoDest = Join-Path $recent 'AutomaticDestinations'
$custDest = Join-Path $recent 'CustomDestinations'
if (Test-Path $recent) {
    $lnk = @(Get-ChildItem -Path $recent -Filter *.lnk -Force)
    $lastLnk = $lnk | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Item 'Recent folder .lnk files: ' ("{0} (newest {1})" -f $lnk.Count, (Fmt $lastLnk.LastWriteTime)) 'White'
    $ad = @(Get-ChildItem -Path $autoDest -Force)
    $cd = @(Get-ChildItem -Path $custDest -Force)
    $adNew = $ad | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Item 'Jump lists (Automatic/Custom): ' ("{0} / {1} (newest auto {2})" -f $ad.Count, $cd.Count, (Fmt $adNew.LastWriteTime)) 'White'
    if ($ad.Count -eq 0 -and $cd.Count -eq 0) {
        Write-Item '    ' 'Jump list folders are EMPTY (cleared or tracking disabled)' $Purple
        Add-Flag 'Jump list folders empty'
    }
}

# ----------------------------------------------------------------------------
# Event log checks (purple = record found)
# ----------------------------------------------------------------------------
Write-Section 'EVENT LOG CHECKS'

function Show-Event {
    param([string]$Log, [int[]]$Ids, [string]$Label, [string]$Provider, [switch]$Flag, [switch]$ShowId)
    $f = @{ LogName = $Log; Id = $Ids }
    if ($Provider) { $f.ProviderName = $Provider }
    $e = Get-WinEvent -FilterHashtable $f -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) {
        $lbl = $Label
        if ($ShowId) { $lbl = "$Label (Event ID: $($e.Id))" }
        Write-Host ("  {0} at: " -f $lbl) -NoNewline -ForegroundColor White
        Write-Host (Fmt $e.TimeCreated) -ForegroundColor $Purple
        if ($Flag) { Add-Flag ("{0} {1}" -f $Label, (Fmt $e.TimeCreated)) }
    } else {
        Write-Host ("  {0} - no records found" -f $Label) -ForegroundColor Green
    }
}

Show-Event -Log 'Application' -Ids 3079 -Label 'USN Journal last deleted' -Flag
Show-Event -Log 'System'      -Ids 104  -Label 'Event Logs last cleared (System log)' -Flag -ShowId
Show-Event -Log 'Security'    -Ids 1102 -Label 'Security log last cleared' -Flag -ShowId
Show-Event -Log 'System'      -Ids 1074 -Label 'User recent PC shutdown'
Show-Event -Log 'Security'    -Ids 4616 -Label 'System time changed' -Flag
Show-Event -Log 'System'      -Ids 6005 -Label 'Event Log Service started'

# device changes
$dev = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -FilterXPath '*[System[EventID=400]]' -MaxEvents 1 -ErrorAction SilentlyContinue
if ($dev) {
    Write-Host '  Device configuration changed at: ' -NoNewline -ForegroundColor White
    Write-Host (Fmt $dev.TimeCreated) -ForegroundColor $Purple
} else {
    $dev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 225 } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($dev) {
        Write-Host '  Device removed at: ' -NoNewline -ForegroundColor White
        Write-Host (Fmt $dev.TimeCreated) -ForegroundColor $Purple
    } else {
        Write-Host '  Device changes - no records found' -ForegroundColor Green
    }
}

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
        Add-Flag 'Prefetch folder has no .pf files'
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
            Add-Flag "Prefetch: $($suspicious.Count) suspicious file(s)"
            foreach ($e in ($suspicious.GetEnumerator() | Sort-Object Key)) {
                Write-Host ("    {0} : {1}" -f $e.Key, $e.Value) -ForegroundColor White
            }
        } else {
            Write-Host ("  Prefetch integrity: clean ({0} files checked)" -f $files.Count) -ForegroundColor Green
        }
    }
}

# ----------------------------------------------------------------------------
# PowerShell console history
# ----------------------------------------------------------------------------
Write-Section 'POWERSHELL HISTORY'
$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $hist) {
    $hf = Get-Item -Path $hist -Force
    Write-Item 'LAST MODIFIED: ' (Fmt $hf.LastWriteTime) 'Yellow'
    if ($hf.Attributes -ne 'Archive') { Write-Item 'ATTRIBUTES: ' "$($hf.Attributes)" 'Yellow'; Add-Flag "PS history attributes: $($hf.Attributes)" }
    else { Write-Item 'ATTRIBUTES: ' 'Normal' 'Green' }
    Write-Item 'FILE SIZE: ' ("{0} KB" -f [math]::Round($hf.Length / 1KB, 2)) 'Yellow'
} else {
    Write-Item 'File not found: ' $hist 'Yellow'
}

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
Write-Section 'SUMMARY'
if ($script:Flags.Count -eq 0) {
    Write-Host '  No flags raised.' -ForegroundColor Green
} else {
    Write-Host ("  {0} flag(s) raised:" -f $script:Flags.Count) -ForegroundColor $Purple
    foreach ($f in $script:Flags) { Write-Host "   - $f" -ForegroundColor White }
}
Write-Host ""
Write-Host "  Flags are indicators, not proof. Verify manually before a verdict." -ForegroundColor DarkGray
Write-Host ""
Write-Host "Check complete. Made by Winem. DM null.mood for assistance." -ForegroundColor Magenta
Write-Host ""

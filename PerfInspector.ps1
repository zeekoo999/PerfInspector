#Requires -Version 5.1
<#
.SYNOPSIS
    PerfInspector - modern GUI performance analyzer for Windows applications, services and boot.

.DESCRIPTION
    - Live Monitor   : CPU / RAM / I/O of all processes, live chart, baseline recording and
                       "above usual" detection (what runs heavier in the background than normal).
    - Services       : every service with resource usage, impact, details, dependencies,
                       start / stop / restart and startup-type changes (with automatic backup + restore).
    - Recommendations: which services can be disabled / set to Manual and why.
    - App Start Test : automatic multi-run launch tests (process created, input idle, main window)
                       and a manual stopwatch mode with process / window detection; time chart + statistics.
    - Boot & Autostart: boot duration history, boot slowdown events, autostart apps (registry, startup
                       folders, scheduled tasks, Store apps) incl. enable/disable, services at boot with
                       their start time after boot, service errors since boot.
    - Every table can be exported to CSV (Excel), JSON or HTML, every chart to PNG,
      and a full HTML report with all charts can be generated.

.PARAMETER HideConsole
    Hides the PowerShell console window while the GUI is open.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\PerfInspector.ps1

.NOTES
    Version : 1.0
    Requires: Windows 10 / 11, Windows PowerShell 5.1 or PowerShell 7+
    Run as Administrator for full functionality (boot diagnostics log, service changes, HKLM autostart entries).
    Data (baseline, service change backup) is stored in %LOCALAPPDATA%\PerfInspector
#>
[CmdletBinding()]
param([switch]$HideConsole)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { Write-Error 'PerfInspector requires Windows.'; return }

$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:HostExe    = (Get-Process -Id $PID).Path

# WPF needs an STA thread - relaunch if necessary
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    if ($script:ScriptPath) {
        Start-Process -FilePath $script:HostExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$script:ScriptPath`"")
    } else {
        Write-Error 'Please run this script in an STA session (powershell.exe -STA).'
    }
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, System.Windows.Forms

if ($HideConsole) {
    try {
        if (-not ('PerfInspector.ConsoleUtil' -as [type])) {
            Add-Type -Namespace PerfInspector -Name ConsoleUtil -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
        }
        [void][PerfInspector.ConsoleUtil]::ShowWindow([PerfInspector.ConsoleUtil]::GetConsoleWindow(), 0)
    } catch { }
}

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$script:DataDir = Join-Path $env:LOCALAPPDATA 'PerfInspector'
if (-not (Test-Path $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null }
$script:BaselineFile  = Join-Path $script:DataDir 'baseline.json'
$script:ChangeLogFile = Join-Path $script:DataDir 'service-changes.json'

#region ---------------------------------------------------------------- Service knowledge base
# Name|Category|Recommendation|Reason   (Recommendation: Safe to disable / Set to Manual / Conditional / Keep)
$script:ServiceKB = @{}
@(
    'DiagTrack|Telemetry|Safe to disable|Connected User Experiences and Telemetry. Collects and uploads diagnostic and usage data to Microsoft. Windows works normally without it and it regularly causes background CPU and disk activity.'
    'dmwappushservice|Telemetry|Safe to disable|Device Management WAP Push routing. Mainly used for telemetry and mobile device management. Not needed on private PCs that are not managed by Intune/MDM.'
    'NvTelemetryContainer|Telemetry|Safe to disable|NVIDIA telemetry container. Sends usage data to NVIDIA and is not needed for the graphics driver to work.'
    'RetailDemo|Retail demo|Safe to disable|Retail Demo service. Only used for the shop demo mode of Windows.'
    'MapsBroker|Maps|Safe to disable|Downloaded Maps Manager. Only needed by the Windows Maps app for offline maps.'
    'Fax|Fax|Safe to disable|Fax service. Only needed if you send or receive faxes with this PC.'
    'RemoteRegistry|Security|Safe to disable|Remote Registry allows remote users to modify the registry. Disabling reduces the attack surface (disabled by default on current Windows versions).'
    'WMPNetworkSvc|Media|Safe to disable|Windows Media Player network sharing. Rarely used today.'
    'AJRouter|IoT|Safe to disable|AllJoyn Router for IoT device communication. Rarely used.'
    'WalletService|Payments|Safe to disable|Wallet service used by legacy wallet clients. Rarely used.'
    'lfsvc|Location|Conditional|Geolocation service. Disable if no app needs your location (weather, maps, Find my device, time zone auto detection).'
    'XblAuthManager|Xbox|Conditional|Xbox Live Auth Manager. Disable only if you do not use the Xbox app, Game Pass or Microsoft Store games.'
    'XblGameSave|Xbox|Conditional|Xbox Live Game Save (cloud saves). Disable only if you do not play Xbox/Game Pass games on this PC.'
    'XboxNetApiSvc|Xbox|Conditional|Xbox Live Networking. Disable only if you do not use Xbox online features.'
    'XboxGipSvc|Xbox|Conditional|Xbox Accessory Management (controller firmware and settings). Disable only if you never use Xbox controllers.'
    'wisvc|Insider|Conditional|Windows Insider Service. Only needed when you participate in the Windows Insider program.'
    'PhoneSvc|Telephony|Conditional|Phone Service. Used by telephony apps and Phone Link calls.'
    'icssvc|Network|Conditional|Windows Mobile Hotspot. Disable if you never share your internet connection from this PC.'
    'SharedAccess|Network|Conditional|Internet Connection Sharing. Needed for hotspots and some virtual machine networks (Hyper-V default switch). Keep if you use VMs or WSL networking features.'
    'SysMain|Performance|Conditional|SysMain (Superfetch) preloads frequently used apps into RAM. Helpful on HDDs; on fast SSDs it can cause unnecessary background disk and CPU load. Disable only if it shows high usage.'
    'WSearch|Search|Conditional|Windows Search indexer. Speeds up file, Start menu and Outlook search, but indexing can cause heavy background I/O. Set to Manual or disable if you rarely search.'
    'Spooler|Printing|Conditional|Print Spooler. Required for printing, PDF printers and print preview. Disable only if you never print (also mitigates print spooler vulnerabilities).'
    'bthserv|Bluetooth|Conditional|Bluetooth Support Service. Disable only if you do not use any Bluetooth devices (mouse, keyboard, headset).'
    'BTAGService|Bluetooth|Conditional|Bluetooth Audio Gateway (headset telephony). Disable only if you do not use Bluetooth headsets.'
    'WbioSrvc|Biometrics|Conditional|Windows Biometric Service. Required for Windows Hello fingerprint and face recognition.'
    'SCardSvr|Smart card|Conditional|Smart Card service. Needed for smart cards, company badges and eID card readers.'
    'ScDeviceEnum|Smart card|Conditional|Smart Card Device Enumeration. Needed only with smart card readers.'
    'SCPolicySvc|Smart card|Conditional|Smart Card Removal Policy. Needed only with smart card logon.'
    'WpcMonSvc|Parental controls|Conditional|Parental Controls (Microsoft Family). Not needed without family/child accounts.'
    'SEMgrSvc|Payments|Conditional|Payments and NFC/SE Manager. Needed only for NFC payments.'
    'MessagingService|Messaging|Conditional|Text messaging service (SMS on devices with cellular modems).'
    'TeamViewer|Remote access|Conditional|TeamViewer background service. Set to Manual if you only use TeamViewer occasionally (also reduces the attack surface).'
    'AnyDesk|Remote access|Conditional|AnyDesk background service. Set to Manual if you only use AnyDesk occasionally.'
    'Apple Mobile Device Service|Apple|Conditional|Needed only when you connect iPhones/iPads to this PC.'
    'Bonjour Service|Network|Conditional|Apple Bonjour network discovery. Needed by iTunes and some printers, otherwise rarely used.'
    'WerSvc|Diagnostics|Set to Manual|Windows Error Reporting. Starts on demand when an application crashes, no need to run permanently.'
    'PcaSvc|Compatibility|Set to Manual|Program Compatibility Assistant monitors older programs for known problems.'
    'TrkWks|File system|Set to Manual|Distributed Link Tracking Client keeps links to files moved between NTFS volumes. Rarely needed on single PCs.'
    'TapiSrv|Telephony|Set to Manual|Telephony API. Only needed by telephony software.'
    'diagnosticshub.standardcollector.service|Diagnostics|Set to Manual|Diagnostics Hub collector used by Visual Studio and diagnostics tools.'
    'AdobeARMservice|Updates|Set to Manual|Adobe Acrobat update service. Acrobat also checks for updates when it starts.'
    'Steam Client Service|Gaming|Set to Manual|Steam Client Service. Steam starts it on demand.'
    'ClickToRunSvc|Office|Keep|Microsoft Office Click-to-Run. Required for Office apps and their updates.'
    'edgeupdate|Updates|Keep|Microsoft Edge Update. Keeps the browser patched against security vulnerabilities.'
    'edgeupdatem|Updates|Keep|Microsoft Edge Update (on-demand). Keeps the browser patched.'
    'gupdate|Updates|Keep|Google Update. Keeps Chrome patched against security vulnerabilities.'
    'gupdatem|Updates|Keep|Google Update (on-demand). Keeps Chrome patched.'
    'DPS|Diagnostics|Keep|Diagnostic Policy Service. Problem detection and troubleshooting for Windows components.'
) | ForEach-Object {
    $parts = $_ -split '\|', 4
    $script:ServiceKB[$parts[0]] = [pscustomobject]@{ Category = $parts[1]; Rec = $parts[2]; Reason = $parts[3] }
}

$script:CriticalServices = @(
    'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'LSM', 'SamSs', 'EventLog', 'Schedule', 'Winmgmt', 'PlugPlay', 'Power',
    'ProfSvc', 'AudioSrv', 'AudioEndpointBuilder', 'Dhcp', 'Dnscache', 'NlaSvc', 'nsi', 'BFE', 'mpssvc', 'WinDefend',
    'wscsvc', 'SecurityHealthService', 'CryptSvc', 'gpsvc', 'UserManager', 'StateRepository', 'CoreMessagingRegistrar',
    'BrokerInfrastructure', 'SystemEventsBroker', 'TimeBrokerSvc', 'Themes', 'FontCache', 'LanmanWorkstation', 'netprofm',
    'Wcmsvc', 'WlanSvc', 'EventSystem', 'SENS', 'ShellHWDetection', 'Appinfo', 'TokenBroker', 'wuauserv', 'BITS', 'UsoSvc',
    'WaaSMedicSvc', 'TrustedInstaller', 'msiserver', 'VaultSvc', 'KeyIso', 'Sense', 'WdNisSvc', 'DispBrokerDesktopSvc',
    'DeviceInstall', 'DsmSvc', 'camsvc', 'AppXSvc', 'ClipSVC', 'LicenseManager', 'W32Time', 'Netlogon', 'LanmanServer',
    'iphlpsvc', 'WdiServiceHost', 'WdiSystemHost', 'SgrmBroker', 'mpsdrv', 'CDPSvc', 'StorSvc', 'TextInputManagementService',
    'webthreatdefsvc', 'webthreatdefusersvc', 'EFS', 'Audiosrv', 'SystemEventsBroker' )
#endregion

#region ---------------------------------------------------------------- Background worker functions (also run inside runspaces)
function Get-ExePathFromCommand {
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|lnk|vbs|ps1|msc))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Get-PerfSnapshot {
    $cores = [Environment]::ProcessorCount
    $perf = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue)
    $wp = @{}
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath -ErrorAction SilentlyContinue)) { $wp[[int]$p.ProcessId] = $p }
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
    $svcByPid = @{}
    foreach ($s in $services) {
        if ($s.ProcessId) {
            $k = [int]$s.ProcessId
            if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = New-Object System.Collections.Generic.List[string] }
            $svcByPid[$k].Add([string]$s.Name)
        }
    }
    $perfByPid = @{}
    $procs = New-Object System.Collections.Generic.List[object]
    foreach ($x in $perf) {
        if ($x.Name -eq '_Total' -or $x.Name -eq 'Idle') { continue }
        $id  = [int]$x.IDProcess
        $cpu = [Math]::Round([double]$x.PercentProcessorTime / $cores, 1)
        $mem = [Math]::Round([double]$x.WorkingSetPrivate / 1MB, 1)
        $io  = [Math]::Round([double]$x.IODataBytesPersec / 1KB, 1)
        $perfByPid[$id] = @{ Cpu = $cpu; Mem = $mem; IO = $io }
        $w = $wp[$id]
        $name = if ($w) { $w.Name -replace '\.exe$', '' } else { $x.Name -replace '#\d+$', '' }
        $path = if ($w) { [string]$w.ExecutablePath } else { '' }
        $hosted = if ($svcByPid.ContainsKey($id)) { $svcByPid[$id] -join ', ' } else { '' }
        $procs.Add([pscustomobject]@{
                Name = $name; PID = $id; CPU = $cpu; MemoryMB = $mem; IOKBs = $io
                Threads = [int]$x.ThreadCount; Handles = [int]$x.HandleCount
                Status = ''; Services = $hosted; Path = $path; Alert = $false
            })
    }
    $svcs = New-Object System.Collections.Generic.List[object]
    foreach ($s in $services) {
        $id = [int]$s.ProcessId
        $pf = $perfByPid[$id]
        $delayed = $false
        if ($null -ne $s.DelayedAutoStart) { $delayed = [bool]$s.DelayedAutoStart }
        elseif ($s.StartMode -eq 'Auto') {
            try { $delayed = ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -Name DelayedAutostart -ErrorAction Stop).DelayedAutostart -eq 1) } catch { }
        }
        $startType = switch ($s.StartMode) {
            'Auto'     { if ($delayed) { 'Automatic (Delayed)' } else { 'Automatic' } }
            'Manual'   { 'Manual' }
            'Disabled' { 'Disabled' }
            default    { [string]$s.StartMode }
        }
        $shared = 0
        if ($id -and $svcByPid.ContainsKey($id)) { $shared = $svcByPid[$id].Count }
        $svcs.Add([pscustomobject]@{
                DisplayName = [string]$s.DisplayName; Name = [string]$s.Name; State = [string]$s.State; StartType = $startType
                CPU = $(if ($pf) { $pf.Cpu } else { 0 }); MemoryMB = $(if ($pf) { $pf.Mem } else { 0 }); IOKBs = $(if ($pf) { $pf.IO } else { 0 })
                Impact = ''; Status = ''; Recommendation = ''; RecColor = '#9AA4B2'; Category = ''; Reason = ''
                StartMode = [string]$s.StartMode; Delayed = $delayed; PID = $id; SharedWith = $shared
                Description = [string]$s.Description; PathName = [string]$s.PathName; Account = [string]$s.StartName
                ThirdParty = $false; Alert = $false
            })
    }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpuTotal = 0
    try { $cpuTotal = [double](Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop).PercentProcessorTime } catch { }
    $memTotal = [double]$os.TotalVisibleMemorySize / 1MB
    $memUsed  = ([double]$os.TotalVisibleMemorySize - [double]$os.FreePhysicalMemory) / 1MB
    [pscustomobject]@{
        Time       = Get-Date
        Processes  = $procs.ToArray()
        Services   = $svcs.ToArray()
        CpuTotal   = $cpuTotal
        MemTotalGB = [Math]::Round($memTotal, 1)
        MemUsedGB  = [Math]::Round($memUsed, 1)
        MemUsedPct = $(if ($memTotal -gt 0) { [Math]::Round($memUsed / $memTotal * 100, 1) } else { 0 })
        LastBoot   = $os.LastBootUpTime
    }
}

function Invoke-AppStartTest {
    param([string]$Exe, [string]$Arguments, [int]$Iterations = 3, [int]$DelaySec = 3, [int]$TimeoutSec = 60,
        [bool]$CloseAfter = $true, [string]$WatchName, $Sync)
    $isShell = $Exe -like 'shell:*'
    $appName = if ($isShell) { $Exe } else { [IO.Path]::GetFileNameWithoutExtension($Exe) }
    $names = @()
    if ($WatchName) { $names = @($WatchName -split '[,;]' | ForEach-Object { $_.Trim() -replace '\.exe$', '' } | Where-Object { $_ }) }
    elseif (-not $isShell) { $names = @($appName) }
    $timeoutMs = [Math]::Max(1, $TimeoutSec) * 1000

    for ($i = 1; $i -le $Iterations; $i++) {
        if ($Sync.Cancel) { break }
        $Sync.Progress = "App start test: run $i of $Iterations - launching $appName ..."
        $pre = @{}
        if ($names.Count) { foreach ($pp in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) { $pre[$pp.Id] = $true } }
        $res = [pscustomobject]@{
            Run = 0; Mode = 'Automatic'; Application = $appName; ProcessMs = $null; InputIdleMs = $null; WindowMs = $null
            UserReadyMs = $null; TotalMs = $null; MemoryMB = $null; CpuTimeMs = $null; Status = ''; Timestamp = (Get-Date)
        }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $p = $null
        try {
            $psi = New-Object Diagnostics.ProcessStartInfo
            $psi.FileName = $Exe
            if ($Arguments) { $psi.Arguments = $Arguments }
            $psi.UseShellExecute = $true
            if (-not $isShell) {
                $wd = Split-Path -Path $Exe -Parent
                if ($wd -and (Test-Path -LiteralPath $wd)) { $psi.WorkingDirectory = $wd }
            }
            $p = [Diagnostics.Process]::Start($psi)
        } catch {
            $res.Status = "Launch failed: $($_.Exception.Message)"
            $res.TotalMs = $sw.ElapsedMilliseconds
            [void]$Sync.TestResults.Add($res)
            continue
        }
        $res.ProcessMs = $sw.ElapsedMilliseconds

        if ($p) { try { if ($p.WaitForInputIdle($timeoutMs)) { $res.InputIdleMs = $sw.ElapsedMilliseconds } } catch { } }

        $target = $null
        while ($sw.ElapsedMilliseconds -lt $timeoutMs -and -not $Sync.Cancel) {
            if ($p) {
                try {
                    if (-not $p.HasExited) {
                        $p.Refresh()
                        if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $target = $p; break }
                    }
                } catch { }
            }
            if ($names.Count) {
                foreach ($c in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) {
                    if ($pre.ContainsKey($c.Id)) { continue }
                    if ($c.MainWindowHandle -ne [IntPtr]::Zero) { $target = $c; break }
                }
            }
            if ($target) { break }
            Start-Sleep -Milliseconds 25
        }

        if ($target) {
            $res.WindowMs = $sw.ElapsedMilliseconds
            $res.TotalMs  = $res.WindowMs
            try {
                $target.Refresh()
                $res.MemoryMB  = [Math]::Round($target.WorkingSet64 / 1MB, 1)
                $res.CpuTimeMs = [Math]::Round($target.TotalProcessorTime.TotalMilliseconds)
            } catch { }
            $res.Status = 'OK'
        } else {
            $res.TotalMs = $sw.ElapsedMilliseconds
            $res.Status = if ($Sync.Cancel) { 'Cancelled' } else { 'Timeout - no window detected' }
        }
        [void]$Sync.TestResults.Add($res)

        if ($CloseAfter) {
            $toClose = New-Object System.Collections.Generic.List[object]
            if ($names.Count) { foreach ($c in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) { if (-not $pre.ContainsKey($c.Id)) { $toClose.Add($c) } } }
            if ($p) { try { if (-not $p.HasExited) { $toClose.Add($p) } } catch { } }
            foreach ($c in $toClose) { try { [void]$c.CloseMainWindow() } catch { } }
            foreach ($c in $toClose) { try { if (-not $c.WaitForExit(5000)) { $c.Kill() } } catch { } }
        }

        if ($i -lt $Iterations) {
            $until = [DateTime]::Now.AddSeconds($DelaySec)
            while ([DateTime]::Now -lt $until -and -not $Sync.Cancel) { Start-Sleep -Milliseconds 100 }
        }
    }
    $Sync.Progress = ''
}

function Get-BootAnalysis {
    param([bool]$IncludeMsTasks = $false)
    $errors = New-Object System.Collections.Generic.List[string]
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    function Get-EvData($ev) {
        $hash = @{}
        try {
            $xd = [xml]$ev.ToXml()
            $ed = $xd.Event.EventData
            if ($ed -and $ed.ChildNodes) {
                foreach ($d in $ed.ChildNodes) { if ($d.LocalName -eq 'Data') { $hash[$d.GetAttribute('Name')] = $d.InnerText } }
            }
        } catch { }
        $hash
    }
    function ToD($v) { $o = 0.0; [void][double]::TryParse([string]$v, [ref]$o); $o }
    function Test-NoEvents($err) { [string]$err.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $lastBoot = $os.LastBootUpTime
    $bootRef = $lastBoot
    # Fast Startup (hybrid boot) does not reset LastBootUpTime - use the kernel boot event instead
    try {
        $kbs = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Boot'; Id = 27 } -MaxEvents 10 -ErrorAction Stop
        foreach ($kb in $kbs) {
            $bt = $null
            try { $bt = [int]$kb.Properties[0].Value } catch { }
            if ($null -eq $bt -or $bt -eq 0 -or $bt -eq 1) {
                if ($kb.TimeCreated -gt $bootRef) { $bootRef = $kb.TimeCreated }
                break
            }
        }
    } catch { }

    $fast = $null
    try { $fast = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled -eq 1) } catch { }

    # --- boot history (Diagnostics-Performance event 100)
    $boots = New-Object System.Collections.Generic.List[object]
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 30 -ErrorAction Stop
        foreach ($e in $evs) {
            $d = Get-EvData $e
            $rating = switch ([int]$e.Level) { 1 { 'Critical (very slow)' } 2 { 'Slow' } 3 { 'Slower than usual' } default { 'Normal' } }
            $boots.Add([pscustomobject]@{
                    Date        = $e.TimeCreated
                    BootSec     = [Math]::Round((ToD $d['BootTime']) / 1000, 1)
                    MainPathSec = [Math]::Round((ToD $d['MainPathBootTime']) / 1000, 1)
                    PostBootSec = [Math]::Round((ToD $d['BootPostBootTime']) / 1000, 1)
                    Rating      = $rating
                })
        }
    } catch {
        if (-not (Test-NoEvents $_)) {
            $hint = if (-not $isAdmin) { ' Run as administrator to read the boot diagnostics log.' } else { '' }
            $errors.Add("Boot history: $($_.Exception.Message)$hint")
        }
    }

    # --- boot slowdown events (101-110)
    $deg = New-Object System.Collections.Generic.List[object]
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101, 102, 103, 104, 105, 106, 107, 108, 109, 110 } -MaxEvents 300 -ErrorAction Stop
        foreach ($e in $evs) {
            $d = Get-EvData $e
            $type = switch ([int]$e.Id) { 101 { 'Application' } 102 { 'Driver' } 103 { 'Service' } default { "System component ($($e.Id))" } }
            $nm = if ($d['FriendlyName']) { $d['FriendlyName'] } elseif ($d['Name']) { $d['Name'] } else { [string]$d['FileName'] }
            $deg.Add([pscustomobject]@{
                    Date = $e.TimeCreated; EventId = [int]$e.Id; Type = $type; Name = $nm
                    TotalMs = ToD $d['TotalTime']; DegradationMs = ToD $d['DegradationTime']; File = [string]$d['Name']
                })
        }
    } catch {
        if (-not (Test-NoEvents $_)) { $errors.Add("Boot slowdowns: $($_.Exception.Message)") }
    }

    # --- services at boot (first state change after boot from SCM event 7036)
    $svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
    $first = @{}
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7036; StartTime = $bootRef; EndTime = $bootRef.AddMinutes(30) } -ErrorAction Stop
        foreach ($e in ($evs | Sort-Object TimeCreated)) {
            $dn = [string]$e.Properties[0].Value
            if ($dn -and -not $first.ContainsKey($dn)) { $first[$dn] = $e.TimeCreated }
        }
    } catch {
        if (-not (Test-NoEvents $_)) { $errors.Add("Service start events: $($_.Exception.Message)") }
    }
    $svcDelay = @{}
    foreach ($d in $deg) {
        if ($d.EventId -ne 103) { continue }
        foreach ($k in @($d.Name, $d.File)) {
            if (-not $k) { continue }
            $kk = $k.ToLower()
            if (-not $svcDelay.ContainsKey($kk) -or $svcDelay[$kk] -lt $d.DegradationMs) { $svcDelay[$kk] = $d.DegradationMs }
        }
    }
    $bootSvcs = New-Object System.Collections.Generic.List[object]
    foreach ($s in $svcs) {
        $dispName = [string]$s.DisplayName
        $t = if ($dispName) { $first[$dispName] } else { $null }
        $auto = $s.StartMode -eq 'Auto'
        $off = if ($t) { [Math]::Round(($t - $bootRef).TotalSeconds, 1) } else { $null }
        if (-not $auto -and ($null -eq $off -or $off -gt 300)) { continue }
        $delayed = [bool]$s.DelayedAutoStart
        $type = if ($auto) { if ($delayed) { 'Automatic (Delayed)' } else { 'Automatic' } } else { "$($s.StartMode) (trigger start)" }
        $dl = $svcDelay[([string]$s.Name).ToLower()]
        if (-not $dl -and $dispName) { $dl = $svcDelay[$dispName.ToLower()] }
        $bootSvcs.Add([pscustomobject]@{
                DisplayName = $dispName; Name = [string]$s.Name; StartType = $type; State = [string]$s.State
                StartedAfterBootSec = $off; BootDelayMs = $(if ($dl) { $dl } else { $null })
                Recommendation = ''; RecColor = '#9AA4B2'; PathName = [string]$s.PathName
            })
    }

    # --- service errors since boot
    $issues = New-Object System.Collections.Generic.List[object]
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034; StartTime = $bootRef } -MaxEvents 200 -ErrorAction Stop
        foreach ($e in $evs) {
            $msg = ([string]$e.Message -split "`r?`n")[0]
            $svcName = ''
            try { $svcName = [string]$e.Properties[0].Value } catch { }
            $issues.Add([pscustomobject]@{ Date = $e.TimeCreated; EventId = [int]$e.Id; Service = $svcName; Message = $msg })
        }
    } catch {
        if (-not (Test-NoEvents $_)) { $errors.Add("Service errors: $($_.Exception.Message)") }
    }

    # --- autostart applications
    $procByPath = @{}
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Property ExecutablePath, CreationDate, ProcessId -ErrorAction SilentlyContinue)) {
        if ($p.ExecutablePath) {
            $k = $p.ExecutablePath.ToLower()
            if (-not $procByPath.ContainsKey($k) -or $p.CreationDate -lt $procByPath[$k]) { $procByPath[$k] = $p.CreationDate }
        }
    }
    function Get-Approved([string]$Path, [string]$Name) {
        if (-not $Path -or -not (Test-Path $Path)) { return $true }
        try {
            $v = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            if ($v -is [byte[]] -and $v.Length -gt 0) { return (($v[0] -band 1) -eq 0) }
        } catch { }
        $true
    }
    $apps = New-Object System.Collections.Generic.List[object]
    $addApp = {
        param($Name, $Command, $Location, $Scope, $Enabled, $Kind, $KeyPath, $ValueName, $ApprovedPath, $Delay)
        $exe = Get-ExePathFromCommand $Command
        if ($exe -and -not [IO.Path]::IsPathRooted($exe)) {
            $gc = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($gc) { $exe = $gc.Path }
        }
        $pub = ''; $desc = ''
        if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
            try { $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe); $pub = $vi.CompanyName; $desc = $vi.FileDescription } catch { }
        }
        $started = $null; $running = $false
        if ($exe) {
            $ct = $procByPath[$exe.ToLower()]
            if ($ct) { $running = $true; $started = [Math]::Round(($ct - $bootRef).TotalSeconds, 1) }
        }
        $apps.Add([pscustomobject]@{
                EnabledText = $(if ($Enabled) { 'Enabled' } else { 'Disabled' }); Name = $Name; Publisher = $pub; Description = $desc
                Location = $Location; Scope = $Scope; Running = $running; StartedAfterBootSec = $started; Delay = $Delay
                Command = $Command; ExePath = $exe; Enabled = [bool]$Enabled; Kind = $Kind; KeyPath = $KeyPath
                ValueName = $ValueName; ApprovedPath = $ApprovedPath
            })
    }
    $ap = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
    $runKeys = @(
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'Current user'; Approved = "HKCU:\$ap\Run"; Loc = 'Registry Run (HKCU)' }
        @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Scope = 'All users'; Approved = "HKLM:\$ap\Run"; Loc = 'Registry Run (HKLM)' }
        @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Scope = 'All users'; Approved = "HKLM:\$ap\Run32"; Loc = 'Registry Run (HKLM 32-bit)' }
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'Current user'; Approved = $null; Loc = 'Registry RunOnce (HKCU)' }
        @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'All users'; Approved = $null; Loc = 'Registry RunOnce (HKLM)' }
    )
    foreach ($k in $runKeys) {
        if (-not (Test-Path $k.Path)) { continue }
        try {
            $key = Get-Item -Path $k.Path -ErrorAction Stop
            foreach ($vn in $key.GetValueNames()) {
                if (-not $vn) { continue }
                $cmd = [string]$key.GetValue($vn)
                & $addApp $vn $cmd $k.Loc $k.Scope (Get-Approved $k.Approved $vn) 'Approved' $k.Path $vn $k.Approved ''
            }
        } catch { $errors.Add("Autostart registry $($k.Path): $($_.Exception.Message)") }
    }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    $folders = @(
        @{ Path = [Environment]::GetFolderPath('Startup'); Scope = 'Current user'; Approved = "HKCU:\$ap\StartupFolder"; Loc = 'Startup folder (user)' }
        @{ Path = [Environment]::GetFolderPath('CommonStartup'); Scope = 'All users'; Approved = "HKLM:\$ap\StartupFolder"; Loc = 'Startup folder (all users)' }
    )
    foreach ($f in $folders) {
        if (-not $f.Path -or -not (Test-Path -LiteralPath $f.Path)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $f.Path -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $cmd = $file.FullName
            if ($file.Extension -eq '.lnk' -and $shell) {
                try { $sc = $shell.CreateShortcut($file.FullName); if ($sc.TargetPath) { $cmd = ('"{0}" {1}' -f $sc.TargetPath, $sc.Arguments).Trim() } } catch { }
            }
            & $addApp $file.BaseName $cmd $f.Loc $f.Scope (Get-Approved $f.Approved $file.Name) 'Approved' $file.FullName $file.Name $f.Approved ''
        }
    }
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            if (-not $IncludeMsTasks -and $t.TaskPath -like '\Microsoft\*') { continue }
            $trig = @($t.Triggers | Where-Object { $_ -and $_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger' })
            if (-not $trig.Count) { continue }
            $atBoot = @($trig | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' }).Count -gt 0
            $cmd = (@($t.Actions | Where-Object { $_.Execute }) | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join ' ; '
            $delay = (@($trig | ForEach-Object { $_.Delay } | Where-Object { $_ }) -join ', ')
            $loc = if ($atBoot) { 'Scheduled task (at boot)' } else { 'Scheduled task (at logon)' }
            & $addApp $t.TaskName $cmd $loc $t.TaskPath ($t.State -ne 'Disabled') 'Task' $t.TaskPath $t.TaskName $null $delay
        }
    } catch { $errors.Add("Scheduled tasks: $($_.Exception.Message)") }
    $appModel = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData'
    if (Test-Path $appModel) {
        foreach ($pkg in @(Get-ChildItem -Path $appModel -ErrorAction SilentlyContinue)) {
            foreach ($task in @(Get-ChildItem -Path $pkg.PSPath -ErrorAction SilentlyContinue)) {
                $state = $task.GetValue('State')
                if ($null -eq $state) { continue }
                $pkgName = ($pkg.PSChildName -split '_')[0]
                & $addApp "$pkgName ($($task.PSChildName))" $pkg.PSChildName 'Store app startup task' 'Current user' ([int]$state -in 2, 4) 'AppX' $task.PSPath 'State' $null ''
            }
        }
    }

    [pscustomobject]@{
        LastBoot    = $lastBoot
        BootRef     = $bootRef
        FastStartup = $fast
        IsAdmin     = $isAdmin
        Boots       = $boots.ToArray()
        Degradation = $deg.ToArray()
        Services    = $bootSvcs.ToArray()
        StartupApps = $apps.ToArray()
        Issues      = $issues.ToArray()
        Errors      = $errors.ToArray()
    }
}
#endregion

#region ---------------------------------------------------------------- XAML
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PerfInspector - Windows Performance Analyzer"
        Width="1440" Height="900" MinWidth="1150" MinHeight="700"
        WindowStartupLocation="CenterScreen"
        Background="#0F1115" Foreground="#E6EAF0"
        FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <Style x:Key="Icon" TargetType="TextBlock">
      <Setter Property="FontFamily" Value="Segoe MDL2 Assets"/>
      <Setter Property="FontSize" Value="15"/>
      <Setter Property="Margin" Value="0,0,12,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="NumCell" TargetType="TextBlock">
      <Setter Property="HorizontalAlignment" Value="Right"/>
      <Setter Property="Margin" Value="0,0,6,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="WrapCell" TargetType="TextBlock">
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="0,5"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="#161A22"/>
      <Setter Property="BorderBrush" Value="#232A36"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="10"/>
      <Setter Property="Padding" Value="14,12"/>
    </Style>
    <Style x:Key="CardLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#8A94A6"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="CardValue" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="FontSize" Value="22"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
    </Style>
    <Style x:Key="CardSub" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#6B7385"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="Margin" Value="0,2,0,0"/>
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
    </Style>
    <Style x:Key="SectionTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="14"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="Margin" Value="0,0,0,6"/>
    </Style>
    <Style x:Key="FieldLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#9AA4B2"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="Margin" Value="0,10,0,4"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#8A94A6"/>
      <Setter Property="FontSize" Value="11.5"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>

    <Style TargetType="Button">
      <Setter Property="Foreground" Value="#E6EAF0"/>
      <Setter Property="Background" Value="#232A36"/>
      <Setter Property="BorderBrush" Value="#2E3746"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="0,0,8,6"/>
      <Setter Property="MinHeight" Value="32"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#4F8CFF"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="Bd" Property="Opacity" Value="0.8"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Bd" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Accent" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#3B78F0"/>
      <Setter Property="BorderBrush" Value="#3B78F0"/>
      <Setter Property="Foreground" Value="#FFFFFF"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#3A1F24"/>
      <Setter Property="BorderBrush" Value="#6B2B33"/>
      <Setter Property="Foreground" Value="#FF9B9B"/>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Foreground" Value="#E6EAF0"/>
      <Setter Property="Background" Value="#1A1F29"/>
      <Setter Property="BorderBrush" Value="#2E3746"/>
      <Setter Property="CaretBrush" Value="#E6EAF0"/>
      <Setter Property="SelectionBrush" Value="#4F8CFF"/>
      <Setter Property="Padding" Value="8,5"/>
      <Setter Property="MinHeight" Value="32"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="6">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#4F8CFF"/></Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#3E4A5E"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="ComboBox">
      <Setter Property="Foreground" Value="#E6EAF0"/>
      <Setter Property="MinHeight" Value="32"/>
      <Setter Property="Margin" Value="0,0,8,6"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton Focusable="False" ClickMode="Press"
                            IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="B" Background="#1A1F29" BorderBrush="#2E3746" BorderThickness="1" CornerRadius="6">
                      <TextBlock Text="&#xE70D;" FontFamily="Segoe MDL2 Assets" FontSize="10" Foreground="#9AA4B2"
                                 HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,10,0"/>
                    </Border>
                    <ControlTemplate.Triggers>
                      <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="B" Property="BorderBrush" Value="#4F8CFF"/></Trigger>
                    </ControlTemplate.Triggers>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter IsHitTestVisible="False" Margin="10,5,28,5" VerticalAlignment="Center"
                                Content="{TemplateBinding SelectionBoxItem}"
                                ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"/>
              <Popup Placement="Bottom" AllowsTransparency="True" Focusable="False" PopupAnimation="Slide"
                     IsOpen="{TemplateBinding IsDropDownOpen}">
                <Border Background="#1C212B" BorderBrush="#2E3746" BorderThickness="1" CornerRadius="6" Margin="0,2,0,0"
                        MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}" MaxHeight="320">
                  <ScrollViewer><ItemsPresenter/></ScrollViewer>
                </Border>
              </Popup>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="#E6EAF0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="B" Padding="10,6" Background="Transparent"><ContentPresenter/></Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsHighlighted" Value="True"><Setter TargetName="B" Property="Background" Value="#2A3342"/></Trigger>
              <Trigger Property="IsSelected" Value="True"><Setter TargetName="B" Property="Background" Value="#24406E"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#C9D1DD"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Margin" Value="0,0,14,6"/>
    </Style>
    <Style TargetType="ToolTip">
      <Setter Property="Background" Value="#1C212B"/>
      <Setter Property="Foreground" Value="#E6EAF0"/>
      <Setter Property="BorderBrush" Value="#2E3746"/>
    </Style>

    <Style x:Key="ScrollThumb" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border Background="#3A4356" CornerRadius="4" Margin="2"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ScrollBar">
      <Setter Property="Width" Value="11"/>
      <Setter Property="MinWidth" Value="11"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Border Background="Transparent">
              <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}"/></Track.Thumb>
              </Track>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/>
          <Setter Property="MinWidth" Value="0"/>
          <Setter Property="Height" Value="11"/>
          <Setter Property="MinHeight" Value="11"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ScrollBar">
                <Border Background="Transparent">
                  <Track x:Name="PART_Track">
                    <Track.Thumb><Thumb Style="{StaticResource ScrollThumb}"/></Track.Thumb>
                  </Track>
                </Border>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="#161A22"/>
      <Setter Property="Foreground" Value="#E6EAF0"/>
      <Setter Property="BorderBrush" Value="#232A36"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="RowBackground" Value="#161A22"/>
      <Setter Property="AlternatingRowBackground" Value="#1A1F29"/>
      <Setter Property="GridLinesVisibility" Value="None"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="SelectionMode" Value="Extended"/>
      <Setter Property="MinRowHeight" Value="28"/>
      <Setter Property="EnableRowVirtualization" Value="True"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#1C212B"/>
      <Setter Property="Foreground" Value="#9AA4B2"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Padding" Value="10,8"/>
      <Setter Property="BorderBrush" Value="#262D3A"/>
      <Setter Property="BorderThickness" Value="0,0,1,1"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridColumnHeader">
            <Grid>
              <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                      BorderThickness="{TemplateBinding BorderThickness}" Padding="{TemplateBinding Padding}">
                <DockPanel>
                  <TextBlock x:Name="Arrow" DockPanel.Dock="Right" FontFamily="Segoe MDL2 Assets" FontSize="9" Margin="6,0,0,0"
                             VerticalAlignment="Center" Visibility="Collapsed" Text="&#xE70E;" Foreground="#4F8CFF"/>
                  <ContentPresenter VerticalAlignment="Center"/>
                </DockPanel>
              </Border>
              <Thumb x:Name="PART_RightHeaderGripper" HorizontalAlignment="Right" Width="6" Cursor="SizeWE" Opacity="0"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="SortDirection" Value="Ascending">
                <Setter TargetName="Arrow" Property="Visibility" Value="Visible"/>
                <Setter TargetName="Arrow" Property="Text" Value="&#xE70E;"/>
              </Trigger>
              <Trigger Property="SortDirection" Value="Descending">
                <Setter TargetName="Arrow" Property="Visibility" Value="Visible"/>
                <Setter TargetName="Arrow" Property="Text" Value="&#xE70D;"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="10,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="#24406E"/>
          <Setter Property="Foreground" Value="#FFFFFF"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="DataGridRow">
      <Style.Triggers>
        <DataTrigger Binding="{Binding Alert}" Value="True">
          <Setter Property="Foreground" Value="#FF9B8A"/>
        </DataTrigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="NavTab" TargetType="TabItem">
      <Setter Property="Foreground" Value="#9AA4B2"/>
      <Setter Property="Width" Value="220"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="8" Padding="14,11" Margin="10,3,10,3">
              <ContentPresenter ContentSource="Header" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="Background" Value="#181E29"/></Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#1F2838"/>
                <Setter Property="Foreground" Value="#FFFFFF"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="SubTab" TargetType="TabItem">
      <Setter Property="Foreground" Value="#9AA4B2"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Padding="14,7" Margin="0,0,6,10"
                    BorderBrush="#262D3A" BorderThickness="1">
              <ContentPresenter ContentSource="Header" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Bd" Property="BorderBrush" Value="#4F8CFF"/></Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#24406E"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="#4F8CFF"/>
                <Setter Property="Foreground" Value="#FFFFFF"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="#12151C" BorderBrush="#222836" BorderThickness="0,0,0,1">
      <DockPanel Margin="20,0" Height="62" LastChildFill="False">
        <StackPanel DockPanel.Dock="Left" Orientation="Horizontal" VerticalAlignment="Center">
          <Border Width="36" Height="36" CornerRadius="9">
            <Border.Background>
              <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                <GradientStop Color="#4F8CFF" Offset="0"/>
                <GradientStop Color="#7C5CFF" Offset="1"/>
              </LinearGradientBrush>
            </Border.Background>
            <TextBlock Text="&#xE9D9;" FontFamily="Segoe MDL2 Assets" FontSize="18" Foreground="White"
                       HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
            <TextBlock Text="PerfInspector" FontSize="18" FontWeight="SemiBold" Foreground="#FFFFFF"/>
            <TextBlock x:Name="HdrSub" Text="" FontSize="11" Foreground="#8A94A6"/>
          </StackPanel>
        </StackPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
          <Border x:Name="AdminBadge" CornerRadius="10" Padding="10,4" Margin="0,0,12,0" VerticalAlignment="Center">
            <TextBlock x:Name="AdminText" FontSize="11" FontWeight="SemiBold"/>
          </Border>
          <Button x:Name="BtnElevate" Margin="0,0,8,0">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE7EF;" Margin="0,0,8,0" FontSize="13"/><TextBlock Text="Restart as administrator"/></StackPanel>
          </Button>
          <Button x:Name="BtnReport" Style="{StaticResource Accent}" Margin="0">
            <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xEDE1;" Margin="0,0,8,0" FontSize="13"/><TextBlock Text="Full report (HTML)"/></StackPanel>
          </Button>
        </StackPanel>
      </DockPanel>
    </Border>

    <TabControl x:Name="MainTabs" Grid.Row="1" TabStripPlacement="Left" Background="Transparent" BorderThickness="0" Padding="0" Margin="0,10,0,0">

      <!-- ======================= LIVE MONITOR ======================= -->
      <TabItem Style="{StaticResource NavTab}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE9D9;"/><TextBlock Text="Live Monitor"/></StackPanel>
        </TabItem.Header>
        <Grid Margin="6,6,18,12">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="180"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <UniformGrid Rows="1" Columns="5">
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="CPU USAGE"/>
              <TextBlock x:Name="CardCpu" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="CardCpuSub" Style="{StaticResource CardSub}" Text=""/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="MEMORY"/>
              <TextBlock x:Name="CardMem" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="CardMemSub" Style="{StaticResource CardSub}" Text=""/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="PROCESSES"/>
              <TextBlock x:Name="CardProc" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="CardProcSub" Style="{StaticResource CardSub}" Text=""/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="SERVICES RUNNING"/>
              <TextBlock x:Name="CardSvc" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="CardSvcSub" Style="{StaticResource CardSub}" Text=""/></StackPanel></Border>
            <Border Style="{StaticResource Card}"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="UPTIME"/>
              <TextBlock x:Name="CardUp" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="CardUpSub" Style="{StaticResource CardSub}" Text=""/></StackPanel></Border>
          </UniformGrid>
          <Border Grid.Row="1" Style="{StaticResource Card}" Margin="0,10,0,0" Padding="6">
            <Canvas x:Name="LiveChart" ClipToBounds="True"/>
          </Border>
          <WrapPanel Grid.Row="2" Margin="0,12,0,4">
            <TextBlock Text="Search" Foreground="#9AA4B2" VerticalAlignment="Center" Margin="0,0,8,6"/>
            <TextBox x:Name="ProcFilter" Width="200" Margin="0,0,12,6"/>
            <CheckBox x:Name="ProcOnlyFlagged" Content="Only above usual / high usage"/>
            <CheckBox x:Name="LiveAuto" Content="Auto refresh" IsChecked="True" Margin="0,0,6,6"/>
            <ComboBox x:Name="LiveInterval" Width="80" SelectedIndex="1">
              <ComboBoxItem Content="2 s"/><ComboBoxItem Content="5 s"/><ComboBoxItem Content="10 s"/><ComboBoxItem Content="30 s"/>
            </ComboBox>
            <Button x:Name="BtnLiveRefresh" Content="Refresh now"/>
            <Button x:Name="BtnBaseline" Style="{StaticResource Accent}" Content="Record baseline (30 s)"
                    ToolTip="Samples all processes and services for 30 seconds while the PC is in its normal state. Later measurements are compared against it."/>
            <Button x:Name="BtnBaselineClear" Content="Clear baseline"/>
            <Button x:Name="BtnKillProc" Style="{StaticResource Danger}" Content="End process"/>
            <Button x:Name="BtnProcExport" Content="Export..."/>
            <TextBlock x:Name="BaselineInfo" Foreground="#8A94A6" FontSize="11.5" VerticalAlignment="Center" Margin="6,0,0,6"/>
          </WrapPanel>
          <DataGrid x:Name="ProcGrid" Grid.Row="3">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Process" Binding="{Binding Name}" Width="170"/>
              <DataGridTextColumn Header="PID" Binding="{Binding PID}" Width="70" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="CPU %" Binding="{Binding CPU, StringFormat=N1}" Width="80" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="Memory (MB)" Binding="{Binding MemoryMB, StringFormat=N1}" Width="115" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="Disk/Net I/O (KB/s)" Binding="{Binding IOKBs, StringFormat=N1}" Width="140" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="Threads" Binding="{Binding Threads}" Width="78" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="Handles" Binding="{Binding Handles}" Width="82" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="Usage status" Binding="{Binding Status}" Width="260"/>
              <DataGridTextColumn Header="Hosted services" Binding="{Binding Services}" Width="220"/>
              <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="*" MinWidth="220"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>

      <!-- ======================= SERVICES ======================= -->
      <TabItem Style="{StaticResource NavTab}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE713;"/><TextBlock Text="Services"/></StackPanel>
        </TabItem.Header>
        <Grid Margin="6,6,18,12">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <WrapPanel Margin="0,0,0,6">
            <TextBlock Text="Search" Foreground="#9AA4B2" VerticalAlignment="Center" Margin="0,0,8,6"/>
            <TextBox x:Name="SvcFilter" Width="220" Margin="0,0,12,6"/>
            <TextBlock Text="View" Foreground="#9AA4B2" VerticalAlignment="Center" Margin="0,0,8,6"/>
            <ComboBox x:Name="SvcView" Width="230" SelectedIndex="0">
              <ComboBoxItem Content="All services"/>
              <ComboBoxItem Content="Running"/>
              <ComboBoxItem Content="Automatic start"/>
              <ComboBoxItem Content="Above usual / high usage"/>
              <ComboBoxItem Content="Third-party"/>
              <ComboBoxItem Content="With recommendation"/>
            </ComboBox>
            <Button x:Name="BtnSvcRefresh" Content="Refresh"/>
            <Button x:Name="BtnSvcExport" Content="Export..."/>
            <TextBlock x:Name="SvcCount" Foreground="#8A94A6" FontSize="11.5" VerticalAlignment="Center" Margin="6,0,0,6"/>
          </WrapPanel>
          <Grid Grid.Row="1">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="390"/></Grid.ColumnDefinitions>
            <DataGrid x:Name="SvcGrid" Margin="0,0,12,0">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Display name" Binding="{Binding DisplayName}" Width="240"/>
                <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="140"/>
                <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                <DataGridTextColumn Header="Startup type" Binding="{Binding StartType}" Width="145"/>
                <DataGridTextColumn Header="CPU %" Binding="{Binding CPU, StringFormat=N1}" Width="72" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="Memory (MB)" Binding="{Binding MemoryMB, StringFormat=N1}" Width="110" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="I/O (KB/s)" Binding="{Binding IOKBs, StringFormat=N1}" Width="90" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="Impact" Binding="{Binding Impact}" Width="115"/>
                <DataGridTextColumn Header="Usage status" Binding="{Binding Status}" Width="220"/>
                <DataGridTemplateColumn Header="Recommendation" Width="190" SortMemberPath="Recommendation">
                  <DataGridTemplateColumn.CellTemplate>
                    <DataTemplate><TextBlock Text="{Binding Recommendation}" Foreground="{Binding RecColor}" FontWeight="SemiBold" VerticalAlignment="Center"/></DataTemplate>
                  </DataGridTemplateColumn.CellTemplate>
                </DataGridTemplateColumn>
              </DataGrid.Columns>
            </DataGrid>
            <Border Grid.Column="1" Style="{StaticResource Card}" Padding="16">
              <Grid>
                <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                  <StackPanel x:Name="SvcDetails"/>
                </ScrollViewer>
                <StackPanel Grid.Row="1" Margin="0,12,0,0">
                  <TextBlock Style="{StaticResource FieldLabel}" Text="ACTIONS (administrator rights required)"/>
                  <WrapPanel>
                    <Button x:Name="BtnSvcStart" Content="Start"/>
                    <Button x:Name="BtnSvcStop" Content="Stop" Style="{StaticResource Danger}"/>
                    <Button x:Name="BtnSvcRestart" Content="Restart"/>
                  </WrapPanel>
                  <Grid Margin="0,4,0,0">
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                    <ComboBox x:Name="SvcStartType" SelectedIndex="2">
                      <ComboBoxItem Content="Automatic"/>
                      <ComboBoxItem Content="Automatic (Delayed)"/>
                      <ComboBoxItem Content="Manual"/>
                      <ComboBoxItem Content="Disabled"/>
                    </ComboBox>
                    <Button x:Name="BtnSvcApplyType" Grid.Column="1" Content="Set startup type" Margin="0,0,0,6"/>
                  </Grid>
                  <Button x:Name="BtnSvcRestore" Content="Restore original startup types" HorizontalAlignment="Stretch" Margin="0"/>
                </StackPanel>
              </Grid>
            </Border>
          </Grid>
        </Grid>
      </TabItem>

      <!-- ======================= RECOMMENDATIONS ======================= -->
      <TabItem Style="{StaticResource NavTab}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE82F;"/><TextBlock Text="Recommendations"/></StackPanel>
        </TabItem.Header>
        <Grid Margin="6,6,18,12">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Style="{StaticResource Card}" Padding="16">
            <StackPanel>
              <TextBlock Style="{StaticResource SectionTitle}" Text="Service optimization"/>
              <TextBlock x:Name="RecSummary" TextWrapping="Wrap" Foreground="#C9D1DD" Text="Collecting data..."/>
              <TextBlock Style="{StaticResource Hint}" Margin="0,8,0,0"
                         Text="Safe to disable = not needed on typical PCs. Set to Manual = starts automatically on demand. Conditional = depends on whether you use the feature (read the reason). Review = third-party service that starts with Windows. Investigate = currently uses more resources than usual. Every change is backed up and can be restored. Double-click a row to open it in the Services view."/>
            </StackPanel>
          </Border>
          <WrapPanel Grid.Row="1" Margin="0,12,0,4">
            <TextBlock Text="Show" Foreground="#9AA4B2" VerticalAlignment="Center" Margin="0,0,8,6"/>
            <ComboBox x:Name="RecFilter" Width="230" SelectedIndex="0">
              <ComboBoxItem Content="All recommendations"/>
              <ComboBoxItem Content="Safe to disable"/>
              <ComboBoxItem Content="Set to Manual"/>
              <ComboBoxItem Content="Conditional"/>
              <ComboBoxItem Content="Review (third-party)"/>
              <ComboBoxItem Content="Investigate (above usual)"/>
            </ComboBox>
            <Button x:Name="BtnRecManual" Content="Set selected to Manual"/>
            <Button x:Name="BtnRecDisable" Style="{StaticResource Danger}" Content="Disable selected"/>
            <Button x:Name="BtnRecRestore" Content="Restore original startup types"/>
            <Button x:Name="BtnRecExport" Content="Export..."/>
          </WrapPanel>
          <DataGrid x:Name="RecGrid" Grid.Row="2">
            <DataGrid.Columns>
              <DataGridTemplateColumn Header="Recommendation" Width="185" SortMemberPath="Recommendation">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate><TextBlock Text="{Binding Recommendation}" Foreground="{Binding RecColor}" FontWeight="SemiBold" VerticalAlignment="Center"/></DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTextColumn Header="Display name" Binding="{Binding DisplayName}" Width="220" ElementStyle="{StaticResource WrapCell}"/>
              <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="130"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="115"/>
              <DataGridTextColumn Header="State" Binding="{Binding State}" Width="75"/>
              <DataGridTextColumn Header="Startup type" Binding="{Binding StartType}" Width="140"/>
              <DataGridTextColumn Header="Memory (MB)" Binding="{Binding MemoryMB, StringFormat=N1}" Width="105" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="CPU %" Binding="{Binding CPU, StringFormat=N1}" Width="70" ElementStyle="{StaticResource NumCell}"/>
              <DataGridTextColumn Header="Reason" Binding="{Binding Reason}" Width="*" MinWidth="320" ElementStyle="{StaticResource WrapCell}"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>

      <!-- ======================= APP START TEST ======================= -->
      <TabItem Style="{StaticResource NavTab}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE916;"/><TextBlock Text="App Start Test"/></StackPanel>
        </TabItem.Header>
        <Grid Margin="6,6,18,12">
          <Grid.ColumnDefinitions><ColumnDefinition Width="370"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,0,12,0">
            <StackPanel>
              <Border Style="{StaticResource Card}" Padding="16">
                <StackPanel>
                  <TextBlock Style="{StaticResource SectionTitle}" Text="Automatic launch test"/>
                  <TextBlock Style="{StaticResource Hint}" Text="Launches the application several times and measures: process created, ready for input (input idle) and main window visible."/>
                  <TextBlock Style="{StaticResource FieldLabel}" Text="APPLICATION (.exe, shortcut or shell:AppsFolder\...)"/>
                  <DockPanel>
                    <Button x:Name="BtnBrowseExe" DockPanel.Dock="Right" Content="Browse..." Margin="8,0,0,0"/>
                    <TextBox x:Name="TestExe"/>
                  </DockPanel>
                  <TextBlock Style="{StaticResource FieldLabel}" Text="ARGUMENTS (optional)"/>
                  <TextBox x:Name="TestArgs"/>
                  <Grid Margin="0,0,0,0">
                    <Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="8"/><ColumnDefinition/><ColumnDefinition Width="8"/><ColumnDefinition/></Grid.ColumnDefinitions>
                    <StackPanel><TextBlock Style="{StaticResource FieldLabel}" Text="RUNS"/><TextBox x:Name="TestIterations" Text="5"/></StackPanel>
                    <StackPanel Grid.Column="2"><TextBlock Style="{StaticResource FieldLabel}" Text="PAUSE (S)"/><TextBox x:Name="TestDelay" Text="3"/></StackPanel>
                    <StackPanel Grid.Column="4"><TextBlock Style="{StaticResource FieldLabel}" Text="TIMEOUT (S)"/><TextBox x:Name="TestTimeout" Text="60"/></StackPanel>
                  </Grid>
                  <TextBlock Style="{StaticResource FieldLabel}" Text="PROCESS NAME(S) TO WATCH (optional, for launcher apps)"/>
                  <TextBox x:Name="TestWatch" ToolTip="e.g. 'Teams' or 'chrome'. Needed when the started file only launches another process (launchers, Store apps, shortcuts)."/>
                  <CheckBox x:Name="TestCloseAfter" Content="Close the application after each run (cold start)" IsChecked="True" Margin="0,12,0,10"/>
                  <WrapPanel>
                    <Button x:Name="BtnTestRun" Style="{StaticResource Accent}">
                      <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE768;" Margin="0,0,8,0" FontSize="12"/><TextBlock Text="Run test"/></StackPanel>
                    </Button>
                    <Button x:Name="BtnTestCancel" Content="Cancel" IsEnabled="False"/>
                  </WrapPanel>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Padding="16" Margin="0,12,0,0">
                <StackPanel>
                  <TextBlock Style="{StaticResource SectionTitle}" Text="Manual measurement"/>
                  <TextBlock Style="{StaticResource Hint}" Text="1. Optionally enter the process name of the app.  2. Click 'Start stopwatch'.  3. Start the app yourself (Start menu, desktop, taskbar...).  4. Click 'App is ready' as soon as the app is usable. Process and window are detected automatically."/>
                  <TextBlock Style="{StaticResource FieldLabel}" Text="PROCESS NAME TO DETECT (optional)"/>
                  <TextBox x:Name="ManualProc"/>
                  <CheckBox x:Name="ManualAutoStop" Content="Stop automatically when the main window appears" Margin="0,10,0,10"/>
                  <WrapPanel>
                    <Button x:Name="BtnManualStart" Style="{StaticResource Accent}" Content="Start stopwatch"/>
                    <Button x:Name="BtnManualReady" Content="App is ready" IsEnabled="False"/>
                    <Button x:Name="BtnManualCancel" Content="Cancel" IsEnabled="False"/>
                  </WrapPanel>
                  <TextBlock x:Name="ManualTimer" Text="00:00.000" FontFamily="Consolas" FontSize="30" Foreground="#FFFFFF" Margin="0,6,0,0"/>
                  <TextBlock x:Name="ManualInfo" Style="{StaticResource Hint}" Margin="0,4,0,0"/>
                </StackPanel>
              </Border>
              <Border Style="{StaticResource Card}" Padding="16" Margin="0,12,0,0">
                <StackPanel>
                  <TextBlock Style="{StaticResource SectionTitle}" Text="Statistics"/>
                  <TextBlock x:Name="TestStats" FontFamily="Consolas" FontSize="12" Foreground="#C9D1DD" TextWrapping="Wrap" Text="No results yet."/>
                </StackPanel>
              </Border>
            </StackPanel>
          </ScrollViewer>
          <Grid Grid.Column="1">
            <Grid.RowDefinitions><RowDefinition Height="360"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
            <Border Style="{StaticResource Card}" Padding="6"><Canvas x:Name="StartChart" ClipToBounds="True"/></Border>
            <WrapPanel Grid.Row="1" Margin="0,12,0,4">
              <Button x:Name="BtnTestExport" Content="Export results..."/>
              <Button x:Name="BtnTestChartPng" Content="Save chart as PNG..."/>
              <Button x:Name="BtnTestClear" Content="Clear results"/>
            </WrapPanel>
            <DataGrid x:Name="TestGrid" Grid.Row="2">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Run" Binding="{Binding Run}" Width="50" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="Mode" Binding="{Binding Mode}" Width="90"/>
                <DataGridTextColumn Header="Application" Binding="{Binding Application}" Width="140"/>
                <DataGridTextColumn Header="Process (ms)" Binding="{Binding ProcessMs}" Width="100" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="Input idle (ms)" Binding="{Binding InputIdleMs}" Width="115" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="Window (ms)" Binding="{Binding WindowMs}" Width="100" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="User ready (ms)" Binding="{Binding UserReadyMs}" Width="120" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="Total (ms)" Binding="{Binding TotalMs}" Width="90" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="RAM (MB)" Binding="{Binding MemoryMB}" Width="85" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="CPU time (ms)" Binding="{Binding CpuTimeMs}" Width="110" ElementStyle="{StaticResource NumCell}"/>
                <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="190"/>
                <DataGridTextColumn Header="Time" Binding="{Binding Timestamp, StringFormat=G}" Width="*" MinWidth="150"/>
              </DataGrid.Columns>
            </DataGrid>
          </Grid>
        </Grid>
      </TabItem>

      <!-- ======================= BOOT & AUTOSTART ======================= -->
      <TabItem Style="{StaticResource NavTab}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE7E8;"/><TextBlock Text="Boot &amp; Autostart"/></StackPanel>
        </TabItem.Header>
        <Grid Margin="6,6,18,12">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <UniformGrid Rows="1" Columns="6">
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="LAST FULL BOOT"/>
              <TextBlock x:Name="BootCardLast" Style="{StaticResource CardValue}" FontSize="17" Text="--"/>
              <TextBlock x:Name="BootCardLastSub" Style="{StaticResource CardSub}"/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="LAST START (INCL. FAST STARTUP)"/>
              <TextBlock x:Name="BootCardRef" Style="{StaticResource CardValue}" FontSize="17" Text="--"/>
              <TextBlock x:Name="BootCardRefSub" Style="{StaticResource CardSub}"/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="LAST BOOT DURATION"/>
              <TextBlock x:Name="BootCardDur" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="BootCardDurSub" Style="{StaticResource CardSub}"/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="AVERAGE BOOT"/>
              <TextBlock x:Name="BootCardAvg" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="BootCardAvgSub" Style="{StaticResource CardSub}"/></StackPanel></Border>
            <Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="AUTOSTART"/>
              <TextBlock x:Name="BootCardApps" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="BootCardAppsSub" Style="{StaticResource CardSub}"/></StackPanel></Border>
            <Border Style="{StaticResource Card}"><StackPanel>
              <TextBlock Style="{StaticResource CardLabel}" Text="FAST STARTUP"/>
              <TextBlock x:Name="BootCardFast" Style="{StaticResource CardValue}" Text="--"/>
              <TextBlock x:Name="BootCardFastSub" Style="{StaticResource CardSub}"/></StackPanel></Border>
          </UniformGrid>
          <StackPanel Grid.Row="1" Margin="0,12,0,4">
            <WrapPanel>
              <Button x:Name="BtnBootAnalyze" Style="{StaticResource Accent}">
                <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE72C;" Margin="0,0,8,0" FontSize="12"/><TextBlock Text="Analyze boot &amp; autostart"/></StackPanel>
              </Button>
              <CheckBox x:Name="BootIncludeMs" Content="Include Microsoft scheduled tasks"/>
              <Button x:Name="BtnStartupToggle" Content="Enable / disable selected startup app"/>
              <Button x:Name="BtnBootExport" Content="Export current view..."/>
              <Button x:Name="BtnBootChartPng" Content="Save chart as PNG..."/>
            </WrapPanel>
            <TextBlock x:Name="BootNote" Style="{StaticResource Hint}" Margin="0,2,0,6"/>
          </StackPanel>
          <TabControl x:Name="BootTabs" Grid.Row="2" Background="Transparent" BorderThickness="0" Padding="0">
            <TabItem Header="Boot history" Style="{StaticResource SubTab}">
              <Grid>
                <Grid.RowDefinitions><RowDefinition Height="270"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Border Style="{StaticResource Card}" Padding="6" Margin="0,0,0,10"><Canvas x:Name="BootChart" ClipToBounds="True"/></Border>
                <DataGrid x:Name="BootGrid" Grid.Row="1">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Date" Binding="{Binding Date, StringFormat=G}" Width="170"/>
                    <DataGridTextColumn Header="Total boot (s)" Binding="{Binding BootSec}" Width="120" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTextColumn Header="Main path - until desktop (s)" Binding="{Binding MainPathSec}" Width="210" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTextColumn Header="Post boot - until idle (s)" Binding="{Binding PostBootSec}" Width="190" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTextColumn Header="Rating" Binding="{Binding Rating}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
            <TabItem Header="Startup apps" Style="{StaticResource SubTab}">
              <Grid>
                <Grid.RowDefinitions><RowDefinition Height="270"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Border Style="{StaticResource Card}" Padding="6" Margin="0,0,0,10"><Canvas x:Name="AppBootChart" ClipToBounds="True"/></Border>
                <DataGrid x:Name="StartupGrid" Grid.Row="1" SelectionMode="Single">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Status" Binding="{Binding EnabledText}" Width="80"/>
                    <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="190"/>
                    <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="160"/>
                    <DataGridTextColumn Header="Location" Binding="{Binding Location}" Width="190"/>
                    <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="110"/>
                    <DataGridTextColumn Header="Running" Binding="{Binding Running}" Width="75"/>
                    <DataGridTextColumn Header="Started after boot (s)" Binding="{Binding StartedAfterBootSec}" Width="160" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTextColumn Header="Delay" Binding="{Binding Delay}" Width="70"/>
                    <DataGridTextColumn Header="Command" Binding="{Binding Command}" Width="*" MinWidth="250"/>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
            <TabItem Header="Services at boot" Style="{StaticResource SubTab}">
              <Grid>
                <Grid.RowDefinitions><RowDefinition Height="270"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Border Style="{StaticResource Card}" Padding="6" Margin="0,0,0,10"><Canvas x:Name="SvcBootChart" ClipToBounds="True"/></Border>
                <DataGrid x:Name="SvcBootGrid" Grid.Row="1">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Display name" Binding="{Binding DisplayName}" Width="260"/>
                    <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="150"/>
                    <DataGridTextColumn Header="Startup type" Binding="{Binding StartType}" Width="165"/>
                    <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                    <DataGridTextColumn Header="Started after boot (s)" Binding="{Binding StartedAfterBootSec}" Width="160" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTextColumn Header="Boot delay caused (ms)" Binding="{Binding BootDelayMs, StringFormat=N0}" Width="170" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTemplateColumn Header="Recommendation" Width="*" MinWidth="170" SortMemberPath="Recommendation">
                      <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate><TextBlock Text="{Binding Recommendation}" Foreground="{Binding RecColor}" FontWeight="SemiBold" VerticalAlignment="Center"/></DataTemplate>
                      </DataGridTemplateColumn.CellTemplate>
                    </DataGridTemplateColumn>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
            <TabItem Header="Boot slowdowns" Style="{StaticResource SubTab}">
              <DataGrid x:Name="DegGrid">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Date" Binding="{Binding Date, StringFormat=G}" Width="170"/>
                  <DataGridTextColumn Header="Event" Binding="{Binding EventId}" Width="70"/>
                  <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="170"/>
                  <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="280"/>
                  <DataGridTextColumn Header="Total time (ms)" Binding="{Binding TotalMs, StringFormat=N0}" Width="130" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTextColumn Header="Slowdown (ms)" Binding="{Binding DegradationMs, StringFormat=N0}" Width="125" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTextColumn Header="File / internal name" Binding="{Binding File}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Service errors since boot" Style="{StaticResource SubTab}">
              <DataGrid x:Name="IssueGrid">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Date" Binding="{Binding Date, StringFormat=G}" Width="170"/>
                  <DataGridTextColumn Header="Event" Binding="{Binding EventId}" Width="70"/>
                  <DataGridTextColumn Header="Service" Binding="{Binding Service}" Width="220"/>
                  <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*" ElementStyle="{StaticResource WrapCell}"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
          </TabControl>
        </Grid>
      </TabItem>
    </TabControl>

    <!-- Status bar -->
    <Border Grid.Row="2" Background="#12151C" BorderBrush="#222836" BorderThickness="0,1,0,0">
      <Grid Margin="16,0" Height="30">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="160"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <TextBlock x:Name="StatusText" VerticalAlignment="Center" Foreground="#9AA4B2" FontSize="12" TextTrimming="CharacterEllipsis" Text="Ready"/>
        <ProgressBar x:Name="BusyBar" Grid.Column="1" Height="4" Background="#1C212B" BorderThickness="0" Foreground="#4F8CFF" Visibility="Hidden"/>
        <TextBlock x:Name="StatusRight" Grid.Column="2" Margin="14,0,0,0" VerticalAlignment="Center" Foreground="#6B7385" FontSize="12"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@
#endregion

#region ---------------------------------------------------------------- Load window
[xml]$xamlXml = $xaml
$script:Window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xamlXml))
$script:UI = @{}
foreach ($node in $xamlXml.SelectNodes('//*[@*[local-name()="Name"]]')) {
    $n = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
    if ($n) { $obj = $script:Window.FindName($n); if ($obj) { $script:UI[$n] = $obj } }
}
$UI = $script:UI
try { $script:Window.Language = [Windows.Markup.XmlLanguage]::GetLanguage([Globalization.CultureInfo]::CurrentCulture.IetfLanguageTag) } catch { }
#endregion

#region ---------------------------------------------------------------- State
$script:Sync = [hashtable]::Synchronized(@{
        Progress    = ''
        Cancel      = $false
        TestResults = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList))
    })
$script:Jobs          = New-Object Collections.ArrayList
$script:LastSnap      = $null
$script:BootData      = $null
$script:BaselineProc  = $null
$script:BaselineSvc   = $null
$script:TestResults   = New-Object Collections.Generic.List[object]
$script:TestIngested  = 0
$script:TestRunning   = $false
$script:SnapshotBusy  = $false
$script:BaselineBusy  = $false
$script:BootBusy      = $false
$script:Manual        = $null
$script:ProcSortInit  = $false
$script:CpuHist       = New-Object Collections.Generic.List[double]
$script:MemHist       = New-Object Collections.Generic.List[double]
$script:BrushCache    = @{}
$script:FontUI        = New-Object Windows.Media.FontFamily 'Segoe UI'
$script:ManualTimer   = $null

$script:SysInfo = [ordered]@{ Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME" }
try {
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $osi = Get-CimInstance Win32_OperatingSystem
    $script:SysInfo['OS']     = "$($osi.Caption) (version $($osi.Version), build $($osi.BuildNumber))"
    $script:SysInfo['Model']  = "$($cs.Manufacturer) $($cs.Model)"
    $script:SysInfo['CPU']    = ([string]$cpu.Name).Trim()
    $script:SysInfo['Cores']  = "$($cpu.NumberOfCores) cores / $([Environment]::ProcessorCount) logical processors"
    $script:SysInfo['RAM']    = '{0:N1} GB' -f ($cs.TotalPhysicalMemory / 1GB)
} catch { }
#endregion

#region ---------------------------------------------------------------- Runspace pool + async jobs
$iss = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
try { $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass } catch { }
foreach ($fn in 'Get-PerfSnapshot', 'Get-BootAnalysis', 'Get-ExePathFromCommand', 'Invoke-AppStartTest') {
    $def = (Get-Command -Name $fn -CommandType Function).ScriptBlock.ToString()
    $iss.Commands.Add((New-Object Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $fn, $def))
}
$script:Pool = [runspacefactory]::CreateRunspacePool(1, 4, $iss, $Host)
$script:Pool.Open()

function Start-AsyncTask {
    param([Parameter(Mandatory)][scriptblock]$Script, [hashtable]$Parameters = @{}, [scriptblock]$OnComplete, [string]$Status = 'Working...')
    $ps = [powershell]::Create()
    $ps.RunspacePool = $script:Pool
    [void]$ps.AddScript($Script.ToString())
    if ($Parameters.Count) { [void]$ps.AddParameters($Parameters) }
    $job = [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); OnComplete = $OnComplete; Status = $Status }
    [void]$script:Jobs.Add($job)
    Set-Status $Status
    Update-BusyState
}

function Invoke-JobPump {
    foreach ($job in @($script:Jobs)) {
        if (-not $job.Handle.IsCompleted) { continue }
        [void]$script:Jobs.Remove($job)
        $result = $null; $err = $null
        try { $result = $job.PS.EndInvoke($job.Handle) }
        catch { $err = $_.Exception; if ($err.InnerException) { $err = $err.InnerException } }
        if (-not $err -and $job.PS.Streams.Error.Count -gt 0 -and -not $result) { $err = $job.PS.Streams.Error[0].Exception }
        $job.PS.Dispose()
        if ($job.OnComplete) {
            try { & $job.OnComplete $result $err }
            catch { Set-Status "Error while processing results: $($_.Exception.Message)" }
        }
    }
    Invoke-TestIngest
    if ($script:Jobs.Count -gt 0 -and $script:Sync.Progress) { Set-Status $script:Sync.Progress }
    Update-BusyState
}
#endregion

#region ---------------------------------------------------------------- Generic helpers
function Set-Status([string]$Text) { $UI.StatusText.Text = $Text }

function Update-BusyState {
    $busy = ($script:Jobs.Count -gt 0) -or ($null -ne $script:Manual)
    $UI.BusyBar.IsIndeterminate = $busy
    $UI.BusyBar.Visibility = $(if ($busy) { 'Visible' } else { 'Hidden' })
}

function Show-Info([string]$Text, [string]$Title = 'PerfInspector') {
    [void][Windows.MessageBox]::Show($script:Window, $Text, $Title, [Windows.MessageBoxButton]::OK, [Windows.MessageBoxImage]::Information)
}
function Show-ErrorMessage([string]$Text) {
    [void][Windows.MessageBox]::Show($script:Window, $Text, 'PerfInspector', [Windows.MessageBoxButton]::OK, [Windows.MessageBoxImage]::Error)
}
function Confirm-Action([string]$Text, [string]$Title = 'Please confirm') {
    ([Windows.MessageBox]::Show($script:Window, $Text, $Title, [Windows.MessageBoxButton]::YesNo, [Windows.MessageBoxImage]::Warning)) -eq [Windows.MessageBoxResult]::Yes
}
function Test-AdminOrWarn([string]$What) {
    if ($script:IsAdmin) { return $true }
    Show-Info "$What requires administrator rights.`n`nUse 'Restart as administrator' in the top-right corner."
    $false
}
function Test-Contains($Value, [string]$Text) {
    if (-not $Value) { return $false }
    ([string]$Value).IndexOf($Text, [StringComparison]::OrdinalIgnoreCase) -ge 0
}
function Format-Num([double]$v) {
    $a = [Math]::Abs($v)
    if ($a -ge 100) { '{0:N0}' -f $v } elseif ($a -ge 10) { '{0:N1}' -f $v } else { '{0:N2}' -f $v }
}
function Format-Uptime([TimeSpan]$ts) {
    if ($ts.TotalDays -ge 1) { '{0}d {1}h {2}m' -f $ts.Days, $ts.Hours, $ts.Minutes } else { '{0}h {1}m' -f $ts.Hours, $ts.Minutes }
}
function Get-RecColor([string]$Rec) {
    switch -Wildcard ($Rec) {
        'Safe to disable'  { '#2ECC71' }
        'Set to Manual'    { '#4F9DFF' }
        'Conditional'      { '#F5A524' }
        'Review*'          { '#B08CFF' }
        'Investigate*'     { '#FF8A3D' }
        'Keep (critical)'  { '#FF6B6B' }
        default            { '#8A94A6' }
    }
}

function Get-ChildOfType($Parent, [type]$Type) {
    if (-not $Parent) { return $null }
    $count = [Windows.Media.VisualTreeHelper]::GetChildrenCount($Parent)
    for ($i = 0; $i -lt $count; $i++) {
        $ch = [Windows.Media.VisualTreeHelper]::GetChild($Parent, $i)
        if ($ch -is $Type) { return $ch }
        $found = Get-ChildOfType $ch $Type
        if ($found) { return $found }
    }
    $null
}

# Replaces the rows of a grid while keeping sort order, selection and scroll position
function Set-GridItems {
    param($Grid, $Items, [string]$Key)
    $sorts = @($Grid.Items.SortDescriptions)
    $sv = Get-ChildOfType $Grid ([Windows.Controls.ScrollViewer])
    $off = if ($sv) { $sv.VerticalOffset } else { 0 }
    $selKeys = @{}
    if ($Key) { foreach ($it in @($Grid.SelectedItems)) { $selKeys[[string]$it.$Key] = $true } }
    $Grid.ItemsSource = @($Items)
    if ($sorts.Count) {
        foreach ($sd in $sorts) { $Grid.Items.SortDescriptions.Add($sd) }
        foreach ($col in $Grid.Columns) {
            $col.SortDirection = $null
            foreach ($sd in $sorts) { if ($col.SortMemberPath -eq $sd.PropertyName) { $col.SortDirection = $sd.Direction } }
        }
    }
    if ($selKeys.Count) {
        foreach ($it in $Grid.Items) { if ($selKeys.ContainsKey([string]$it.$Key)) { [void]$Grid.SelectedItems.Add($it) } }
    }
    if ($sv -and $off -gt 0) { $Grid.UpdateLayout(); $sv.ScrollToVerticalOffset($off) }
}

function Set-GridSort($Grid, [string]$Property, [ComponentModel.ListSortDirection]$Direction) {
    $Grid.Items.SortDescriptions.Clear()
    $Grid.Items.SortDescriptions.Add((New-Object ComponentModel.SortDescription $Property, $Direction))
    foreach ($col in $Grid.Columns) { $col.SortDirection = $(if ($col.SortMemberPath -eq $Property) { $Direction } else { $null }) }
}
#endregion

#region ---------------------------------------------------------------- Chart engine (pure WPF, no extra libraries)
function Get-Brush([string]$Hex) {
    if (-not $script:BrushCache.ContainsKey($Hex)) {
        $b = New-Object Windows.Media.SolidColorBrush ([Windows.Media.Color][Windows.Media.ColorConverter]::ConvertFromString($Hex))
        $b.Freeze()
        $script:BrushCache[$Hex] = $b
    }
    $script:BrushCache[$Hex]
}
function Add-CText {
    param($C, [string]$Text, [double]$X, [double]$Y, [double]$Size = 11, [string]$Color = '#9AA4B2', [switch]$Bold, [double]$MaxW = 0, [string]$Align = 'Left')
    $tb = New-Object Windows.Controls.TextBlock
    $tb.Text = $Text
    $tb.FontSize = $Size
    $tb.FontFamily = $script:FontUI
    $tb.Foreground = Get-Brush $Color
    if ($Bold) { $tb.FontWeight = [Windows.FontWeights]::SemiBold }
    if ($MaxW -gt 0) {
        $tb.Width = $MaxW
        $tb.TextAlignment = [Windows.TextAlignment]$Align
        $tb.TextTrimming = [Windows.TextTrimming]::CharacterEllipsis
    }
    [Windows.Controls.Canvas]::SetLeft($tb, $X)
    [Windows.Controls.Canvas]::SetTop($tb, $Y)
    [void]$C.Children.Add($tb)
}
function Add-CLine {
    param($C, [double]$X1, [double]$Y1, [double]$X2, [double]$Y2, [string]$Color = '#262D3A', [double]$Thickness = 1, [switch]$Dash)
    $ln = New-Object Windows.Shapes.Line
    $ln.X1 = $X1; $ln.Y1 = $Y1; $ln.X2 = $X2; $ln.Y2 = $Y2
    $ln.Stroke = Get-Brush $Color
    $ln.StrokeThickness = $Thickness
    if ($Dash) { $ln.StrokeDashArray = [Windows.Media.DoubleCollection]::Parse('5 3') }
    [void]$C.Children.Add($ln)
}
function Add-CRect {
    param($C, [double]$X, [double]$Y, [double]$Width, [double]$Height, [string]$Color, [string]$Tip, [double]$Radius = 2)
    $r = New-Object Windows.Shapes.Rectangle
    $r.Width = [Math]::Max(0, $Width)
    $r.Height = [Math]::Max(0, $Height)
    $r.Fill = Get-Brush $Color
    $r.RadiusX = $Radius; $r.RadiusY = $Radius
    if ($Tip) { $r.ToolTip = $Tip }
    [Windows.Controls.Canvas]::SetLeft($r, $X)
    [Windows.Controls.Canvas]::SetTop($r, $Y)
    [void]$C.Children.Add($r)
}
function Add-Legend {
    param($C, [object[]]$Items, [double]$Right, [double]$Y)
    $x = $Right
    for ($k = $Items.Count - 1; $k -ge 0; $k--) {
        $txt = [string]$Items[$k].N
        $x -= ($txt.Length * 6.2 + 30)
        Add-CRect $C $x ($Y + 4) 10 10 $Items[$k].C $null 2
        Add-CText $C $txt ($x + 15) $Y 11 '#C9D1DD'
    }
}
function Get-NiceMax([double]$v) {
    if ($v -le 0 -or [double]::IsNaN($v)) { return 1 }
    $mag = [Math]::Pow(10, [Math]::Floor([Math]::Log10($v)))
    foreach ($m in 1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10) { if ($m * $mag -ge $v) { return $m * $mag } }
    10 * $mag
}

function Draw-StackedBarChart {
    param($Canvas, [string[]]$Categories, [object[]]$Series, [string]$Title, [string]$Unit = 'ms', [double]$AvgLine = -1,
        [string]$EmptyText = 'No data yet.', [double]$W = 0, [double]$H = 0)
    $C = $Canvas
    $C.Children.Clear()
    if ($W -le 0) { $W = $C.ActualWidth }
    if ($H -le 0) { $H = $C.ActualHeight }
    if ($W -lt 80 -or $H -lt 80) { return }
    Add-CText $C $Title 8 4 13 '#E6EAF0' -Bold
    $n = @($Categories).Count
    if ($n -eq 0) { Add-CText $C $EmptyText 0 ($H / 2 - 10) 12 '#6B7385' -MaxW $W -Align Center; return }
    $L = 64; $R = 16; $T = 46; $B = 38
    $pw = $W - $L - $R; $ph = $H - $T - $B
    $totals = New-Object double[] $n
    for ($i = 0; $i -lt $n; $i++) { foreach ($s in $Series) { $totals[$i] += [double]$s.Data[$i] } }
    $maxV = ($totals | Measure-Object -Maximum).Maximum
    if ($AvgLine -gt $maxV) { $maxV = $AvgLine }
    $max = Get-NiceMax $maxV
    for ($g = 0; $g -le 5; $g++) {
        $y = $T + $ph - ($ph * $g / 5)
        Add-CLine $C $L $y ($L + $pw) $y '#232A36' 1
        Add-CText $C (Format-Num ($max * $g / 5)) 0 ($y - 8) 10 '#8A94A6' -MaxW ($L - 8) -Align Right
    }
    Add-CText $C $Unit 0 ($T - 22) 10 '#6B7385' -MaxW ($L - 8) -Align Right
    $slot = $pw / $n
    $bw = [Math]::Max(3, [Math]::Min(56, $slot * 0.62))
    $labelStep = [Math]::Max(1, [int][Math]::Ceiling(80 / $slot))
    for ($i = 0; $i -lt $n; $i++) {
        $x = $L + $slot * $i + ($slot - $bw) / 2
        $acc = 0.0
        foreach ($s in $Series) {
            $v = [double]$s.Data[$i]
            if ($v -le 0) { continue }
            $bh = $ph * $v / $max
            $y = $T + $ph - $ph * ($acc + $v) / $max
            Add-CRect $C $x $y $bw $bh $s.Color ("{0}`n{1}: {2} {3}" -f $Categories[$i], $s.Name, (Format-Num $v), $Unit)
            $acc += $v
        }
        if ($slot -ge 36 -and $acc -gt 0) {
            Add-CText $C (Format-Num $acc) ($L + $slot * $i) ($T + $ph - $ph * $acc / $max - 16) 10 '#C9D1DD' -MaxW $slot -Align Center
        }
        if ($i % $labelStep -eq 0) {
            $lw = $slot * $labelStep
            Add-CText $C $Categories[$i] ($L + $slot * $i + $slot / 2 - $lw / 2) ($T + $ph + 7) 10 '#9AA4B2' -MaxW $lw -Align Center
        }
    }
    if ($AvgLine -gt 0) {
        $y = $T + $ph - $ph * $AvgLine / $max
        Add-CLine $C $L $y ($L + $pw) $y '#F5A524' 1.5 -Dash
        Add-CText $C ('avg {0} {1}' -f (Format-Num $AvgLine), $Unit) ($L + $pw - 150) ($y - 17) 10 '#F5A524' -MaxW 146 -Align Right
    }
    $leg = @($Series | Where-Object { ($_.Data | Measure-Object -Maximum).Maximum -gt 0 } | ForEach-Object { @{ N = $_.Name; C = $_.Color } })
    if ($leg.Count) { Add-Legend $C $leg ($W - $R) 24 }
}

function Draw-HBarChart {
    param($Canvas, [string[]]$Labels, [double[]]$Values, [string]$Title, [string]$Unit = 's', [string]$Color = '#4F8CFF',
        [string[]]$Colors, [string]$EmptyText = 'No data yet.', [double]$W = 0, [double]$H = 0)
    $C = $Canvas
    $C.Children.Clear()
    if ($W -le 0) { $W = $C.ActualWidth }
    if ($H -le 0) { $H = $C.ActualHeight }
    if ($W -lt 80 -or $H -lt 80) { return }
    Add-CText $C $Title 8 4 13 '#E6EAF0' -Bold
    $n = @($Labels).Count
    if ($n -eq 0) { Add-CText $C $EmptyText 0 ($H / 2 - 10) 12 '#6B7385' -MaxW $W -Align Center; return }
    $L = [Math]::Min(280, [Math]::Max(130, $W * 0.27)); $R = 70; $T = 34; $B = 26
    $pw = $W - $L - $R; $ph = $H - $T - $B
    $rowH = 19
    $count = [Math]::Min($n, [Math]::Max(1, [int][Math]::Floor($ph / $rowH)))
    $maxV = 0.0
    for ($i = 0; $i -lt $count; $i++) { if ($Values[$i] -gt $maxV) { $maxV = $Values[$i] } }
    $max = Get-NiceMax $maxV
    for ($g = 0; $g -le 4; $g++) {
        $x = $L + $pw * $g / 4
        Add-CLine $C $x $T $x ($T + $count * $rowH) '#232A36' 1
        Add-CText $C ('{0} {1}' -f (Format-Num ($max * $g / 4)), $Unit) ($x - 40) ($T + $count * $rowH + 4) 10 '#8A94A6' -MaxW 80 -Align Center
    }
    for ($i = 0; $i -lt $count; $i++) {
        $y = $T + $i * $rowH
        $col = if ($Colors -and $Colors.Count -gt $i -and $Colors[$i]) { $Colors[$i] } else { $Color }
        Add-CText $C $Labels[$i] 0 ($y + 1) 11 '#C9D1DD' -MaxW ($L - 10) -Align Right
        $bwid = $pw * $Values[$i] / $max
        Add-CRect $C $L ($y + 3) $bwid ($rowH - 6) $col ('{0}: {1} {2}' -f $Labels[$i], (Format-Num $Values[$i]), $Unit)
        Add-CText $C ('{0} {1}' -f (Format-Num $Values[$i]), $Unit) ($L + $bwid + 6) ($y + 1) 10 '#9AA4B2'
    }
    if ($n -gt $count) { Add-CText $C ("+ $($n - $count) more (see table)") ($W - 190) 6 10 '#6B7385' -MaxW 180 -Align Right }
}

function Draw-LineChart {
    param($Canvas, [object[]]$Series, [string]$Title, [double]$MaxY = 100, [string]$Unit = '%', [int]$Slots = 60, [double]$W = 0, [double]$H = 0)
    $C = $Canvas
    $C.Children.Clear()
    if ($W -le 0) { $W = $C.ActualWidth }
    if ($H -le 0) { $H = $C.ActualHeight }
    if ($W -lt 80 -or $H -lt 60) { return }
    Add-CText $C $Title 8 4 13 '#E6EAF0' -Bold
    $L = 44; $R = 12; $T = 32; $B = 10
    $pw = $W - $L - $R; $ph = $H - $T - $B
    foreach ($g in 0, 25, 50, 75, 100) {
        $y = $T + $ph - $ph * $g / $MaxY
        Add-CLine $C $L $y ($L + $pw) $y '#232A36' 1
        Add-CText $C ("$g$Unit") 0 ($y - 8) 10 '#8A94A6' -MaxW ($L - 6) -Align Right
    }
    $step = $pw / [Math]::Max(1, $Slots - 1)
    $leg = New-Object Collections.Generic.List[object]
    foreach ($s in $Series) {
        $vals = @($s.Data)
        if ($vals.Count -eq 0) { continue }
        $startX = $L + $pw - ($vals.Count - 1) * $step
        $pts = New-Object Windows.Media.PointCollection
        $fill = New-Object Windows.Media.PointCollection
        $fill.Add([Windows.Point]::new($startX, $T + $ph))
        for ($i = 0; $i -lt $vals.Count; $i++) {
            $v = [Math]::Min($MaxY, [Math]::Max(0, [double]$vals[$i]))
            $pt = [Windows.Point]::new($startX + $i * $step, $T + $ph - $ph * $v / $MaxY)
            $pts.Add($pt); $fill.Add($pt)
        }
        $fill.Add([Windows.Point]::new($startX + ($vals.Count - 1) * $step, $T + $ph))
        $pg = New-Object Windows.Shapes.Polygon
        $pg.Points = $fill
        $pg.Fill = Get-Brush ('#22' + $s.Color.Substring(1))
        [void]$C.Children.Add($pg)
        $pl = New-Object Windows.Shapes.Polyline
        $pl.Points = $pts
        $pl.Stroke = Get-Brush $s.Color
        $pl.StrokeThickness = 2
        $pl.StrokeLineJoin = [Windows.Media.PenLineJoin]::Round
        [void]$C.Children.Add($pl)
        $leg.Add(@{ N = ('{0}: {1:N0}{2}' -f $s.Name, [double]$vals[-1], $Unit); C = $s.Color })
    }
    if ($leg.Count) { Add-Legend $C $leg.ToArray() ($W - $R) 6 }
}

function Get-ChartBitmap {
    param([string]$Renderer, [double]$W = 1100, [double]$H = 420)
    $cv = New-Object Windows.Controls.Canvas
    $cv.Width = $W; $cv.Height = $H
    $cv.Background = Get-Brush '#161A22'
    $null = & $Renderer $cv $W $H
    $cv.Measure((New-Object Windows.Size $W, $H))
    $cv.Arrange((New-Object Windows.Rect 0, 0, $W, $H))
    $cv.UpdateLayout()
    $rtb = [Windows.Media.Imaging.RenderTargetBitmap]::new([int]$W, [int]$H, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($cv)
    $rtb
}
function Get-ChartPngBytes {
    param([string]$Renderer, [double]$W = 1100, [double]$H = 420)
    $bmp = Get-ChartBitmap $Renderer $W $H
    $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $ms = New-Object IO.MemoryStream
    $enc.Save($ms)
    , $ms.ToArray()
}
function Save-ChartPng {
    param([string]$Renderer, [string]$BaseName, $Canvas)
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'PNG image|*.png'
    $dlg.FileName = '{0}_{1:yyyyMMdd_HHmmss}' -f $BaseName, (Get-Date)
    if (-not $dlg.ShowDialog($script:Window)) { return }
    $w = [Math]::Max(1000, $Canvas.ActualWidth)
    $h = [Math]::Max(380, $Canvas.ActualHeight)
    try {
        [IO.File]::WriteAllBytes($dlg.FileName, (Get-ChartPngBytes $Renderer $w $h))
        Set-Status "Chart saved to $($dlg.FileName)"
    } catch { Show-ErrorMessage "Could not save the chart: $($_.Exception.Message)" }
}

# ---- Renderers (each takes canvas, width, height so they can be drawn on screen or off screen for export)
function Render-LiveChart {
    param($C, [double]$W = 0, [double]$H = 0)
    Draw-LineChart -Canvas $C -W $W -H $H -Title 'CPU and memory usage (last 60 samples)' -Series @(
        [pscustomobject]@{ Name = 'CPU'; Color = '#4F8CFF'; Data = $script:CpuHist.ToArray() },
        [pscustomobject]@{ Name = 'Memory'; Color = '#2ECC71'; Data = $script:MemHist.ToArray() })
}

function Get-TestPhases($r) {
    $cp = @($r.ProcessMs, $r.InputIdleMs, $r.WindowMs, $r.UserReadyMs)
    $vals = New-Object double[] 5
    $prev = 0.0
    for ($i = 0; $i -lt 4; $i++) {
        if ($null -ne $cp[$i] -and "$($cp[$i])" -ne '') {
            $v = [double]$cp[$i]
            $vals[$i] = [Math]::Max(0, $v - $prev)
            if ($v -gt $prev) { $prev = $v }
        }
    }
    if ($r.TotalMs -and [double]$r.TotalMs -gt $prev) { $vals[4] = [double]$r.TotalMs - $prev }
    , $vals
}
function Render-StartChart {
    param($C, [double]$W = 0, [double]$H = 0)
    $rs = $script:TestResults.ToArray()
    $cnt = $rs.Length
    $cats = New-Object 'System.Collections.Generic.List[string]'
    foreach ($r in $rs) { $cats.Add(('#{0} {1}' -f $r.Run, $r.Application)) }
    $names  = 'Process created', 'Ready for input', 'Main window visible', 'User confirmed ready', 'Not completed'
    $colors = '#4F8CFF', '#7C5CFF', '#2ECC71', '#F5A524', '#5A6275'
    $cols = New-Object 'System.Collections.Generic.List[object]'
    for ($k = 0; $k -lt 5; $k++) { $cols.Add((New-Object 'double[]' $cnt)) }
    for ($i = 0; $i -lt $cnt; $i++) {
        $ph = Get-TestPhases $rs[$i]
        for ($k = 0; $k -lt 5; $k++) { $arr = $cols[$k]; $arr[$i] = [double]$ph[$k] }
    }
    $series = New-Object 'System.Collections.Generic.List[object]'
    for ($k = 0; $k -lt 5; $k++) { $series.Add([pscustomobject]@{ Name = $names[$k]; Color = $colors[$k]; Data = $cols[$k] }) }
    $series = $series.ToArray()
    $cats = $cats.ToArray()
    $ok = @($rs | Where-Object { $_.Status -like 'OK*' -and $_.TotalMs } | ForEach-Object { [double]$_.TotalMs })
    $avg = if ($ok.Count) { ($ok | Measure-Object -Average).Average } else { -1 }
    Draw-StackedBarChart -Canvas $C -W $W -H $H -Categories $cats -Series $series -Title 'Application start time per run' -Unit 'ms' -AvgLine $avg `
        -EmptyText 'No results yet - run an automatic test or a manual measurement.'
}
function Render-BootChart {
    param($C, [double]$W = 0, [double]$H = 0)
    $b = @()
    if ($script:BootData) { $b = @($script:BootData.Boots | Sort-Object Date) }
    $cats = @($b | ForEach-Object { $_.Date.ToString('dd.MM. HH:mm') })
    $series = @(
        [pscustomobject]@{ Name = 'Main path (until desktop)'; Color = '#4F8CFF'; Data = [double[]]@($b | ForEach-Object { $_.MainPathSec }) },
        [pscustomobject]@{ Name = 'Post boot (until idle)'; Color = '#7C5CFF'; Data = [double[]]@($b | ForEach-Object { $_.PostBootSec }) })
    $avg = if ($b.Count) { ($b | Measure-Object BootSec -Average).Average } else { -1 }
    Draw-StackedBarChart -Canvas $C -W $W -H $H -Categories $cats -Series $series -Title 'Boot duration history' -Unit 's' -AvgLine $avg `
        -EmptyText 'No boot history - run the analysis as administrator (Diagnostics-Performance log).'
}
function Render-AppBootChart {
    param($C, [double]$W = 0, [double]$H = 0)
    $a = @()
    if ($script:BootData) { $a = @($script:BootData.StartupApps | Where-Object { $null -ne $_.StartedAfterBootSec -and $_.StartedAfterBootSec -ge 0 } | Sort-Object StartedAfterBootSec) }
    Draw-HBarChart -Canvas $C -W $W -H $H -Labels @($a | ForEach-Object { $_.Name }) -Values ([double[]]@($a | ForEach-Object { $_.StartedAfterBootSec })) `
        -Title 'Startup apps - process started after boot (currently running apps)' -Unit 's' -Color '#2ECC71' -EmptyText 'No running startup apps found - click "Analyze boot & autostart".'
}
function Render-SvcBootChart {
    param($C, [double]$W = 0, [double]$H = 0)
    $s = @()
    if ($script:BootData) { $s = @($script:BootData.Services | Where-Object { $null -ne $_.StartedAfterBootSec } | Sort-Object StartedAfterBootSec -Descending) }
    $cols = @($s | ForEach-Object { if ($_.BootDelayMs) { '#FF6B6B' } elseif ($_.StartType -like '*Delayed*') { '#7C5CFF' } else { '#4F8CFF' } })
    Draw-HBarChart -Canvas $C -W $W -H $H -Labels @($s | ForEach-Object { $_.DisplayName }) -Values ([double[]]@($s | ForEach-Object { $_.StartedAfterBootSec })) `
        -Colors $cols -Title 'Services - started after boot, latest first (red = reported boot delay, purple = delayed start)' -Unit 's' `
        -EmptyText 'No service start events found - click "Analyze boot & autostart".'
}
#endregion

#region ---------------------------------------------------------------- Live monitor + baseline
function Import-Baseline {
    $script:BaselineProc = $null
    $script:BaselineSvc = $null
    if (-not (Test-Path $script:BaselineFile)) {
        $UI.BaselineInfo.Text = 'No baseline yet - absolute thresholds are used. Record one while the PC is in its normal state.'
        return
    }
    try {
        $j = Get-Content -Path $script:BaselineFile -Raw | ConvertFrom-Json
        $script:BaselineProc = @{}
        foreach ($pp in $j.Processes.PSObject.Properties) { $script:BaselineProc[$pp.Name] = $pp.Value }
        $script:BaselineSvc = @{}
        foreach ($pp in $j.Services.PSObject.Properties) { $script:BaselineSvc[$pp.Name] = $pp.Value }
        $UI.BaselineInfo.Text = "Baseline from $($j.Created) ($($j.Samples) samples) - values above it are flagged."
    } catch {
        $UI.BaselineInfo.Text = "Baseline file could not be read: $($_.Exception.Message)"
    }
}

function Get-UsageStatus {
    param([double]$Cpu, [double]$Mem, [double]$IO, $Base, [switch]$IsService)
    $flags = New-Object System.Collections.Generic.List[string]
    if ($Base) {
        $bCpu = [double]$Base.Cpu; $bMax = [double]$Base.MaxCpu; $bMem = [double]$Base.Mem; $bIO = [double]$Base.IO
        $cpuLimit = [Math]::Max([Math]::Max($bCpu * 2, $bMax * 1.25), $bCpu + 5)
        if ($Cpu -ge 3 -and $Cpu -gt $cpuLimit) { $flags.Add(('CPU {0:N1}% (usual {1:N1}%)' -f $Cpu, $bCpu)) }
        if ($Mem -gt [Math]::Max($bMem * 1.5, $bMem + 150)) { $flags.Add(('RAM {0:N0} MB (usual {1:N0} MB)' -f $Mem, $bMem)) }
        if ($IO -gt [Math]::Max($bIO * 3, $bIO + 2048)) { $flags.Add(('I/O {0:N0} KB/s (usual {1:N0})' -f $IO, $bIO)) }
        if ($flags.Count) { return '! Above usual: ' + ($flags -join ', ') }
        return 'Normal (within baseline)'
    }
    $memLimit = if ($IsService) { 500 } else { 2048 }
    if ($Cpu -ge 25) { $flags.Add(('High CPU {0:N1}%' -f $Cpu)) }
    if ($Mem -ge $memLimit) { $flags.Add(('High RAM {0:N0} MB' -f $Mem)) }
    if ($IO -ge 20480) { $flags.Add(('High I/O {0:N0} KB/s' -f $IO)) }
    if ($flags.Count) { return '! ' + ($flags -join ', ') }
    if ($script:BaselineProc) { return 'New since baseline' }
    'Normal'
}

function Start-LiveRefresh {
    if ($script:SnapshotBusy) { return }
    $script:SnapshotBusy = $true
    Start-AsyncTask -Status 'Collecting performance data...' -Script { Get-PerfSnapshot } -OnComplete {
        param($r, $e)
        $script:SnapshotBusy = $false
        if ($e) { Set-Status "Snapshot failed: $($e.Message)"; return }
        $snap = @($r) | Select-Object -First 1
        if ($snap) { Update-LiveData $snap }
    }
}

function Update-LiveData($snap) {
    $script:LastSnap = $snap
    # aggregate processes by name (e.g. all chrome.exe instances) and compare with baseline
    $agg = @{}
    foreach ($p in $snap.Processes) {
        $k = ([string]$p.Name).ToLower()
        if (-not $agg.ContainsKey($k)) { $agg[$k] = @{ Cpu = 0.0; Mem = 0.0; IO = 0.0 } }
        $agg[$k].Cpu += $p.CPU; $agg[$k].Mem += $p.MemoryMB; $agg[$k].IO += $p.IOKBs
    }
    $statusByName = @{}
    foreach ($k in $agg.Keys) {
        $base = if ($script:BaselineProc) { $script:BaselineProc[$k] } else { $null }
        $statusByName[$k] = Get-UsageStatus $agg[$k].Cpu $agg[$k].Mem $agg[$k].IO $base
    }
    foreach ($p in $snap.Processes) {
        $st = $statusByName[([string]$p.Name).ToLower()]
        $p.Status = $st
        $p.Alert = $st -like '!*'
    }
    foreach ($s in $snap.Services) {
        if ($s.State -eq 'Running') {
            $base = if ($script:BaselineSvc) { $script:BaselineSvc[$s.Name.ToLower()] } else { $null }
            $s.Status = Get-UsageStatus $s.CPU $s.MemoryMB $s.IOKBs $base -IsService
            if ($s.Status -eq 'New since baseline' -and -not $script:BaselineSvc) { $s.Status = 'Normal' }
        } else { $s.Status = '-' }
        $s.Alert = $s.Status -like '!*'
        Set-ServiceAdvice $s
    }

    $flaggedP = @($snap.Processes | Where-Object { $_.Alert }).Count
    $running = @($snap.Services | Where-Object { $_.State -eq 'Running' })
    $flaggedS = @($running | Where-Object { $_.Alert }).Count
    $UI.CardCpu.Text = '{0:N0} %' -f $snap.CpuTotal
    $UI.CardCpuSub.Text = "$([Environment]::ProcessorCount) logical processors"
    $UI.CardMem.Text = '{0:N0} %' -f $snap.MemUsedPct
    $UI.CardMemSub.Text = '{0:N1} of {1:N1} GB in use' -f $snap.MemUsedGB, $snap.MemTotalGB
    $UI.CardProc.Text = [string]@($snap.Processes).Count
    $UI.CardProcSub.Text = "$flaggedP flagged (above usual / high)"
    $UI.CardSvc.Text = [string]$running.Count
    $UI.CardSvcSub.Text = "$(@($snap.Services | Where-Object { $_.StartMode -eq 'Auto' }).Count) automatic, $flaggedS flagged"
    if ($snap.LastBoot) {
        $UI.CardUp.Text = Format-Uptime ((Get-Date) - $snap.LastBoot)
        $UI.CardUpSub.Text = 'since ' + $snap.LastBoot.ToString('g')
    }

    $script:CpuHist.Add([double]$snap.CpuTotal); $script:MemHist.Add([double]$snap.MemUsedPct)
    while ($script:CpuHist.Count -gt 60) { $script:CpuHist.RemoveAt(0) }
    while ($script:MemHist.Count -gt 60) { $script:MemHist.RemoveAt(0) }
    Render-LiveChart $UI.LiveChart

    Update-ProcGrid
    Update-SvcGrid
    Update-Recommendations
    $UI.StatusRight.Text = 'Last update {0:HH:mm:ss}' -f $snap.Time
    Set-Status ('Snapshot: {0} processes, {1} services. {2} processes and {3} services flagged.' -f @($snap.Processes).Count, @($snap.Services).Count, $flaggedP, $flaggedS)
}

function Update-ProcGrid {
    if (-not $script:LastSnap) { return }
    $f = $UI.ProcFilter.Text.Trim()
    $items = @($script:LastSnap.Processes)
    if ($f) { $items = @($items | Where-Object { (Test-Contains $_.Name $f) -or (Test-Contains $_.Path $f) -or (Test-Contains $_.Services $f) -or ("$($_.PID)" -eq $f) }) }
    if ($UI.ProcOnlyFlagged.IsChecked) { $items = @($items | Where-Object { $_.Alert }) }
    Set-GridItems $UI.ProcGrid $items 'PID'
    if (-not $script:ProcSortInit) { Set-GridSort $UI.ProcGrid 'CPU' ([ComponentModel.ListSortDirection]::Descending); $script:ProcSortInit = $true }
}

function Start-BaselineRecording {
    if ($script:BaselineBusy) { return }
    if (-not (Confirm-Action "A baseline describes the NORMAL resource usage of this PC.`n`nRecord it now while the PC is idle or in typical use (no installs, updates or heavy tasks running). It takes about 30 seconds.`n`nRecord baseline now?" 'Record baseline')) { return }
    $script:BaselineBusy = $true
    $UI.BtnBaseline.IsEnabled = $false
    $script:Sync.Cancel = $false
    Start-AsyncTask -Status 'Recording baseline...' -Parameters @{ Samples = 10; IntervalSec = 3; Sync = $script:Sync } -Script {
        param($Samples, $IntervalSec, $Sync)
        $null = Get-PerfSnapshot   # warm up the performance counters
        $pAcc = @{}; $sAcc = @{}; $taken = 0
        for ($i = 1; $i -le $Samples; $i++) {
            if ($Sync.Cancel) { break }
            $Sync.Progress = "Recording baseline: sample $i of $Samples ..."
            Start-Sleep -Seconds $IntervalSec
            $snap = Get-PerfSnapshot
            $taken++
            $agg = @{}
            foreach ($p in $snap.Processes) {
                $k = ([string]$p.Name).ToLower()
                if (-not $agg.ContainsKey($k)) { $agg[$k] = @(0.0, 0.0, 0.0) }
                $agg[$k][0] += $p.CPU; $agg[$k][1] += $p.MemoryMB; $agg[$k][2] += $p.IOKBs
            }
            foreach ($k in $agg.Keys) {
                if (-not $pAcc.ContainsKey($k)) { $pAcc[$k] = @{ Cpu = 0.0; Mem = 0.0; IO = 0.0; MaxCpu = 0.0; N = 0 } }
                $a = $pAcc[$k]; $v = $agg[$k]
                $a.Cpu += $v[0]; $a.Mem += $v[1]; $a.IO += $v[2]; $a.N++
                if ($v[0] -gt $a.MaxCpu) { $a.MaxCpu = $v[0] }
            }
            foreach ($s in $snap.Services) {
                if ($s.State -ne 'Running') { continue }
                $k = $s.Name.ToLower()
                if (-not $sAcc.ContainsKey($k)) { $sAcc[$k] = @{ Cpu = 0.0; Mem = 0.0; IO = 0.0; MaxCpu = 0.0; N = 0 } }
                $a = $sAcc[$k]
                $a.Cpu += $s.CPU; $a.Mem += $s.MemoryMB; $a.IO += $s.IOKBs; $a.N++
                if ($s.CPU -gt $a.MaxCpu) { $a.MaxCpu = $s.CPU }
            }
        }
        $outP = @{}; $outS = @{}
        foreach ($k in $pAcc.Keys) { $a = $pAcc[$k]; $outP[$k] = [pscustomobject]@{ Cpu = [Math]::Round($a.Cpu / $a.N, 2); Mem = [Math]::Round($a.Mem / $a.N, 1); IO = [Math]::Round($a.IO / $a.N, 1); MaxCpu = [Math]::Round($a.MaxCpu, 2); Seen = $a.N } }
        foreach ($k in $sAcc.Keys) { $a = $sAcc[$k]; $outS[$k] = [pscustomobject]@{ Cpu = [Math]::Round($a.Cpu / $a.N, 2); Mem = [Math]::Round($a.Mem / $a.N, 1); IO = [Math]::Round($a.IO / $a.N, 1); MaxCpu = [Math]::Round($a.MaxCpu, 2); Seen = $a.N } }
        $Sync.Progress = ''
        [pscustomobject]@{ Created = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Computer = $env:COMPUTERNAME; Samples = $taken; Processes = $outP; Services = $outS }
    } -OnComplete {
        param($r, $e)
        $script:BaselineBusy = $false
        $UI.BtnBaseline.IsEnabled = $true
        if ($e) { Show-ErrorMessage "Baseline recording failed: $($e.Message)"; return }
        $b = @($r) | Select-Object -First 1
        if (-not $b -or $b.Samples -lt 1) { Set-Status 'Baseline recording cancelled.'; return }
        try {
            $b | ConvertTo-Json -Depth 5 | Set-Content -Path $script:BaselineFile -Encoding UTF8
            Import-Baseline
            Set-Status "Baseline saved ($($b.Samples) samples). Processes and services are now compared against it."
            Start-LiveRefresh
        } catch { Show-ErrorMessage "Could not save the baseline: $($_.Exception.Message)" }
    }
}
#endregion

#region ---------------------------------------------------------------- Services
function Set-ServiceAdvice($s) {
    $base = $s.Name -replace '_[0-9a-fA-F]{4,}$', ''
    $kb = $script:ServiceKB[$base]
    $isWin = $false
    if ($s.PathName) { $isWin = ($s.PathName.IndexOf($env:windir, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
    $s.ThirdParty = -not $isWin
    if ($script:CriticalServices -contains $base) {
        $cat = 'Core system'; $rec = 'Keep (critical)'
        $why = 'Core Windows component. Disabling or stopping it can make Windows unstable, break networking/security or prevent booting.'
    } elseif ($kb) {
        $cat = $kb.Category; $rec = $kb.Rec; $why = $kb.Reason
    } elseif (-not $isWin) {
        $cat = 'Third-party'
        if ($s.StartMode -eq 'Auto') {
            $rec = 'Review (third-party)'
            $why = 'Third-party service that starts automatically with Windows. If you do not need its application running in the background all the time, setting it to Manual can speed up boot and save resources. Check the publisher first.'
        } else { $rec = 'Keep'; $why = 'Third-party service that only starts on demand.' }
    } else {
        $cat = 'Windows'; $rec = 'Keep'
        $why = 'Windows service without a general recommendation. Keep the default setting unless you are troubleshooting.'
    }
    if ($s.StartMode -eq 'Disabled' -and $rec -ne 'Keep (critical)') { $rec = 'Already disabled' }
    elseif ($rec -eq 'Set to Manual' -and $s.StartMode -eq 'Manual') { $rec = 'OK (already Manual)' }
    if ($s.Alert) {
        $why = "$why`n`nCurrently uses more resources than usual: $($s.Status.TrimStart('!', ' ')). Consider restarting the service or checking the related application."
        if ($rec -in 'Keep', 'OK (already Manual)') { $rec = 'Investigate (above usual)' }
    }
    $impact = '-'
    if ($s.State -eq 'Running') {
        $memForImpact = if ($s.SharedWith -le 1) { $s.MemoryMB } else { 0 }
        if ($s.CPU -ge 10 -or $s.IOKBs -ge 5120 -or $memForImpact -ge 300) { $impact = 'High' }
        elseif ($s.CPU -ge 2 -or $s.IOKBs -ge 512 -or $memForImpact -ge 100) { $impact = 'Medium' }
        else { $impact = 'Low' }
        if ($s.SharedWith -gt 1) { $impact += ' (shared)' }
    }
    $s.Impact = $impact
    $s.Category = $cat
    $s.Recommendation = $rec
    $s.Reason = $why
    $s.RecColor = Get-RecColor $rec
}

function Update-SvcGrid {
    if (-not $script:LastSnap) { return }
    $f = $UI.SvcFilter.Text.Trim()
    $items = @($script:LastSnap.Services)
    if ($f) { $items = @($items | Where-Object { (Test-Contains $_.Name $f) -or (Test-Contains $_.DisplayName $f) -or (Test-Contains $_.Description $f) -or (Test-Contains $_.PathName $f) }) }
    switch ($UI.SvcView.SelectedIndex) {
        1 { $items = @($items | Where-Object { $_.State -eq 'Running' }) }
        2 { $items = @($items | Where-Object { $_.StartMode -eq 'Auto' }) }
        3 { $items = @($items | Where-Object { $_.Alert -or $_.Impact -like 'High*' }) }
        4 { $items = @($items | Where-Object { $_.ThirdParty }) }
        5 { $items = @($items | Where-Object { $_.Recommendation -in 'Safe to disable', 'Set to Manual', 'Conditional', 'Review (third-party)', 'Investigate (above usual)' }) }
    }
    Set-GridItems $UI.SvcGrid $items 'Name'
    $UI.SvcCount.Text = "$($items.Count) of $(@($script:LastSnap.Services).Count) services"
}

function Add-DetailText($Panel, [string]$Text, [double]$Size = 12.5, [string]$Color = '#E6EAF0', [switch]$Bold, [string]$Margin = '0,0,0,0') {
    $tb = New-Object Windows.Controls.TextBlock
    $tb.Text = $Text; $tb.FontSize = $Size; $tb.Foreground = Get-Brush $Color
    $tb.TextWrapping = [Windows.TextWrapping]::Wrap
    $m = @($Margin -split ',' | ForEach-Object { [double]::Parse($_.Trim(), [Globalization.CultureInfo]::InvariantCulture) })
    $tb.Margin = New-Object Windows.Thickness $m[0], $m[1], $m[2], $m[3]
    if ($Bold) { $tb.FontWeight = [Windows.FontWeights]::SemiBold }
    [void]$Panel.Children.Add($tb)
}
function Add-DetailRow($Panel, [string]$Label, [string]$Value) {
    if (-not $Value) { $Value = '-' }
    Add-DetailText $Panel $Label.ToUpper() 10.5 '#8A94A6' -Bold -Margin '0,10,0,2'
    Add-DetailText $Panel $Value 12.5 '#E6EAF0'
}

function Show-ServiceDetails($s) {
    $p = $UI.SvcDetails
    $p.Children.Clear()
    if (-not $s) { Add-DetailText $p 'Select a service to see its details, resource usage and recommendation.' 12.5 '#8A94A6'; return }
    Add-DetailText $p $s.DisplayName 17 '#FFFFFF' -Bold
    Add-DetailText $p $s.Name 12 '#8A94A6' -Margin '0,2,0,0'
    $badge = New-Object Windows.Controls.Border
    $badge.Background = Get-Brush ('#33' + $s.RecColor.Substring(1))
    $badge.CornerRadius = New-Object Windows.CornerRadius 6
    $badge.Padding = New-Object Windows.Thickness 10, 4, 10, 4
    $badge.Margin = New-Object Windows.Thickness 0, 12, 0, 8
    $badge.HorizontalAlignment = 'Left'
    $bt = New-Object Windows.Controls.TextBlock
    $bt.Text = $s.Recommendation; $bt.Foreground = Get-Brush $s.RecColor; $bt.FontWeight = [Windows.FontWeights]::SemiBold
    $badge.Child = $bt
    [void]$p.Children.Add($badge)
    Add-DetailText $p $s.Reason 12.5 '#C9D1DD'
    Add-DetailRow $p 'Status' "$($s.State)   |   Startup type: $($s.StartType)"
    Add-DetailRow $p 'Category' $s.Category
    Add-DetailRow $p 'Usage status' $s.Status
    if ($s.State -eq 'Running') {
        $usage = 'CPU {0:N1} %   |   RAM {1:N1} MB   |   I/O {2:N1} KB/s   |   Impact: {3}' -f $s.CPU, $s.MemoryMB, $s.IOKBs, $s.Impact
        if ($s.SharedWith -gt 1) {
            $others = ''
            $hostProc = @($script:LastSnap.Processes | Where-Object { $_.PID -eq $s.PID }) | Select-Object -First 1
            if ($hostProc) { $others = $hostProc.Services }
            $usage += "`nValues belong to the shared host process (PID $($s.PID)) which runs $($s.SharedWith) services: $others"
        } else { $usage += "`nProcess ID: $($s.PID)" }
        Add-DetailRow $p 'Resource usage' $usage
    }
    Add-DetailRow $p 'Description' $s.Description
    Add-DetailRow $p 'Executable' $s.PathName
    Add-DetailRow $p 'Log on as' $s.Account
    $dep = ''; $req = ''
    try {
        $gs = Get-Service -Name $s.Name -ErrorAction Stop
        $dep = (@($gs.ServicesDependedOn) | ForEach-Object { $_.Name }) -join ', '
        $req = (@($gs.DependentServices) | ForEach-Object { $_.Name }) -join ', '
    } catch { }
    Add-DetailRow $p 'Depends on' $dep
    Add-DetailRow $p 'Required by (stopping this stops them too)' $req
    $idx = switch ($s.StartType) { 'Automatic' { 0 } 'Automatic (Delayed)' { 1 } 'Manual' { 2 } 'Disabled' { 3 } default { 2 } }
    $UI.SvcStartType.SelectedIndex = $idx
}

function ConvertTo-ScMode([string]$StartMode, [bool]$Delayed) {
    switch ($StartMode) {
        'Auto'     { if ($Delayed) { 'delayed-auto' } else { 'auto' } }
        'Manual'   { 'demand' }
        'Disabled' { 'disabled' }
        default    { 'demand' }
    }
}
function Get-ChangeLog {
    $l = New-Object Collections.Generic.List[object]
    if (Test-Path $script:ChangeLogFile) {
        try {
            $data = Get-Content -Path $script:ChangeLogFile -Raw | ConvertFrom-Json
            foreach ($x in $data) { if ($x) { $l.Add($x) } }
        } catch { }
    }
    , $l
}
function Save-ChangeLog($List) {
    ConvertTo-Json -InputObject @($List) -Depth 3 | Set-Content -Path $script:ChangeLogFile -Encoding UTF8
}

function Start-ServiceOperation([string[]]$Names, [string]$Action) {
    Start-AsyncTask -Status "$Action service(s)..." -Parameters @{ Names = $Names; Action = $Action } -Script {
        param($Names, $Action)
        foreach ($n in $Names) {
            try {
                switch ($Action) {
                    'Start'   { Start-Service -Name $n -ErrorAction Stop }
                    'Stop'    { Stop-Service -Name $n -Force -ErrorAction Stop }
                    'Restart' { Restart-Service -Name $n -Force -ErrorAction Stop }
                }
                "${n}: $Action OK"
            } catch { "${n}: FAILED - $($_.Exception.Message)" }
        }
    } -OnComplete {
        param($r, $e)
        if ($e) { Show-ErrorMessage $e.Message } else { Show-Info ((@($r) -join "`n")) 'Service operation' }
        Start-LiveRefresh
    }
}

function Invoke-ServiceAction([string]$Action) {
    $sel = @($UI.SvcGrid.SelectedItems)
    if (-not $sel.Count) { Show-Info 'Select one or more services first.'; return }
    if (-not (Test-AdminOrWarn 'Starting and stopping services')) { return }
    $names = @($sel | ForEach-Object { $_.Name })
    $warn = ''
    if ($Action -ne 'Start') {
        $crit = @($sel | Where-Object { $_.Recommendation -eq 'Keep (critical)' })
        if ($crit.Count) { $warn += "`n`nWARNING: core Windows service(s) selected: $(($crit | ForEach-Object { $_.Name }) -join ', '). Stopping them can freeze or crash Windows." }
        $deps = @()
        foreach ($n in $names) { try { $deps += @((Get-Service -Name $n -ErrorAction Stop).DependentServices | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name }) } catch { } }
        if ($deps.Count) { $warn += "`n`nThese running dependent services will be stopped too: $($deps -join ', ')" }
    }
    if (-not (Confirm-Action "$Action the following service(s)?`n`n$($names -join "`n")$warn")) { return }
    Start-ServiceOperation $names $Action
}

function Set-ServiceStartup {
    param([object[]]$Services, [string]$ScMode, [string]$Label)
    if (-not $Services -or -not $Services.Count) { Show-Info 'Select one or more services first.'; return }
    if (-not (Test-AdminOrWarn 'Changing the startup type of services')) { return }
    $crit = @($Services | Where-Object { $_.Recommendation -eq 'Keep (critical)' })
    if ($crit.Count -and $ScMode -in 'disabled', 'demand') {
        Show-ErrorMessage "The following core Windows service(s) are protected by PerfInspector and will not be changed:`n`n$(($crit | ForEach-Object { $_.Name }) -join "`n")"
        $Services = @($Services | Where-Object { $_.Recommendation -ne 'Keep (critical)' })
        if (-not $Services.Count) { return }
    }
    $list = ($Services | ForEach-Object { " - $($_.DisplayName) ($($_.Name)): $($_.StartType) -> $Label" }) -join "`n"
    if (-not (Confirm-Action "Change the startup type of these service(s)?`n`n$list`n`nThe original settings are saved and can be restored at any time with 'Restore original startup types'.")) { return }
    $log = Get-ChangeLog
    $results = foreach ($s in $Services) {
        $old = ConvertTo-ScMode $s.StartMode $s.Delayed
        $out = & sc.exe config "$($s.Name)" start= $ScMode 2>&1
        if ($LASTEXITCODE -eq 0) {
            $log.Add([pscustomobject]@{ Time = (Get-Date).ToString('s'); Name = $s.Name; DisplayName = $s.DisplayName; Old = $old; New = $ScMode })
            "$($s.Name): OK ($old -> $ScMode)"
        } else { "$($s.Name): FAILED - $((($out | Out-String).Trim() -split "`r?`n")[-1])" }
    }
    Save-ChangeLog $log
    Show-Info (($results -join "`n")) 'Startup type'
    if ($ScMode -eq 'disabled') {
        $runningNames = @($Services | Where-Object { $_.State -eq 'Running' } | ForEach-Object { $_.Name })
        if ($runningNames.Count -and (Confirm-Action "Stop the now disabled running service(s) right away?`n`n$($runningNames -join "`n")")) {
            Start-ServiceOperation $runningNames 'Stop'
            return
        }
    }
    Start-LiveRefresh
}

function Restore-ServiceChanges {
    $log = Get-ChangeLog
    if (-not $log.Count) { Show-Info 'There are no service changes recorded by PerfInspector.'; return }
    if (-not (Test-AdminOrWarn 'Restoring service startup types')) { return }
    $orig = [ordered]@{}
    foreach ($entry in $log) { if (-not $orig.Contains($entry.Name)) { $orig[$entry.Name] = $entry.Old } }
    $list = ($orig.Keys | ForEach-Object { " - $_ -> $($orig[$_])" }) -join "`n"
    if (-not (Confirm-Action "Restore the original startup type of $($orig.Count) service(s)?`n`n$list")) { return }
    $res = foreach ($n in @($orig.Keys)) {
        $mode = $orig[$n]
        $out = & sc.exe config "$n" start= $mode 2>&1
        if ($LASTEXITCODE -eq 0) { "${n}: restored to $mode" } else { "${n}: FAILED - $((($out | Out-String).Trim() -split "`r?`n")[-1])" }
    }
    try { Move-Item -Path $script:ChangeLogFile -Destination (Join-Path $script:DataDir ('service-changes_restored_{0:yyyyMMdd_HHmmss}.json' -f (Get-Date))) -Force } catch { }
    Show-Info (($res -join "`n")) 'Restore'
    Start-LiveRefresh
}
#endregion

#region ---------------------------------------------------------------- Recommendations
function Update-Recommendations {
    if (-not $script:LastSnap) { return }
    $actionable = 'Safe to disable', 'Set to Manual', 'Conditional', 'Review (third-party)', 'Investigate (above usual)'
    $all = @($script:LastSnap.Services | Where-Object { $_.Recommendation -in $actionable })
    $items = $all
    $fi = $UI.RecFilter.SelectedIndex
    if ($fi -gt 0) { $want = $actionable[$fi - 1]; $items = @($all | Where-Object { $_.Recommendation -eq $want }) }
    $prio = @{ 'Investigate (above usual)' = 0; 'Safe to disable' = 1; 'Set to Manual' = 2; 'Review (third-party)' = 3; 'Conditional' = 4 }
    $items = @($items | Sort-Object @{ Expression = { $prio[$_.Recommendation] } }, @{ Expression = { $_.MemoryMB }; Descending = $true })
    Set-GridItems $UI.RecGrid $items 'Name'

    $cnt = @{}
    foreach ($a in $actionable) { $cnt[$a] = @($all | Where-Object { $_.Recommendation -eq $a }).Count }
    $savers = @($all | Where-Object { $_.State -eq 'Running' -and $_.SharedWith -le 1 -and $_.Recommendation -in 'Safe to disable', 'Set to Manual', 'Review (third-party)' })
    $mem = ($savers | Measure-Object MemoryMB -Sum).Sum
    $autoCnt = @($all | Where-Object { $_.StartMode -eq 'Auto' -and $_.Recommendation -in 'Safe to disable', 'Set to Manual', 'Review (third-party)' }).Count
    $UI.RecSummary.Text = ("{0} safe to disable  |  {1} can be set to Manual  |  {2} conditional (depends on your usage)  |  {3} third-party auto-start services to review  |  {4} running above usual.`n" +
        "Acting on the clear recommendations could remove up to {5} service(s) from the boot sequence and free roughly {6:N0} MB of RAM (services in dedicated processes only).") -f `
        $cnt['Safe to disable'], $cnt['Set to Manual'], $cnt['Conditional'], $cnt['Review (third-party)'], $cnt['Investigate (above usual)'], $autoCnt, [double]$mem
}
#endregion

#region ---------------------------------------------------------------- App start test
function Invoke-TestIngest {
    while ($script:TestIngested -lt $script:Sync.TestResults.Count) {
        $r = $script:Sync.TestResults[$script:TestIngested]
        $script:TestIngested++
        Add-TestResult $r
    }
}
function Add-TestResult($r) {
    $r.Run = $script:TestResults.Count + 1
    $script:TestResults.Add($r)
    Set-GridItems $UI.TestGrid $script:TestResults.ToArray()
    Render-StartChart $UI.StartChart
    Update-TestStats
}
function Update-TestStats {
    if (-not $script:TestResults.Count) { $UI.TestStats.Text = 'No results yet.'; return }
    $sb = New-Object Text.StringBuilder
    foreach ($g in ($script:TestResults | Group-Object Application, Mode)) {
        [void]$sb.AppendLine($g.Name)
        $ok = @($g.Group | Where-Object { $_.Status -like 'OK*' -and $_.TotalMs })
        $vals = @($ok | ForEach-Object { [double]$_.TotalMs })
        if (-not $vals.Count) { [void]$sb.AppendLine('  no successful runs'); [void]$sb.AppendLine(''); continue }
        $sorted = @($vals | Sort-Object)
        $avg = ($vals | Measure-Object -Average).Average
        $mid = [int][Math]::Floor($sorted.Count / 2)
        $med = if ($sorted.Count % 2) { $sorted[$mid] } else { ($sorted[$mid - 1] + $sorted[$mid]) / 2 }
        $sd = 0
        if ($vals.Count -gt 1) { $sd = [Math]::Sqrt((($vals | ForEach-Object { ($_ - $avg) * ($_ - $avg) } | Measure-Object -Sum).Sum) / ($vals.Count - 1)) }
        [void]$sb.AppendLine(('  Successful runs : {0} of {1}' -f $vals.Count, $g.Count))
        [void]$sb.AppendLine(('  Min / Max       : {0:N0} / {1:N0} ms' -f $sorted[0], $sorted[-1]))
        [void]$sb.AppendLine(('  Average         : {0:N0} ms' -f $avg))
        [void]$sb.AppendLine(('  Median          : {0:N0} ms' -f $med))
        [void]$sb.AppendLine(('  Std deviation   : {0:N0} ms' -f $sd))
        if ($vals.Count -gt 1) {
            $warm = ($vals[1..($vals.Count - 1)] | Measure-Object -Average).Average
            [void]$sb.AppendLine(('  First run (cold): {0:N0} ms' -f $vals[0]))
            [void]$sb.AppendLine(('  Next runs (warm): {0:N0} ms avg' -f $warm))
        }
        $memVals = @($ok | Where-Object { $_.MemoryMB } | ForEach-Object { [double]$_.MemoryMB })
        if ($memVals.Count) { [void]$sb.AppendLine(('  RAM when ready  : {0:N0} MB avg' -f ($memVals | Measure-Object -Average).Average)) }
        [void]$sb.AppendLine('')
    }
    $UI.TestStats.Text = $sb.ToString().TrimEnd()
}

function Set-TestButtons([bool]$Running) {
    $UI.BtnTestRun.IsEnabled = -not $Running
    $UI.BtnTestCancel.IsEnabled = $Running
    $UI.BtnTestClear.IsEnabled = -not $Running
    $UI.BtnManualStart.IsEnabled = (-not $Running) -and ($null -eq $script:Manual)
}

function Start-AppTest {
    $exe = $UI.TestExe.Text.Trim().Trim('"')
    if (-not $exe) { Show-Info 'Choose an application first (Browse...).'; return }
    $isShell = $exe -like 'shell:*'
    if (-not $isShell -and -not (Test-Path -LiteralPath $exe) -and -not (Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue)) {
        Show-ErrorMessage "File not found:`n$exe"; return
    }
    $it = 0; $delay = 0; $timeout = 0
    if (-not [int]::TryParse($UI.TestIterations.Text, [ref]$it) -or $it -lt 1 -or $it -gt 100) { Show-Info 'Runs must be a number between 1 and 100.'; return }
    if (-not [int]::TryParse($UI.TestDelay.Text, [ref]$delay) -or $delay -lt 0 -or $delay -gt 600) { Show-Info 'Pause must be a number between 0 and 600 seconds.'; return }
    if (-not [int]::TryParse($UI.TestTimeout.Text, [ref]$timeout) -or $timeout -lt 5 -or $timeout -gt 600) { Show-Info 'Timeout must be a number between 5 and 600 seconds.'; return }
    $watch = $UI.TestWatch.Text.Trim()
    if (-not $watch -and $exe -like '*.lnk') {
        try { $t = (New-Object -ComObject WScript.Shell).CreateShortcut($exe).TargetPath; if ($t) { $watch = [IO.Path]::GetFileNameWithoutExtension($t) } } catch { }
    }
    if ($isShell -and -not $watch) { Show-Info 'For shell:AppsFolder entries please enter the process name to watch (e.g. "Calculator" or "WindowsTerminal").'; return }
    $names = if ($watch) { @($watch -split '[,;]' | ForEach-Object { $_.Trim() -replace '\.exe$', '' } | Where-Object { $_ }) } else { @([IO.Path]::GetFileNameWithoutExtension($exe)) }
    $running = @(Get-Process -Name $names -ErrorAction SilentlyContinue)
    if ($running.Count) {
        if (-not (Confirm-Action ("{0} instance(s) of '{1}' are already running.`n`nExisting instances are NOT touched by the test, but single-instance apps may hand the launch over to them, which distorts the results. For accurate cold-start values close the app first.`n`nContinue anyway?" -f $running.Count, ($names -join ', ')))) { return }
    }
    $script:Sync.Cancel = $false
    $script:TestRunning = $true
    Set-TestButtons $true
    Start-AsyncTask -Status "Running application start test ($it runs)..." -Parameters @{
        Exe = $exe; Arguments = $UI.TestArgs.Text; Iterations = $it; DelaySec = $delay; TimeoutSec = $timeout
        CloseAfter = [bool]$UI.TestCloseAfter.IsChecked; WatchName = $watch; Sync = $script:Sync
    } -Script {
        param($Exe, $Arguments, $Iterations, $DelaySec, $TimeoutSec, $CloseAfter, $WatchName, $Sync)
        Invoke-AppStartTest -Exe $Exe -Arguments $Arguments -Iterations $Iterations -DelaySec $DelaySec -TimeoutSec $TimeoutSec -CloseAfter $CloseAfter -WatchName $WatchName -Sync $Sync
    } -OnComplete {
        param($r, $e)
        $script:TestRunning = $false
        Invoke-TestIngest
        Set-TestButtons $false
        if ($e) { Show-ErrorMessage "The test stopped with an error: $($e.Message)" }
        Set-Status $(if ($script:Sync.Cancel) { 'Application start test cancelled.' } else { 'Application start test finished.' })
    }
}

function Format-Elapsed([TimeSpan]$ts) { '{0:00}:{1:00}.{2:000}' -f [Math]::Floor($ts.TotalMinutes), $ts.Seconds, $ts.Milliseconds }

function Start-ManualTest {
    $names = @($UI.ManualProc.Text -split '[,;]' | ForEach-Object { $_.Trim() -replace '\.exe$', '' } | Where-Object { $_ })
    $pre = @{}
    if ($names.Count) { foreach ($pp in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) { $pre[$pp.Id] = $true } }
    $armed = Get-Date
    $script:Manual = @{ Names = $names; Pre = $pre; Armed = $armed; SW = [Diagnostics.Stopwatch]::StartNew(); ProcessMs = $null; WindowMs = $null; Target = $null; LastPoll = 0 }
    $UI.BtnManualStart.IsEnabled = $false
    $UI.BtnManualReady.IsEnabled = $true
    $UI.BtnManualCancel.IsEnabled = $true
    $UI.BtnTestRun.IsEnabled = $false
    $UI.ManualInfo.Text = if ($names.Count) { "Stopwatch running - start '$($names -join ', ')' now. Process and main window will be detected automatically." } else { "Stopwatch running - start the application now and click 'App is ready' as soon as it is usable." }
    $script:ManualTimer.Start()
    Update-BusyState
}

function Invoke-ManualTick {
    $m = $script:Manual
    if (-not $m) { return }
    $UI.ManualTimer.Text = Format-Elapsed $m.SW.Elapsed
    if (-not $m.Names.Count -or $null -ne $m.WindowMs) { return }
    if (($m.SW.ElapsedMilliseconds - $m.LastPoll) -lt 80) { return }
    $m.LastPoll = $m.SW.ElapsedMilliseconds
    foreach ($pp in @(Get-Process -Name $m.Names -ErrorAction SilentlyContinue)) {
        if ($m.Pre.ContainsKey($pp.Id)) { continue }
        if ($null -eq $m.ProcessMs) {
            $ms = $m.SW.ElapsedMilliseconds
            try { $ms = [Math]::Max(0, [Math]::Round(($pp.StartTime - $m.Armed).TotalMilliseconds)) } catch { }
            $m.ProcessMs = $ms
            $m.Target = $pp
            $UI.ManualInfo.Text = "Process '$($pp.ProcessName)' (PID $($pp.Id)) started after $ms ms - waiting for its main window..."
        }
        if ($pp.MainWindowHandle -ne [IntPtr]::Zero) {
            $m.WindowMs = $m.SW.ElapsedMilliseconds
            $m.Target = $pp
            $UI.ManualInfo.Text = "Main window visible after $($m.WindowMs) ms. Click 'App is ready' as soon as the app is usable."
            if ($UI.ManualAutoStop.IsChecked) { Complete-ManualTest -AtWindow }
            return
        }
    }
}

function Complete-ManualTest([switch]$AtWindow) {
    $m = $script:Manual
    if (-not $m) { return }
    $script:ManualTimer.Stop()
    $m.SW.Stop()
    $ready = if ($AtWindow) { $null } else { $m.SW.ElapsedMilliseconds }
    $mem = $null; $cpuMs = $null
    if ($m.Target) {
        try { $m.Target.Refresh(); $mem = [Math]::Round($m.Target.WorkingSet64 / 1MB, 1); $cpuMs = [Math]::Round($m.Target.TotalProcessorTime.TotalMilliseconds) } catch { }
    }
    $app = if ($m.Target) { $m.Target.ProcessName } elseif ($m.Names.Count) { $m.Names -join ',' } else { 'Manual stopwatch' }
    $total = if ($null -ne $ready) { $ready } elseif ($null -ne $m.WindowMs) { $m.WindowMs } else { $m.SW.ElapsedMilliseconds }
    $status = if ($m.Names.Count -and $null -eq $m.ProcessMs) { 'OK (process not detected)' } else { 'OK' }
    $res = [pscustomobject]@{
        Run = 0; Mode = 'Manual'; Application = $app; ProcessMs = $m.ProcessMs; InputIdleMs = $null; WindowMs = $m.WindowMs
        UserReadyMs = $ready; TotalMs = $total; MemoryMB = $mem; CpuTimeMs = $cpuMs; Status = $status; Timestamp = $m.Armed
    }
    $script:Manual = $null
    $UI.ManualTimer.Text = Format-Elapsed ([TimeSpan]::FromMilliseconds($total))
    $UI.ManualInfo.Text = "Measurement saved: $total ms total."
    $UI.BtnManualReady.IsEnabled = $false
    $UI.BtnManualCancel.IsEnabled = $false
    Set-TestButtons $script:TestRunning
    Update-BusyState
    Add-TestResult $res
}

function Stop-ManualTest {
    $script:ManualTimer.Stop()
    $script:Manual = $null
    $UI.ManualInfo.Text = 'Manual measurement cancelled.'
    $UI.BtnManualReady.IsEnabled = $false
    $UI.BtnManualCancel.IsEnabled = $false
    Set-TestButtons $script:TestRunning
    Update-BusyState
}
#endregion

#region ---------------------------------------------------------------- Boot & autostart
function Start-BootAnalysis {
    if ($script:BootBusy) { return }
    $script:BootBusy = $true
    $UI.BtnBootAnalyze.IsEnabled = $false
    Start-AsyncTask -Status 'Analyzing boot performance, autostart entries and services at boot...' -Parameters @{ IncludeMsTasks = [bool]$UI.BootIncludeMs.IsChecked } -Script {
        param($IncludeMsTasks)
        Get-BootAnalysis -IncludeMsTasks $IncludeMsTasks
    } -OnComplete {
        param($r, $e)
        $script:BootBusy = $false
        $UI.BtnBootAnalyze.IsEnabled = $true
        if ($e) { Show-ErrorMessage "Boot analysis failed: $($e.Message)"; return }
        $b = @($r) | Select-Object -First 1
        if ($b) { Update-BootView $b; Set-Status 'Boot analysis finished.' }
    }
}

function Update-BootView($b) {
    $script:BootData = $b
    $UI.BootCardLast.Text = $b.LastBoot.ToString('g')
    $UI.BootCardLastSub.Text = 'Full restart (cold boot)'
    $UI.BootCardRef.Text = $b.BootRef.ToString('g')
    $UI.BootCardRefSub.Text = 'Uptime ' + (Format-Uptime ((Get-Date) - $b.BootRef))
    $boots = @($b.Boots)
    if ($boots.Count) {
        $last = $boots | Sort-Object Date -Descending | Select-Object -First 1
        $UI.BootCardDur.Text = '{0:N1} s' -f $last.BootSec
        $UI.BootCardDurSub.Text = 'Desktop {0:N1} s + idle {1:N1} s ({2})' -f $last.MainPathSec, $last.PostBootSec, $last.Rating
        $avg = ($boots | Measure-Object BootSec -Average).Average
        $UI.BootCardAvg.Text = '{0:N1} s' -f $avg
        $UI.BootCardAvgSub.Text = 'over the last {0} recorded boots' -f $boots.Count
    } else {
        $UI.BootCardDur.Text = 'n/a'; $UI.BootCardDurSub.Text = $(if ($b.IsAdmin) { 'no boot events recorded' } else { 'administrator rights needed' })
        $UI.BootCardAvg.Text = 'n/a'; $UI.BootCardAvgSub.Text = ''
    }
    $apps = @($b.StartupApps)
    $UI.BootCardApps.Text = '{0} / {1}' -f @($apps | Where-Object { $_.Enabled }).Count, $apps.Count
    $UI.BootCardAppsSub.Text = 'enabled / total entries, {0} auto services' -f @($b.Services | Where-Object { $_.StartType -like 'Automatic*' }).Count
    $UI.BootCardFast.Text = switch ($b.FastStartup) { $true { 'Enabled' } $false { 'Disabled' } default { 'Unknown' } }
    $UI.BootCardFastSub.Text = if ($b.FastStartup) { 'Shutdown = hybrid boot; use Restart for a full boot' } else { 'Every start is a full boot' }

    # merge service recommendations from the live data
    if ($script:LastSnap) {
        $map = @{}
        foreach ($s in $script:LastSnap.Services) { $map[$s.Name] = $s }
        foreach ($s in $b.Services) { $m = $map[$s.Name]; if ($m) { $s.Recommendation = $m.Recommendation; $s.RecColor = $m.RecColor } }
    }

    Set-GridItems $UI.BootGrid @($boots | Sort-Object Date -Descending)
    Set-GridItems $UI.StartupGrid $apps
    Set-GridItems $UI.SvcBootGrid @($b.Services | Sort-Object @{ Expression = { if ($null -eq $_.StartedAfterBootSec) { [double]::MaxValue } else { $_.StartedAfterBootSec } } })
    Set-GridItems $UI.DegGrid @($b.Degradation)
    Set-GridItems $UI.IssueGrid @($b.Issues)
    Render-BootChart $UI.BootChart
    Render-AppBootChart $UI.AppBootChart
    Render-SvcBootChart $UI.SvcBootChart

    $notes = New-Object Collections.Generic.List[string]
    if (-not $b.IsAdmin) { $notes.Add('Limited mode: boot history and boot slowdown events need administrator rights.') }
    foreach ($x in @($b.Errors)) { $notes.Add($x) }
    $notes.Add('Service start times are taken from the System event log (first state change after boot). Startup app times are measured from the start time of the running process.')
    $UI.BootNote.Text = $notes -join '  '
}

function Switch-StartupItem {
    $sel = $UI.StartupGrid.SelectedItem
    if (-not $sel) { Show-Info 'Select a startup app in the "Startup apps" list first.'; return }
    $enable = -not $sel.Enabled
    $verb = if ($enable) { 'Enable' } else { 'Disable' }
    $needsAdmin = ($sel.ApprovedPath -like 'HKLM*') -or ($sel.Kind -eq 'Task' -and $sel.Scope -ne '\')
    if ($needsAdmin -and -not $script:IsAdmin) { if (-not (Test-AdminOrWarn 'Changing this startup entry')) { return } }
    if (-not (Confirm-Action "$verb startup entry '$($sel.Name)'?`n`nLocation: $($sel.Location)`nCommand: $($sel.Command)`n`nThe entry itself is not deleted - it can be re-enabled at any time (same as in Task Manager).")) { return }
    try {
        switch ($sel.Kind) {
            'Approved' {
                if (-not $sel.ApprovedPath) { throw 'RunOnce entries run only once and cannot be enabled/disabled.' }
                if (-not (Test-Path $sel.ApprovedPath)) { New-Item -Path $sel.ApprovedPath -Force | Out-Null }
                $bytes = New-Object byte[] 12
                if ($enable) { $bytes[0] = 2 } else {
                    $bytes[0] = 3
                    [Array]::Copy([BitConverter]::GetBytes((Get-Date).ToFileTime()), 0, $bytes, 4, 8)
                }
                New-ItemProperty -Path $sel.ApprovedPath -Name $sel.ValueName -PropertyType Binary -Value $bytes -Force | Out-Null
            }
            'Task' {
                if ($enable) { Enable-ScheduledTask -TaskPath $sel.KeyPath -TaskName $sel.ValueName -ErrorAction Stop | Out-Null }
                else { Disable-ScheduledTask -TaskPath $sel.KeyPath -TaskName $sel.ValueName -ErrorAction Stop | Out-Null }
            }
            'AppX' {
                $state = if ($enable) { 2 } else { 1 }
                Set-ItemProperty -Path $sel.KeyPath -Name 'State' -Value $state -Type DWord -ErrorAction Stop
            }
        }
        $sel.Enabled = $enable
        $sel.EnabledText = if ($enable) { 'Enabled' } else { 'Disabled' }
        $UI.StartupGrid.Items.Refresh()
        Set-Status "Startup entry '$($sel.Name)' $($sel.EnabledText.ToLower()). Takes effect at the next sign-in."
    } catch { Show-ErrorMessage "Could not change the startup entry:`n$($_.Exception.Message)" }
}
#endregion

#region ---------------------------------------------------------------- Export
function Export-Items {
    param([object[]]$Items, [string]$BaseName, [string[]]$Properties)
    if (-not $Items -or @($Items).Count -eq 0) { Show-Info 'Nothing to export yet.'; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.FileName = '{0}_{1}_{2:yyyyMMdd_HHmmss}' -f $BaseName, $env:COMPUTERNAME, (Get-Date)
    $dlg.Filter = 'CSV for Excel (*.csv)|*.csv|JSON (*.json)|*.json|HTML table (*.html)|*.html'
    if (-not $dlg.ShowDialog($script:Window)) { return }
    $data = if ($Properties) { $Items | Select-Object -Property $Properties } else { $Items }
    try {
        switch ([IO.Path]::GetExtension($dlg.FileName).ToLower()) {
            '.json' { ConvertTo-Json -InputObject @($data) -Depth 4 | Set-Content -Path $dlg.FileName -Encoding UTF8 }
            '.html' {
                $body = "<h2>$([Net.WebUtility]::HtmlEncode($BaseName))</h2><p class='muted'>$env:COMPUTERNAME - $(Get-Date -Format 'g')</p>" + (($data | ConvertTo-Html -Fragment) -join "`n")
                [IO.File]::WriteAllText($dlg.FileName, (New-HtmlPage $BaseName $body), [Text.Encoding]::UTF8)
            }
            default { $data | Export-Csv -Path $dlg.FileName -NoTypeInformation -UseCulture -Encoding UTF8 }
        }
        Set-Status "Exported $(@($data).Count) rows to $($dlg.FileName)"
    } catch { Show-ErrorMessage "Export failed: $($_.Exception.Message)" }
}

function New-HtmlPage([string]$Title, [string]$Body) {
    $css = @'
body{background:#0F1115;color:#E6EAF0;font-family:"Segoe UI",Arial,sans-serif;margin:0;padding:32px;font-size:13px}
h1{font-size:26px;margin:0 0 4px 0}h2{font-size:18px;margin:34px 0 10px 0;padding-bottom:6px;border-bottom:1px solid #262D3A}
h3{font-size:14px;color:#9AA4B2;margin:20px 0 8px 0}.muted{color:#8A94A6}
table{border-collapse:collapse;width:100%;margin:6px 0 14px 0;background:#161A22;border:1px solid #232A36}
th{background:#1C212B;color:#9AA4B2;text-align:left;padding:7px 10px;font-weight:600;border-bottom:1px solid #262D3A}
td{padding:6px 10px;border-bottom:1px solid #1E2430;vertical-align:top}tr:nth-child(even) td{background:#1A1F29}
img{max-width:100%;border-radius:10px;border:1px solid #232A36;margin:6px 0 10px 0}
.cards{display:flex;flex-wrap:wrap;gap:12px}.card{background:#161A22;border:1px solid #232A36;border-radius:10px;padding:12px 16px;min-width:170px}
.card .l{color:#8A94A6;font-size:11px;font-weight:600;text-transform:uppercase}.card .v{font-size:22px;font-weight:600;margin-top:4px}
pre{background:#161A22;border:1px solid #232A36;border-radius:10px;padding:12px;font-family:Consolas,monospace}
'@
    "<!DOCTYPE html><html><head><meta charset='utf-8'><title>$([Net.WebUtility]::HtmlEncode($Title))</title><style>$css</style></head><body>$Body</body></html>"
}
function ConvertTo-HtmlTable($Items, [string[]]$Props) {
    if (-not $Items -or @($Items).Count -eq 0) { return '<p class="muted">No data.</p>' }
    (@($Items) | Select-Object -Property $Props | ConvertTo-Html -Fragment) -join "`n"
}
function Get-ChartImgTag([string]$Renderer, [double]$W = 1100, [double]$H = 380) {
    try { "<img alt='chart' src='data:image/png;base64,$([Convert]::ToBase64String((Get-ChartPngBytes $Renderer $W $H)))'/>" } catch { '' }
}
function New-HtmlCards([System.Collections.IDictionary]$Cards) {
    '<div class="cards">' + (($Cards.GetEnumerator() | ForEach-Object { "<div class='card'><div class='l'>$([Net.WebUtility]::HtmlEncode($_.Key))</div><div class='v'>$([Net.WebUtility]::HtmlEncode([string]$_.Value))</div></div>" }) -join '') + '</div>'
}

function Export-FullReport {
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html'
    $dlg.FileName = 'PerfInspector_Report_{0}_{1:yyyyMMdd_HHmmss}' -f $env:COMPUTERNAME, (Get-Date)
    if (-not $dlg.ShowDialog($script:Window)) { return }
    Set-Status 'Building report...'
    $script:Window.Cursor = [Windows.Input.Cursors]::Wait
    try {
        $sb = New-Object Text.StringBuilder
        [void]$sb.Append("<h1>PerfInspector report</h1><p class='muted'>$env:COMPUTERNAME - created $(Get-Date -Format 'F')$(if (-not $script:IsAdmin) { ' - collected without administrator rights (some boot data unavailable)' })</p>")
        [void]$sb.Append('<h2>System</h2><table>' + (($script:SysInfo.GetEnumerator() | ForEach-Object { '<tr><th>{0}</th><td>{1}</td></tr>' -f $_.Key, [Net.WebUtility]::HtmlEncode([string]$_.Value) }) -join '') + '</table>')

        if ($script:LastSnap) {
            $s = $script:LastSnap
            [void]$sb.Append('<h2>Live snapshot</h2>')
            [void]$sb.Append((New-HtmlCards ([ordered]@{
                            'CPU' = ('{0:N0} %' -f $s.CpuTotal); 'Memory' = ('{0:N0} % ({1:N1} / {2:N1} GB)' -f $s.MemUsedPct, $s.MemUsedGB, $s.MemTotalGB)
                            'Processes' = @($s.Processes).Count; 'Services running' = @($s.Services | Where-Object { $_.State -eq 'Running' }).Count
                            'Snapshot' = $s.Time.ToString('g') })))
            if ($script:CpuHist.Count -gt 1) { [void]$sb.Append((Get-ChartImgTag 'Render-LiveChart' 1100 260)) }
            [void]$sb.Append("<p class='muted'>$([Net.WebUtility]::HtmlEncode($UI.BaselineInfo.Text))</p>")
            $pp = 'Name', 'PID', 'CPU', 'MemoryMB', 'IOKBs', 'Threads', 'Status', 'Services', 'Path'
            [void]$sb.Append('<h3>Processes above usual / high usage</h3>' + (ConvertTo-HtmlTable @($s.Processes | Where-Object { $_.Alert } | Sort-Object CPU -Descending) $pp))
            [void]$sb.Append('<h3>Top 25 processes by CPU</h3>' + (ConvertTo-HtmlTable @($s.Processes | Sort-Object CPU -Descending | Select-Object -First 25) $pp))
            [void]$sb.Append('<h3>Top 25 processes by memory</h3>' + (ConvertTo-HtmlTable @($s.Processes | Sort-Object MemoryMB -Descending | Select-Object -First 25) $pp))
            $sp = 'DisplayName', 'Name', 'State', 'StartType', 'CPU', 'MemoryMB', 'IOKBs', 'Impact', 'Status', 'Recommendation'
            [void]$sb.Append('<h2>Services</h2><h3>Services above usual / high impact</h3>' + (ConvertTo-HtmlTable @($s.Services | Where-Object { $_.Alert -or $_.Impact -like 'High*' }) $sp))
            $rec = @($s.Services | Where-Object { $_.Recommendation -in 'Safe to disable', 'Set to Manual', 'Conditional', 'Review (third-party)', 'Investigate (above usual)' } | Sort-Object Recommendation, DisplayName)
            [void]$sb.Append('<h2>Recommendations</h2><p>' + [Net.WebUtility]::HtmlEncode($UI.RecSummary.Text) + '</p>' + (ConvertTo-HtmlTable $rec @('Recommendation', 'DisplayName', 'Name', 'Category', 'State', 'StartType', 'MemoryMB', 'CPU', 'Reason')))
        }

        if ($script:TestResults.Count) {
            [void]$sb.Append('<h2>Application start tests</h2>')
            [void]$sb.Append((Get-ChartImgTag 'Render-StartChart' 1100 400))
            [void]$sb.Append('<pre>' + [Net.WebUtility]::HtmlEncode($UI.TestStats.Text) + '</pre>')
            [void]$sb.Append((ConvertTo-HtmlTable $script:TestResults.ToArray() @('Run', 'Mode', 'Application', 'ProcessMs', 'InputIdleMs', 'WindowMs', 'UserReadyMs', 'TotalMs', 'MemoryMB', 'CpuTimeMs', 'Status', 'Timestamp')))
        }

        if ($script:BootData) {
            $b = $script:BootData
            [void]$sb.Append('<h2>Boot &amp; autostart</h2>')
            [void]$sb.Append((New-HtmlCards ([ordered]@{
                            'Last full boot' = $UI.BootCardLast.Text; 'Last start' = $UI.BootCardRef.Text; 'Last boot duration' = $UI.BootCardDur.Text
                            'Average boot' = $UI.BootCardAvg.Text; 'Autostart entries' = $UI.BootCardApps.Text; 'Fast Startup' = $UI.BootCardFast.Text })))
            [void]$sb.Append('<h3>Boot history</h3>' + (Get-ChartImgTag 'Render-BootChart' 1100 340) + (ConvertTo-HtmlTable @($b.Boots) @('Date', 'BootSec', 'MainPathSec', 'PostBootSec', 'Rating')))
            [void]$sb.Append('<h3>Startup apps</h3>' + (Get-ChartImgTag 'Render-AppBootChart' 1100 360) + (ConvertTo-HtmlTable @($b.StartupApps) @('EnabledText', 'Name', 'Publisher', 'Location', 'Scope', 'Running', 'StartedAfterBootSec', 'Delay', 'Command')))
            [void]$sb.Append('<h3>Services at boot</h3>' + (Get-ChartImgTag 'Render-SvcBootChart' 1100 520) + (ConvertTo-HtmlTable @($b.Services | Sort-Object StartedAfterBootSec -Descending) @('DisplayName', 'Name', 'StartType', 'State', 'StartedAfterBootSec', 'BootDelayMs', 'Recommendation')))
            [void]$sb.Append('<h3>Boot slowdown events</h3>' + (ConvertTo-HtmlTable @($b.Degradation) @('Date', 'EventId', 'Type', 'Name', 'TotalMs', 'DegradationMs', 'File')))
            [void]$sb.Append('<h3>Service errors since boot</h3>' + (ConvertTo-HtmlTable @($b.Issues) @('Date', 'EventId', 'Service', 'Message')))
        } else {
            [void]$sb.Append("<h2>Boot &amp; autostart</h2><p class='muted'>Boot analysis was not run before creating this report.</p>")
        }

        [IO.File]::WriteAllText($dlg.FileName, (New-HtmlPage "PerfInspector report - $env:COMPUTERNAME" $sb.ToString()), [Text.Encoding]::UTF8)
        Set-Status "Report saved to $($dlg.FileName)"
        $script:Window.Cursor = $null
        if (Confirm-Action "Report saved:`n$($dlg.FileName)`n`nOpen it now?" 'Report created') { Start-Process -FilePath $dlg.FileName }
    } catch {
        Show-ErrorMessage "Report could not be created: $($_.Exception.Message)"
    } finally { $script:Window.Cursor = $null }
}
#endregion

#region ---------------------------------------------------------------- Wire up events
# Header
$UI.HdrSub.Text = '{0}  |  {1}  |  {2}' -f $script:SysInfo['Computer'], $script:SysInfo['OS'], $script:SysInfo['CPU']
if ($script:IsAdmin) {
    $UI.AdminBadge.Background = Get-Brush '#1B3A2A'; $UI.AdminText.Foreground = Get-Brush '#2ECC71'; $UI.AdminText.Text = 'ADMINISTRATOR'
    $UI.BtnElevate.Visibility = 'Collapsed'
} else {
    $UI.AdminBadge.Background = Get-Brush '#3A2C17'; $UI.AdminText.Foreground = Get-Brush '#F5A524'; $UI.AdminText.Text = 'LIMITED MODE'
    if (-not $script:ScriptPath) { $UI.BtnElevate.Visibility = 'Collapsed' }
}
$UI.BtnElevate.Add_Click({
        try {
            Start-Process -FilePath $script:HostExe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -File `"$($script:ScriptPath)`""
            $script:Window.Close()
        } catch { Set-Status 'Elevation was cancelled.' }
    })
$UI.BtnReport.Add_Click({ Export-FullReport })

# Main tabs - start the boot analysis automatically the first time the tab is opened
$UI.MainTabs.Add_SelectionChanged({
        param($sender, $e)
        if ($e.OriginalSource -ne $UI.MainTabs) { return }
        if ($UI.MainTabs.SelectedIndex -eq 4 -and -not $script:BootData -and -not $script:BootBusy) { Start-BootAnalysis }
    })

# Live monitor
$script:LiveTimer = New-Object Windows.Threading.DispatcherTimer
$script:LiveTimer.Interval = [TimeSpan]::FromSeconds(5)
$script:LiveTimer.Add_Tick({ if ($UI.LiveAuto.IsChecked -and -not $script:TestRunning -and -not $script:Manual) { Start-LiveRefresh } })
$UI.LiveInterval.Add_SelectionChanged({
        $idx = $UI.LiveInterval.SelectedIndex
        if ($idx -ge 0) { $script:LiveTimer.Interval = [TimeSpan]::FromSeconds(@(2, 5, 10, 30)[$idx]) }
    })
$UI.BtnLiveRefresh.Add_Click({ Start-LiveRefresh })
$UI.ProcFilter.Add_TextChanged({ Update-ProcGrid })
$UI.ProcOnlyFlagged.Add_Click({ Update-ProcGrid })
$UI.BtnBaseline.Add_Click({ Start-BaselineRecording })
$UI.BtnBaselineClear.Add_Click({
        if (-not (Test-Path $script:BaselineFile)) { Show-Info 'No baseline recorded.'; return }
        if (Confirm-Action 'Delete the recorded baseline? Absolute thresholds will be used again.') {
            Remove-Item -Path $script:BaselineFile -Force -ErrorAction SilentlyContinue
            Import-Baseline
            Start-LiveRefresh
        }
    })
$UI.BtnKillProc.Add_Click({
        $sel = @($UI.ProcGrid.SelectedItems)
        if (-not $sel.Count) { Show-Info 'Select one or more processes first.'; return }
        $list = ($sel | ForEach-Object { " - $($_.Name) (PID $($_.PID))" }) -join "`n"
        if (-not (Confirm-Action "End these process(es)? Unsaved data will be lost.`n`n$list")) { return }
        $errs = @()
        foreach ($p in $sel) { try { Stop-Process -Id $p.PID -Force -ErrorAction Stop } catch { $errs += "$($p.Name): $($_.Exception.Message)" } }
        if ($errs.Count) { Show-ErrorMessage ($errs -join "`n") }
        Start-LiveRefresh
    })
$UI.BtnProcExport.Add_Click({
        $items = @($UI.ProcGrid.Items)
        Export-Items $items 'Processes' @('Name', 'PID', 'CPU', 'MemoryMB', 'IOKBs', 'Threads', 'Handles', 'Status', 'Services', 'Path')
    })
$UI.LiveChart.Add_SizeChanged({ Render-LiveChart $UI.LiveChart })

# Services
$UI.SvcFilter.Add_TextChanged({ Update-SvcGrid })
$UI.SvcView.Add_SelectionChanged({ Update-SvcGrid })
$UI.BtnSvcRefresh.Add_Click({ Start-LiveRefresh })
$UI.BtnSvcExport.Add_Click({
        Export-Items @($UI.SvcGrid.Items) 'Services' @('DisplayName', 'Name', 'State', 'StartType', 'CPU', 'MemoryMB', 'IOKBs', 'Impact', 'Status', 'Recommendation', 'Category', 'Reason', 'Account', 'PathName', 'Description')
    })
$UI.SvcGrid.Add_SelectionChanged({ Show-ServiceDetails $UI.SvcGrid.SelectedItem })
$UI.BtnSvcStart.Add_Click({ Invoke-ServiceAction 'Start' })
$UI.BtnSvcStop.Add_Click({ Invoke-ServiceAction 'Stop' })
$UI.BtnSvcRestart.Add_Click({ Invoke-ServiceAction 'Restart' })
$UI.BtnSvcApplyType.Add_Click({
        $modes = @('auto', 'delayed-auto', 'demand', 'disabled')
        $labels = @('Automatic', 'Automatic (Delayed)', 'Manual', 'Disabled')
        $i = $UI.SvcStartType.SelectedIndex
        if ($i -lt 0) { return }
        Set-ServiceStartup -Services @($UI.SvcGrid.SelectedItems) -ScMode $modes[$i] -Label $labels[$i]
    })
$UI.BtnSvcRestore.Add_Click({ Restore-ServiceChanges })
Show-ServiceDetails $null

# Recommendations
$UI.RecFilter.Add_SelectionChanged({ Update-Recommendations })
$UI.BtnRecManual.Add_Click({ Set-ServiceStartup -Services @($UI.RecGrid.SelectedItems) -ScMode 'demand' -Label 'Manual' })
$UI.BtnRecDisable.Add_Click({ Set-ServiceStartup -Services @($UI.RecGrid.SelectedItems) -ScMode 'disabled' -Label 'Disabled' })
$UI.BtnRecRestore.Add_Click({ Restore-ServiceChanges })
$UI.BtnRecExport.Add_Click({
        Export-Items @($UI.RecGrid.Items) 'ServiceRecommendations' @('Recommendation', 'DisplayName', 'Name', 'Category', 'State', 'StartType', 'MemoryMB', 'CPU', 'Impact', 'Status', 'Reason')
    })
$UI.RecGrid.Add_MouseDoubleClick({
        $sel = $UI.RecGrid.SelectedItem
        if (-not $sel) { return }
        $UI.SvcView.SelectedIndex = 0
        $UI.SvcFilter.Text = $sel.Name
        $UI.MainTabs.SelectedIndex = 1
        foreach ($it in $UI.SvcGrid.Items) { if ($it.Name -eq $sel.Name) { $UI.SvcGrid.SelectedItem = $it; $UI.SvcGrid.ScrollIntoView($it); break } }
    })

# App start test
$UI.BtnBrowseExe.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Applications and shortcuts (*.exe;*.lnk;*.bat;*.cmd)|*.exe;*.lnk;*.bat;*.cmd|All files (*.*)|*.*'
        $dlg.DereferenceLinks = $false
        if ($dlg.ShowDialog($script:Window)) {
            $UI.TestExe.Text = $dlg.FileName
            if ($dlg.FileName -like '*.lnk') {
                try {
                    $t = (New-Object -ComObject WScript.Shell).CreateShortcut($dlg.FileName).TargetPath
                    if ($t -and -not $UI.TestWatch.Text) { $UI.TestWatch.Text = [IO.Path]::GetFileNameWithoutExtension($t) }
                } catch { }
            }
        }
    })
$UI.BtnTestRun.Add_Click({ Start-AppTest })
$UI.BtnTestCancel.Add_Click({ $script:Sync.Cancel = $true; Set-Status 'Cancelling test after the current step...' })
$UI.BtnTestExport.Add_Click({ Export-Items $script:TestResults.ToArray() 'AppStartTest' })
$UI.BtnTestChartPng.Add_Click({ Save-ChartPng 'Render-StartChart' 'AppStartChart' $UI.StartChart })
$UI.BtnTestClear.Add_Click({
        if (-not $script:TestResults.Count) { return }
        if (-not (Confirm-Action 'Clear all test results?')) { return }
        $script:TestResults.Clear()
        $script:Sync.TestResults.Clear()
        $script:TestIngested = 0
        Set-GridItems $UI.TestGrid @()
        Render-StartChart $UI.StartChart
        Update-TestStats
    })
$UI.StartChart.Add_SizeChanged({ Render-StartChart $UI.StartChart })

$script:ManualTimer = New-Object Windows.Threading.DispatcherTimer
$script:ManualTimer.Interval = [TimeSpan]::FromMilliseconds(30)
$script:ManualTimer.Add_Tick({ Invoke-ManualTick })
$UI.BtnManualStart.Add_Click({ Start-ManualTest })
$UI.BtnManualReady.Add_Click({ Complete-ManualTest })
$UI.BtnManualCancel.Add_Click({ Stop-ManualTest })

# Boot
$UI.BtnBootAnalyze.Add_Click({ Start-BootAnalysis })
$UI.BtnStartupToggle.Add_Click({ Switch-StartupItem })
$UI.BtnBootExport.Add_Click({
        if (-not $script:BootData) { Show-Info 'Run "Analyze boot & autostart" first.'; return }
        $b = $script:BootData
        switch ($UI.BootTabs.SelectedIndex) {
            0 { Export-Items $b.Boots 'BootHistory' @('Date', 'BootSec', 'MainPathSec', 'PostBootSec', 'Rating') }
            1 { Export-Items $b.StartupApps 'StartupApps' @('EnabledText', 'Name', 'Publisher', 'Description', 'Location', 'Scope', 'Running', 'StartedAfterBootSec', 'Delay', 'Command', 'ExePath') }
            2 { Export-Items $b.Services 'ServicesAtBoot' @('DisplayName', 'Name', 'StartType', 'State', 'StartedAfterBootSec', 'BootDelayMs', 'Recommendation', 'PathName') }
            3 { Export-Items $b.Degradation 'BootSlowdowns' @('Date', 'EventId', 'Type', 'Name', 'TotalMs', 'DegradationMs', 'File') }
            4 { Export-Items $b.Issues 'ServiceErrors' @('Date', 'EventId', 'Service', 'Message') }
        }
    })
$UI.BtnBootChartPng.Add_Click({
        switch ($UI.BootTabs.SelectedIndex) {
            0 { Save-ChartPng 'Render-BootChart' 'BootHistory' $UI.BootChart }
            1 { Save-ChartPng 'Render-AppBootChart' 'StartupApps' $UI.AppBootChart }
            2 { Save-ChartPng 'Render-SvcBootChart' 'ServicesAtBoot' $UI.SvcBootChart }
            default { Show-Info 'This view has no chart. Select "Boot history", "Startup apps" or "Services at boot".' }
        }
    })
$UI.BootChart.Add_SizeChanged({ Render-BootChart $UI.BootChart })
$UI.AppBootChart.Add_SizeChanged({ Render-AppBootChart $UI.AppBootChart })
$UI.SvcBootChart.Add_SizeChanged({ Render-SvcBootChart $UI.SvcBootChart })

# Job pump + startup
$script:JobTimer = New-Object Windows.Threading.DispatcherTimer
$script:JobTimer.Interval = [TimeSpan]::FromMilliseconds(200)
$script:JobTimer.Add_Tick({ Invoke-JobPump })
$script:JobTimer.Start()

$script:Window.Add_ContentRendered({
        Import-Baseline
        Render-StartChart $UI.StartChart
        Start-LiveRefresh
        $script:LiveTimer.Start()
    })
$script:Window.Add_Closing({
        $script:Sync.Cancel = $true
        $script:LiveTimer.Stop()
        $script:JobTimer.Stop()
        if ($script:ManualTimer) { $script:ManualTimer.Stop() }
        foreach ($job in @($script:Jobs)) { try { [void]$job.PS.BeginStop($null, $null) } catch { } }
    })
#endregion

[void]$script:Window.ShowDialog()

try { $script:Pool.Close(); $script:Pool.Dispose() } catch { }

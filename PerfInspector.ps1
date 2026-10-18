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
    - Start Trace     : live trace of an app start - the chain of processes it starts, what is busy in the background
                       (antivirus, indexing, updates, other apps), services started on demand, where the time went and why it was slow.
    - Boot timeline  : boot phases until the desktop, services and programs started, Group Policy, reported slowdowns and
                       (optional) a recording of the CPU/disk activity of every process during the next boot.
    - Every table can be exported to CSV (Excel), JSON or HTML, every chart to PNG,
      and a full HTML report with all charts can be generated.

.PARAMETER HideConsole
    Hides the PowerShell console window while the GUI is open.

.PARAMETER BootTraceRecord
    Internal: headless boot activity recorder (started by the 'Record next boot' scheduled task).

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\PerfInspector.ps1

.NOTES
    Version : 2.0
    Requires: Windows 10 / 11, Windows PowerShell 5.1 or PowerShell 7+
    Run as Administrator for full functionality (boot diagnostics log, service changes, HKLM autostart entries).
    Data (baseline, service change backup) is stored in %LOCALAPPDATA%\PerfInspector
#>
[CmdletBinding()]
param([switch]$HideConsole, [switch]$BootTraceRecord, [int]$BootTraceSeconds = 180)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { Write-Error 'PerfInspector requires Windows.'; return }

$script:ScriptPath = $MyInvocation.MyCommand.Path
$script:HostExe    = (Get-Process -Id $PID).Path

# WPF needs an STA thread - relaunch if necessary
if (-not $BootTraceRecord -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) {
    if ($script:ScriptPath) {
        Start-Process -FilePath $script:HostExe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$script:ScriptPath`"")
    } else {
        Write-Error 'Please run this script in an STA session (powershell.exe -STA).'
    }
    return
}

if (-not $BootTraceRecord) { Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, System.Windows.Forms }

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
    $raw100 = New-Object System.Collections.Generic.List[object]
    try {
        $evs = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } -MaxEvents 30 -ErrorAction Stop
        foreach ($e in $evs) {
            $d = Get-EvData $e
            $raw100.Add(@{ Ev = $e; D = $d; Start = $null })
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

    # --- detailed timeline of the current boot (phases, services, programs, policies)
    $match = $null
    foreach ($r in $raw100) {
        $bs = $null
        try { $bs = [datetime]::Parse([string]$r.D['BootStartTime'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime() } catch { }
        if ($bs -and (([Math]::Abs(($bs - $bootRef).TotalSeconds) -lt 240) -or ([Math]::Abs(($bs - $lastBoot).TotalSeconds) -lt 240))) { $r.Start = $bs; $match = $r; break }
    }
    function Get-D100([string]$n) { if (-not $match) { return 0.0 }; ToD $match.D[$n] }
    $t0 = if ($match) { $match.Start } else { $bootRef }
    $phases = New-Object System.Collections.Generic.List[object]
    $addPhase = { param($n, $st, $du, $c) if ($du -gt 0) { $phases.Add([pscustomobject]@{ Name = $n; Start = [Math]::Round($st / 1000, 2); Duration = [Math]::Round($du / 1000, 2); Color = $c }) } }
    $mainPath = Get-D100 'MainPathBootTime'
    $bootTime = Get-D100 'BootTime'
    $wl = 0.0
    if ($match) {
        & $addPhase 'Boot loader' 0 (Get-D100 'OSLoaderDuration') '#5A6275'
        $pnpS = Get-D100 'BootPNPInitStartTimeMS'; $pnpD = Get-D100 'BootPNPInitDuration'
        & $addPhase 'Boot drivers (PnP)' $pnpS $pnpD '#7C5CFF'
        & $addPhase 'Kernel init (other)' ($pnpS + $pnpD) (Get-D100 'OtherKernelInitDuration') '#5BC0EB'
        & $addPhase 'Devices (system PnP)' (Get-D100 'SystemPNPInitStartTimeMS') (Get-D100 'SystemPNPInitDuration') '#B08CFF'
        & $addPhase 'Session init (services start)' (Get-D100 'SessionInitStartTimeMS') ((Get-D100 'Session0InitDuration') + (Get-D100 'Session1InitDuration') + (Get-D100 'SessionInitOtherDuration')) '#F5A524'
        $wl = Get-D100 'WinLogonStartTimeMS'; $wlD = Get-D100 'OtherLogonInitActivityDuration'
        & $addPhase 'Logon processing' $wl $wlD '#2EC4B6'
        & $addPhase 'Waiting at sign-in screen' ($wl + $wlD) (Get-D100 'UserLogonWaitDuration') '#3A4356'
        $exD = Get-D100 'BootExplorerInitTime'
        & $addPhase 'Explorer / desktop init' ($mainPath - $exD) $exD '#2ECC71'
        & $addPhase 'Post boot (until idle)' $mainPath (Get-D100 'BootPostBootTime') '#4F5B70'
    }
    $durNames = [ordered]@{
        OSLoaderDuration = 'Boot loader'; BootKernelInitTime = 'Kernel init'; BootDriverInitTime = 'Driver init'; BootDevicesInitTime = 'Devices init'
        BootPrefetchInitTime = 'Prefetch init'; BootAutoChkTime = 'Disk check (autochk)'; BootSmssInitTime = 'Session manager (SMSS)'
        BootCriticalServicesInitTime = 'Critical services'; BootMachineProfileProcessingTime = 'Computer policies / machine profile'
        BootUserProfileProcessingTime = 'User profile load'; BootExplorerInitTime = 'Explorer / desktop init'; BootPNPInitDuration = 'Boot drivers (PnP)'
        OtherKernelInitDuration = 'Other kernel init'; SystemPNPInitDuration = 'System devices (PnP)'; Session0InitDuration = 'Session 0 init (services)'
        Session1InitDuration = 'Session 1 init (user session)'; SessionInitOtherDuration = 'Other session init'; OtherLogonInitActivityDuration = 'Logon processing'
        UserLogonWaitDuration = 'Waiting at sign-in screen'; BootPostBootTime = 'Post boot (until idle)'
    }
    $durations = New-Object System.Collections.Generic.List[object]
    foreach ($k in $durNames.Keys) { $v = Get-D100 $k; if ($v -gt 0) { $durations.Add([pscustomobject]@{ Name = $durNames[$k]; Seconds = [Math]::Round($v / 1000, 2) }) } }

    $dispToName = @{}
    foreach ($s in $svcs) { if ($s.DisplayName) { $dispToName[[string]$s.DisplayName] = [string]$s.Name } }
    $svcStarts = New-Object System.Collections.Generic.List[object]
    foreach ($k in $first.Keys) { $svcStarts.Add([pscustomobject]@{ DisplayName = $k; Name = $(if ($dispToName[$k]) { $dispToName[$k] } else { $k }); T = [Math]::Round(($first[$k] - $t0).TotalSeconds, 2) }) }

    $procStarts = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath, CreationDate, SessionId, ParentProcessId -ErrorAction SilentlyContinue)) {
        if (-not $p.CreationDate) { continue }
        $off = ($p.CreationDate - $t0).TotalSeconds
        if ($off -lt -5 -or $off -gt 900) { continue }
        $procStarts.Add([pscustomobject]@{ Name = ([string]$p.Name -replace '\.exe$', ''); PID = [int]$p.ProcessId; T = [Math]::Round($off, 2); Session = [int]$p.SessionId; Path = [string]$p.ExecutablePath; Parent = [int]$p.ParentProcessId })
    }
    $explorerT = $null
    $ex = @($procStarts | Where-Object { $_.Name -eq 'explorer' -and $_.Session -gt 0 } | Sort-Object T) | Select-Object -First 1
    if ($ex) { $explorerT = [double]$ex.T }
    $desktopT = if ($mainPath -gt 0) { $mainPath / 1000 } elseif ($null -ne $explorerT) { $explorerT } else { $null }

    $markers = New-Object System.Collections.Generic.List[object]
    if ($wl -gt 0) { $markers.Add([pscustomobject]@{ Name = 'Winlogon started'; T = [Math]::Round($wl / 1000, 2); Color = '#2EC4B6' }) }
    if ($null -ne $explorerT) { $markers.Add([pscustomobject]@{ Name = 'Explorer started'; T = $explorerT; Color = '#8FA3BF' }) }
    if ($mainPath -gt 0) { $markers.Add([pscustomobject]@{ Name = 'Desktop ready'; T = [Math]::Round($mainPath / 1000, 2); Color = '#2ECC71' }) }
    if ($bootTime -gt 0) { $markers.Add([pscustomobject]@{ Name = 'Boot complete (idle)'; T = [Math]::Round($bootTime / 1000, 2); Color = '#8A94A6' }) }

    $pol = New-Object System.Collections.Generic.List[object]
    try {
        $gp = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; Id = 8000, 8001; StartTime = $bootRef.AddMinutes(-2); EndTime = $bootRef.AddMinutes(30) } -ErrorAction Stop
        foreach ($e in $gp) {
            $d = Get-EvData $e
            $sec = ToD $d['PolicyElaspedTimeInSeconds']
            $nm = if ($e.Id -eq 8000) { 'Computer policy (boot)' } else { 'User policy (logon)' }
            $pol.Add([pscustomobject]@{ Name = $nm; T = [Math]::Round(($e.TimeCreated - $t0).TotalSeconds - $sec, 2); Duration = $sec })
        }
    } catch { }
    $fw = 0.0
    try { $fw = [double](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name FwPOSTTime -ErrorAction Stop).FwPOSTTime / 1000 } catch { }
    $bootDeg = @()
    if ($match) { $mt = $match.Ev.TimeCreated; $bootDeg = @($deg | Where-Object { [Math]::Abs(($_.Date - $mt).TotalMinutes) -le 10 }) }
    $sched = $false
    try { $sched = [bool](Get-ScheduledTask -TaskName 'PerfInspector Boot Trace' -TaskPath '\PerfInspector\' -ErrorAction Stop) } catch { }
    $timeline = [pscustomobject]@{
        T0 = $t0; Matched = [bool]$match; Phases = $phases.ToArray(); Durations = $durations.ToArray(); Markers = $markers.ToArray()
        DesktopT = $desktopT; BootEndT = $(if ($bootTime -gt 0) { $bootTime / 1000 } else { $null }); MainPathSec = $mainPath / 1000
        LogonWaitSec = (Get-D100 'UserLogonWaitDuration') / 1000; FirmwareSec = $fw; ServiceStarts = $svcStarts.ToArray()
        ProcessStarts = $procStarts.ToArray(); Policies = $pol.ToArray(); Slowdowns = $bootDeg; StartupAppsCount = (Get-D100 'BootNumStartupApps')
        RecordingScheduled = $sched; ExplorerT = $explorerT
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
        Timeline    = $timeline
    }
}
#endregion

#region ---------------------------------------------------------------- Trace engine (background runspaces + boot recorder)
function Get-QpcSec { [Diagnostics.Stopwatch]::GetTimestamp() / [double][Diagnostics.Stopwatch]::Frequency }

function Get-TraceKeys($o) {
    if ($null -eq $o) { return @() }
    if ($o -is [Collections.IDictionary]) { return @($o.Keys) }
    @($o.PSObject.Properties | ForEach-Object { $_.Name })
}

# One raw sample of all processes (locale independent WMI raw counters)
function Get-TraceRawSample {
    $s = @{ Qpc = 0; Procs = @{}; Ts = 0.0; Disk = $null; Mem = $null }
    $rows = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -Property Name, IDProcess, CreatingProcessID, PercentProcessorTime, IODataBytesPersec, WorkingSetPrivate, Timestamp_Sys100NS -ErrorAction SilentlyContinue)
    $s.Qpc = [Diagnostics.Stopwatch]::GetTimestamp()
    foreach ($r in $rows) {
        $id = [int]$r.IDProcess
        if ($id -eq 0 -or $r.Name -eq '_Total') { continue }
        $ts = [double]$r.Timestamp_Sys100NS
        if ($ts -gt $s.Ts) { $s.Ts = $ts }
        $s.Procs[[string]$id] = @(([string]$r.Name -replace '#\d+$', ''), [int]$r.CreatingProcessID, [double]$r.PercentProcessorTime, [double]$r.IODataBytesPersec, [double]$r.WorkingSetPrivate, $ts)
    }
    try {
        $d = Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -Property DiskBytesPersec, CurrentDiskQueueLength, Timestamp_Sys100NS -ErrorAction Stop | Select-Object -First 1
        if ($d) { $s.Disk = @([double]$d.DiskBytesPersec, [double]$d.CurrentDiskQueueLength, [double]$d.Timestamp_Sys100NS) }
    } catch { }
    try {
        $m = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Memory -Property PageReadsPersec, AvailableMBytes, Timestamp_Sys100NS -ErrorAction Stop | Select-Object -First 1
        if ($m) { $s.Mem = @([double]$m.PageReadsPersec, [double]$m.AvailableMBytes, [double]$m.Timestamp_Sys100NS) }
    } catch { }
    $s
}

# Difference of two raw samples -> rates (CPU % of the whole machine, KB/s)
function Convert-TraceDelta($Prev, $Cur, [int]$Cores) {
    $o = @{ T = 0.0; T0 = 0.0; Cpu = 0.0; DiskKBs = 0.0; Queue = 0.0; HardFaults = 0.0; AvailMB = 0.0; P = @{} }
    $gdt = ($Cur.Ts - $Prev.Ts) / 1e7
    foreach ($k in $Cur.Procs.Keys) {
        $c = $Cur.Procs[$k]; $p = $Prev.Procs[$k]
        if ($p -and $p[0] -eq $c[0]) { $dt = ($c[5] - $p[5]) / 1e7; $pc = $p[2]; $pio = $p[3] }
        else { $dt = $gdt; $pc = 0.0; $pio = 0.0 }   # process started during the interval
        if ($dt -le 0) { continue }
        $cpu = [Math]::Min(100, [Math]::Max(0, ($c[2] - $pc) / 1e7 / $dt * 100 / $Cores))
        $io = [Math]::Max(0, ($c[3] - $pio) / $dt / 1KB)
        $o.Cpu += $cpu
        if ($cpu -ge 0.05 -or $io -ge 4) { $o.P[$k] = @([Math]::Round($cpu, 2), [Math]::Round($io, 1), [Math]::Round($c[4] / 1MB, 1)) }
    }
    $o.Cpu = [Math]::Round([Math]::Min(100, $o.Cpu), 1)
    if ($Cur.Disk -and $Prev.Disk) {
        $dd = ($Cur.Disk[2] - $Prev.Disk[2]) / 1e7
        if ($dd -gt 0) { $o.DiskKBs = [Math]::Round([Math]::Max(0, ($Cur.Disk[0] - $Prev.Disk[0]) / $dd / 1KB), 1) }
        $o.Queue = $Cur.Disk[1]
    }
    if ($Cur.Mem -and $Prev.Mem) {
        $dm = ($Cur.Mem[2] - $Prev.Mem[2]) / 1e7
        if ($dm -gt 0) { $o.HardFaults = [Math]::Round([Math]::Max(0, ($Cur.Mem[0] - $Prev.Mem[0]) / $dm), 0) }
        $o.AvailMB = $Cur.Mem[1]
    }
    $o
}

# Name, parent, path and creation time of processes (creation time converted to QPC seconds)
function Add-TraceProcMeta($Meta, [string[]]$Ids, $Cur, [double]$QpcNowSec) {
    $nowWall = [DateTime]::Now
    for ($i = 0; $i -lt $Ids.Count; $i += 25) {
        $chunk = @($Ids[$i..([Math]::Min($i + 24, $Ids.Count - 1))])
        $filter = ($chunk | ForEach-Object { "ProcessId=$_" }) -join ' OR '
        $found = @{}
        foreach ($w in @(Get-CimInstance -ClassName Win32_Process -Filter $filter -Property ProcessId, Name, ExecutablePath, CreationDate, ParentProcessId, SessionId -ErrorAction SilentlyContinue)) {
            $created = $null
            if ($w.CreationDate) { $created = $QpcNowSec - ($nowWall - $w.CreationDate).TotalSeconds }
            $k = [string]$w.ProcessId
            $found[$k] = $true
            $Meta[$k] = @{ Name = ([string]$w.Name -replace '\.exe$', ''); Parent = [int]$w.ParentProcessId; Path = [string]$w.ExecutablePath; Created = $created; Session = [int]$w.SessionId }
        }
        foreach ($k in $chunk) {
            if (-not $found.ContainsKey($k) -and $Cur.Procs.ContainsKey($k)) {
                $c = $Cur.Procs[$k]   # process already exited again - keep what the counters know
                $Meta[$k] = @{ Name = $c[0]; Parent = $c[1]; Path = ''; Created = $QpcNowSec; Session = -1 }
            }
        }
    }
}

function Get-TraceServiceMap {
    $map = @{}
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter 'ProcessId > 0' -Property Name, ProcessId -ErrorAction SilentlyContinue)) {
        $k = [string]$s.ProcessId
        if ($map.ContainsKey($k)) { $map[$k] += ", $($s.Name)" } else { $map[$k] = [string]$s.Name }
    }
    $map
}

# Samples all processes until $Sync.TraceStop is set (or MaxSeconds reached)
function Invoke-TraceSampler {
    param($Sync, [int]$IntervalMs = 500, [int]$MaxSeconds = 120)
    $cores = [Environment]::ProcessorCount
    $freq = [double][Diagnostics.Stopwatch]::Frequency
    $Sync.TraceClock = @{ Qpc = (Get-QpcSec); Wall = [DateTime]::Now }
    $null = Get-TraceRawSample          # warm up the WMI performance provider
    $prev = Get-TraceRawSample
    Add-TraceProcMeta $Sync.TraceProcs @($prev.Procs.Keys) $prev ($prev.Qpc / $freq)
    $svc = Get-TraceServiceMap
    foreach ($k in $svc.Keys) { $Sync.TraceSvcMap[$k] = $svc[$k] }
    $Sync.TraceReady = $true
    $start = $prev.Qpc / $freq
    $next = Get-QpcSec
    while (-not $Sync.TraceStop) {
        $next += $IntervalMs / 1000.0
        $wait = ($next - (Get-QpcSec)) * 1000
        if ($wait -gt 1) { Start-Sleep -Milliseconds ([int]$wait) } else { $next = Get-QpcSec }
        if ($Sync.TraceStop) { break }
        $cur = Get-TraceRawSample
        $d = Convert-TraceDelta $prev $cur $cores
        $d.T0 = $prev.Qpc / $freq
        $d.T = $cur.Qpc / $freq
        [void]$Sync.TraceSamples.Add($d)
        $new = @($cur.Procs.Keys | Where-Object { -not $Sync.TraceProcs.ContainsKey($_) })
        if ($new.Count) { Add-TraceProcMeta $Sync.TraceProcs $new $cur ($cur.Qpc / $freq) }
        $prev = $cur
        if (($d.T - $start) -ge $MaxSeconds) { break }
    }
    $svc = Get-TraceServiceMap
    foreach ($k in $svc.Keys) { if (-not $Sync.TraceSvcMap.ContainsKey($k)) { $Sync.TraceSvcMap[$k] = $svc[$k] } }
    $Sync.TraceSamplerDone = $true
}

# Launches the app (or waits until the user starts it) and records the milestones
function Invoke-TraceLaunch {
    param([string]$Mode, [string]$Exe, [string]$Arguments, [string]$WatchName, [int]$TimeoutSec = 60, [int]$PostSec = 3, $Sync)
    $marks = $Sync.TraceMarks
    $w = 0
    while (-not $Sync.TraceReady -and -not $Sync.Cancel -and $w -lt 900) { Start-Sleep -Milliseconds 50; $w++ }
    if ($Sync.Cancel) { $marks.Error = 'Cancelled'; $Sync.TraceStop = $true; return }
    $Sync.Progress = 'Recording background activity before the start ...'
    Start-Sleep -Milliseconds 1500
    $isShell = $Exe -like 'shell:*'
    $names = @()
    if ($WatchName) { $names = @($WatchName -split '[,;]' | ForEach-Object { $_.Trim() -replace '\.exe$', '' } | Where-Object { $_ }) }
    elseif ($Exe -and -not $isShell) { $names = @([IO.Path]::GetFileNameWithoutExtension($Exe)) }
    $pre = @{}
    if ($names.Count) { foreach ($pp in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) { $pre[$pp.Id] = $true } }
    $p = $null
    if ($Mode -eq 'Launch') {
        $Sync.Progress = "Starting $Exe ..."
        $marks.Launch = Get-QpcSec
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
            $marks.Process = Get-QpcSec
            if ($p) { $marks.RootPid = $p.Id }
        } catch {
            $marks.Error = "Launch failed: $($_.Exception.Message)"
            $marks.End = Get-QpcSec
            $Sync.TraceStop = $true
            return
        }
    } else {
        $Sync.Progress = "Waiting for you to start '$($names -join ', ')' (up to 5 minutes) ..."
        $deadline = (Get-QpcSec) + 300
        while (-not $Sync.Cancel -and (Get-QpcSec) -lt $deadline) {
            $c = @(Get-Process -Name $names -ErrorAction SilentlyContinue | Where-Object { -not $pre.ContainsKey($_.Id) } | Sort-Object StartTime) | Select-Object -First 1
            if ($c) { $p = $c; break }
            Start-Sleep -Milliseconds 40
        }
        if (-not $p) {
            $marks.Error = $(if ($Sync.Cancel) { 'Cancelled' } else { 'The application was not started within 5 minutes.' })
            $Sync.TraceStop = $true
            return
        }
        $nowQ = Get-QpcSec
        $created = $nowQ
        try { $created = $nowQ - ([DateTime]::Now - $p.StartTime).TotalSeconds } catch { }
        $marks.Launch = $created
        $marks.Process = $created
        $marks.RootPid = $p.Id
    }
    $Sync.Progress = 'Recording the start - waiting for the main window ...'
    $timeoutAt = [double]$marks.Launch + $TimeoutSec
    if ($p) {
        try {
            $ms = [int]([Math]::Max(1, ($timeoutAt - (Get-QpcSec))) * 1000)
            if ($p.WaitForInputIdle($ms)) { $marks.InputIdle = Get-QpcSec }
        } catch { }
    }
    $target = $null
    while ((Get-QpcSec) -lt $timeoutAt -and -not $Sync.Cancel) {
        if ($p) {
            try { if (-not $p.HasExited) { $p.Refresh(); if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $target = $p; break } } } catch { }
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
        $marks.Window = Get-QpcSec
        $marks.WindowPid = $target.Id
        $Sync.Progress = 'Window visible - recording what happens right after ...'
        $until = (Get-QpcSec) + $PostSec
        while ((Get-QpcSec) -lt $until -and -not $Sync.Cancel) { Start-Sleep -Milliseconds 100 }
    } elseif ($Sync.Cancel) {
        $marks.Error = 'Cancelled'
    } else {
        $marks.Timeout = $true
    }
    $marks.End = Get-QpcSec
    $Sync.TraceStop = $true
    $Sync.Progress = ''
}

# Copies the collected data and converts all times to seconds relative to $Origin (QPC seconds)
function ConvertTo-TraceData {
    param($Sync, [double]$Origin, [double]$MinRel = -1e9)
    $samples = New-Object Collections.Generic.List[object]
    foreach ($s in @($Sync.TraceSamples.ToArray())) {
        $t = [double]$s.T - $Origin
        if ($t -lt $MinRel) { continue }
        $samples.Add([pscustomobject]@{ T = [Math]::Round($t, 3); T0 = [Math]::Round([double]$s.T0 - $Origin, 3); Cpu = $s.Cpu; DiskKBs = $s.DiskKBs; Queue = $s.Queue; HardFaults = $s.HardFaults; AvailMB = $s.AvailMB; P = $s.P })
    }
    $keys = $null
    [Threading.Monitor]::Enter($Sync.TraceProcs.SyncRoot)
    try { $keys = @($Sync.TraceProcs.Keys) } finally { [Threading.Monitor]::Exit($Sync.TraceProcs.SyncRoot) }
    $procs = @{}
    foreach ($k in $keys) {
        $m = $Sync.TraceProcs[$k]
        if (-not $m) { continue }
        $procs[$k] = [pscustomobject]@{
            Name = $m.Name; Parent = $m.Parent; Path = $m.Path; Session = $m.Session
            Created = $(if ($null -ne $m.Created) { [Math]::Round([double]$m.Created - $Origin, 3) } else { $null })
        }
    }
    $svc = @{}
    [Threading.Monitor]::Enter($Sync.TraceSvcMap.SyncRoot)
    try { foreach ($k in @($Sync.TraceSvcMap.Keys)) { $svc[$k] = $Sync.TraceSvcMap[$k] } } finally { [Threading.Monitor]::Exit($Sync.TraceSvcMap.SyncRoot) }
    @{ Samples = $samples.ToArray(); Procs = $procs; SvcMap = $svc }
}

# Runs headless as SYSTEM at boot (scheduled task) and records the activity of all processes
function Invoke-BootTraceRecorder {
    param([int]$Seconds = 180)
    $dir = Join-Path $env:ProgramData 'PerfInspector\BootTraces'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $logFile = Join-Path $dir 'recorder.log'
    try {
        Add-Content -Path $logFile -Value "$(Get-Date -Format s) recorder started ($Seconds s)"
        $boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        $sync = [hashtable]::Synchronized(@{
                TraceStop = $false; TraceReady = $false; Cancel = $false; TraceClock = $null
                TraceSamples = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList))
                TraceProcs = [hashtable]::Synchronized(@{}); TraceSvcMap = [hashtable]::Synchronized(@{})
            })
        Invoke-TraceSampler -Sync $sync -IntervalMs 1000 -MaxSeconds $Seconds
        $origin = $sync.TraceClock.Qpc - ($sync.TraceClock.Wall - $boot).TotalSeconds
        $data = ConvertTo-TraceData $sync $origin
        $out = [pscustomobject]@{
            Version = 1; Computer = $env:COMPUTERNAME; BootTime = $boot.ToString('o'); Recorded = (Get-Date).ToString('o')
            IntervalMs = 1000; Seconds = $Seconds; Cores = [Environment]::ProcessorCount; RecorderPid = $PID
            Samples = $data.Samples; Procs = $data.Procs; SvcMap = $data.SvcMap
        }
        $file = Join-Path $dir ('boottrace_{0:yyyyMMdd_HHmmss}.json' -f $boot)
        $out | ConvertTo-Json -Depth 6 -Compress | Set-Content -Path $file -Encoding UTF8
        Add-Content -Path $logFile -Value "$(Get-Date -Format s) saved $file ($(@($data.Samples).Count) samples)"
    } catch {
        Add-Content -Path $logFile -Value "$(Get-Date -Format s) ERROR $($_.Exception.Message)"
    } finally {
        try { Unregister-ScheduledTask -TaskName 'PerfInspector Boot Trace' -TaskPath '\PerfInspector\' -Confirm:$false -ErrorAction Stop } catch { }
    }
}
#endregion

if ($BootTraceRecord) { Invoke-BootTraceRecorder -Seconds $BootTraceSeconds; return }

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
    <Style x:Key="BarLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#9AA4B2"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Margin" Value="0,0,8,6"/>
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

      <!-- ======================= START TRACE ======================= -->
      <TabItem Style="{StaticResource NavTab}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE81C;"/><TextBlock Text="Start Trace"/></StackPanel>
        </TabItem.Header>
        <Grid Margin="6,6,18,12">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Style="{StaticResource Card}" Padding="14,10,14,4">
            <StackPanel>
              <WrapPanel>
                <TextBlock Style="{StaticResource BarLabel}" Text="Mode"/>
                <ComboBox x:Name="TrMode" Width="250" SelectedIndex="0">
                  <ComboBoxItem Content="Launch the app for me"/>
                  <ComboBoxItem Content="Wait until I start it myself"/>
                </ComboBox>
                <TextBlock Style="{StaticResource BarLabel}" Text="App"/>
                <TextBox x:Name="TrExe" Width="330" Margin="0,0,8,6"/>
                <Button x:Name="BtnTrBrowse" Content="Browse..."/>
                <TextBlock Style="{StaticResource BarLabel}" Text="Arguments"/>
                <TextBox x:Name="TrArgs" Width="140" Margin="0,0,8,6"/>
              </WrapPanel>
              <WrapPanel>
                <TextBlock Style="{StaticResource BarLabel}" Text="Process name(s)"/>
                <TextBox x:Name="TrWatch" Width="170" Margin="0,0,12,6" ToolTip="Process name of the app window, e.g. winword, chrome, Teams. Needed for 'Wait' mode, launchers, shortcuts and Store apps."/>
                <TextBlock Style="{StaticResource BarLabel}" Text="Timeout (s)"/>
                <TextBox x:Name="TrTimeout" Width="56" Text="60" Margin="0,0,12,6"/>
                <TextBlock Style="{StaticResource BarLabel}" Text="Keep recording after window (s)"/>
                <TextBox x:Name="TrPost" Width="50" Text="3" Margin="0,0,12,6"/>
                <TextBlock Style="{StaticResource BarLabel}" Text="Sample every"/>
                <ComboBox x:Name="TrInterval" Width="95" SelectedIndex="1">
                  <ComboBoxItem Content="250 ms"/><ComboBoxItem Content="500 ms"/><ComboBoxItem Content="1000 ms"/>
                </ComboBox>
                <Button x:Name="BtnTrStart" Style="{StaticResource Accent}">
                  <StackPanel Orientation="Horizontal"><TextBlock Style="{StaticResource Icon}" Text="&#xE768;" Margin="0,0,8,0" FontSize="12"/><TextBlock Text="Start trace"/></StackPanel>
                </Button>
                <Button x:Name="BtnTrStop" Content="Stop" IsEnabled="False"/>
              </WrapPanel>
              <TextBlock x:Name="TrHint" Style="{StaticResource Hint}" Margin="0,0,0,6"/>
            </StackPanel>
          </Border>
          <WrapPanel Grid.Row="1" Margin="0,10,0,2">
            <TextBlock Style="{StaticResource BarLabel}" Text="App"/>
            <ComboBox x:Name="TrAppFilter" Width="170"/>
            <TextBlock Style="{StaticResource BarLabel}" Text="Trace"/>
            <ComboBox x:Name="TrHistory" Width="310"/>
            <TextBlock Style="{StaticResource BarLabel}" Text="Focus"/>
            <ComboBox x:Name="TrFocus" Width="280"/>
            <Button x:Name="BtnTrSave" Content="Save trace..."/>
            <Button x:Name="BtnTrLoad" Content="Open trace..."/>
            <Button x:Name="BtnTrExport" Content="Export table..."/>
            <Button x:Name="BtnTrPng" Content="Save charts as PNG..."/>
          </WrapPanel>
          <Grid Grid.Row="2">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="350"/></Grid.ColumnDefinitions>
            <Grid Margin="0,0,12,0">
              <Grid.RowDefinitions><RowDefinition Height="262"/><RowDefinition Height="3*" MinHeight="160"/><RowDefinition Height="2*" MinHeight="100"/></Grid.RowDefinitions>
              <Border Style="{StaticResource Card}" Padding="6"><Canvas x:Name="TrOverview" ClipToBounds="True"/></Border>
              <Border Grid.Row="1" Style="{StaticResource Card}" Padding="6" Margin="0,10,0,0">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled"><Canvas x:Name="TrTimeline" ClipToBounds="True"/></ScrollViewer>
              </Border>
              <DataGrid x:Name="TrGrid" Grid.Row="2" Margin="0,10,0,0">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Role" Binding="{Binding Role}" Width="105"/>
                  <DataGridTextColumn Header="Process" Binding="{Binding Name}" Width="150"/>
                  <DataGridTextColumn Header="PID" Binding="{Binding PID}" Width="65" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTemplateColumn Header="Category" Width="175" SortMemberPath="Category">
                    <DataGridTemplateColumn.CellTemplate>
                      <DataTemplate><TextBlock Text="{Binding Category}" Foreground="{Binding Color}" FontWeight="SemiBold" VerticalAlignment="Center"/></DataTemplate>
                    </DataGridTemplateColumn.CellTemplate>
                  </DataGridTemplateColumn>
                  <DataGridTextColumn Header="Started (s)" Binding="{Binding StartedSec}" Width="90" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTextColumn Header="Avg CPU %" Binding="{Binding AvgCpu, StringFormat=N1}" Width="90" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTextColumn Header="CPU time (s)" Binding="{Binding CpuSec, StringFormat=N2}" Width="100" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTextColumn Header="I/O (MB)" Binding="{Binding IoMB, StringFormat=N1}" Width="85" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTextColumn Header="Peak RAM (MB)" Binding="{Binding PeakRamMB, StringFormat=N0}" Width="115" ElementStyle="{StaticResource NumCell}"/>
                  <DataGridTextColumn Header="Services" Binding="{Binding Services}" Width="200"/>
                  <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="*" MinWidth="200"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
            <Border Grid.Column="1" Style="{StaticResource Card}" Padding="14">
              <DockPanel>
                <TextBlock DockPanel.Dock="Top" Style="{StaticResource SectionTitle}" Text="What slowed the start down"/>
                <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="TrFindings"/></ScrollViewer>
              </DockPanel>
            </Border>
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
            <TabItem Header="Boot timeline (until desktop)" Style="{StaticResource SubTab}">
              <Grid>
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="3*" MinHeight="180"/><RowDefinition Height="2*" MinHeight="100"/></Grid.RowDefinitions>
                <StackPanel>
                  <WrapPanel>
                    <TextBlock Style="{StaticResource BarLabel}" Text="Activity recording"/>
                    <ComboBox x:Name="BtRecording" Width="300"/>
                    <Button x:Name="BtnBtRecord" Style="{StaticResource Accent}" Content="Record next boot..."/>
                    <Button x:Name="BtnBtCancel" Content="Cancel scheduled recording" IsEnabled="False"/>
                    <CheckBox x:Name="BtOnlyDesktop" Content="Only until desktop" IsChecked="True"/>
                    <TextBlock Style="{StaticResource BarLabel}" Text="Filter"/>
                    <TextBox x:Name="BtFilter" Width="180" Margin="0,0,8,6" ToolTip="Show only services / programs whose name contains this text"/>
                  </WrapPanel>
                  <TextBlock x:Name="BtSummary" TextWrapping="Wrap" FontSize="12" Foreground="#C9D1DD" Margin="2,0,0,8"/>
                </StackPanel>
                <Border Grid.Row="1" Style="{StaticResource Card}" Padding="6">
                  <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled"><Canvas x:Name="BtTimeline" ClipToBounds="True"/></ScrollViewer>
                </Border>
                <DataGrid x:Name="BtGrid" Grid.Row="2" Margin="0,10,0,0">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Time after boot (s)" Binding="{Binding T, StringFormat=N2}" Width="140" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="140"/>
                    <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="260"/>
                    <DataGridTextColumn Header="Duration (s)" Binding="{Binding DurationSec, StringFormat=N2}" Width="100" ElementStyle="{StaticResource NumCell}"/>
                    <DataGridTextColumn Header="Before desktop" Binding="{Binding BeforeDesktop}" Width="110"/>
                    <DataGridTextColumn Header="Details" Binding="{Binding Details}" Width="*" MinWidth="200"/>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
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
foreach ($fn in 'Get-PerfSnapshot', 'Get-BootAnalysis', 'Get-ExePathFromCommand', 'Invoke-AppStartTest', 'Get-QpcSec', 'Get-TraceKeys', 'Get-TraceRawSample',
    'Convert-TraceDelta', 'Add-TraceProcMeta', 'Get-TraceServiceMap', 'Invoke-TraceSampler', 'Invoke-TraceLaunch', 'ConvertTo-TraceData') {
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
    if ($script:TraceRunning) { try { Update-TraceLive } catch { } }
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
    $cv.Width = $W
    if ($H -gt 0) { $cv.Height = $H }
    $cv.Background = Get-Brush '#161A22'
    $null = & $Renderer $cv $W $H
    if ($H -le 0) { $H = $cv.Height; if (-not ($H -gt 0)) { $H = 400; $cv.Height = 400 } }
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
    Update-BootRecordingList
    Update-BootTimeline
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

        Add-ExtraReportSections $sb
        [IO.File]::WriteAllText($dlg.FileName, (New-HtmlPage "PerfInspector report - $env:COMPUTERNAME" $sb.ToString()), [Text.Encoding]::UTF8)
        Set-Status "Report saved to $($dlg.FileName)"
        $script:Window.Cursor = $null
        if (Confirm-Action "Report saved:`n$($dlg.FileName)`n`nOpen it now?" 'Report created') { Start-Process -FilePath $dlg.FileName }
    } catch {
        Show-ErrorMessage "Report could not be created: $($_.Exception.Message)"
    } finally { $script:Window.Cursor = $null }
}
#endregion

#region ---------------------------------------------------------------- Start trace + boot timeline (UI side)
$script:Traces           = New-Object Collections.Generic.List[object]
$script:CurrentTrace     = $null
$script:TraceModel       = $null
$script:TraceRunning     = $false
$script:TraceDone        = 0
$script:TraceRequest     = $null
$script:TraceLastLive    = [DateTime]::MinValue
$script:TraceFocusKeys   = @('all')
$script:TraceHistList    = @()
$script:SuppressCombo    = $false
$script:BootRecFiles     = @()
$script:BootRecording    = $null
$script:BootRecPath      = $null
$script:BootRecAutoDone  = $false
$script:BootTimelineSpec = $null
$script:BootTimelineFindings = @()
$script:BootTimelineRows = @()
$script:TotalMemMB = 0
try { $script:TotalMemMB = [double](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB } catch { }

# ---------------------------------------------------------------- process categories
$script:TraceCatRules = @(
    @{ Cat = 'Security scan'; Color = '#FF6B6B'
        Names = @('msmpeng', 'nissrv', 'mssense', 'mpdefendercoreservice', 'securityhealthservice', 'smartscreen', 'mpcmdrun', 'senseir', 'sensece', 'sensendr', 'sensetvm',
            'avp', 'avpui', 'ekrn', 'egui', 'bdservicehost', 'bdagent', 'vsserv', 'epsecurityservice', 'mcshield', 'mfemms', 'mfevtps', 'mfefire', 'masvc', 'mcapexe',
            'avgsvc', 'avgui', 'avastsvc', 'avastui', 'afwserv', 'savservice', 'sophosfilescanner', 'sophosfs', 'sophoshealth', 'sedservice', 'sspservice',
            'csfalconservice', 'csfalconcontainer', 'sentinelagent', 'sentinelservicehost', 'sentinelstaticengine', 'cb', 'repmgr', 'cyserver', 'cylancesvc',
            'ntrtscan', 'tmbmsrv', 'pccntmon', 'coreserviceshell', 'ds_agent', 'wrsa', 'sbamsvc', 'psanhost', 'fsorsp', 'fshoster', 'fssm32', 'xagt',
            'elastic-endpoint', 'ccsvchst', 'nortonsecurity', 'mbamservice', 'mbam', 'hmpalert', 'zatray', 'kesl', 'klnagent')
        Svc = @('WinDefend', 'WdNisSvc', 'Sense', 'SecurityHealthService', 'MDCoreSvc', 'webthreatdefsvc') }
    @{ Cat = 'Search indexing'; Color = '#F5A524'; Names = @('searchindexer', 'searchprotocolhost', 'searchfilterhost'); Svc = @('WSearch') }
    @{ Cat = 'Windows Update'; Color = '#B08CFF'; Names = @('tiworker', 'trustedinstaller', 'wuauclt', 'mousocoreworker', 'usoclient', 'sihclient', 'musnotification', 'musnotificationux', 'setuphost', 'dismhost')
        Svc = @('wuauserv', 'UsoSvc', 'BITS', 'DoSvc', 'WaaSMedicSvc', 'TrustedInstaller') }
    @{ Cat = 'Telemetry / diagnostics'; Color = '#8FA3BF'; Names = @('compattelrunner', 'devicecensus', 'wermgr', 'werfault', 'aggregatorhost'); Svc = @('DiagTrack', 'WerSvc', 'DPS', 'PcaSvc') }
    @{ Cat = 'Prefetch (SysMain)'; Color = '#5BC0EB'; Names = @(); Svc = @('SysMain') }
    @{ Cat = 'Cloud sync'; Color = '#2EC4B6'; Names = @('onedrive', 'filecoauth', 'dropbox', 'googledrivefs', 'icloudservices', 'icloud', 'boxsync', 'nextcloud', 'megasync'); Svc = @() }
    @{ Cat = 'Updater'; Color = '#E07BE0'; Names = @('googleupdate', 'msedgeupdate', 'microsoftedgeupdate', 'adobearm', 'armsvc', 'adobeupdateservice', 'squirrel', 'officec2rclient', 'jusched')
        Svc = @('edgeupdate', 'gupdate', 'AdobeARMservice') }
)
$script:TraceSystemNames = @('system', 'registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'svchost', 'dwm', 'explorer', 'fontdrvhost',
    'sihost', 'taskhostw', 'runtimebroker', 'ctfmon', 'audiodg', 'memory compression', 'memcompression', 'conhost', 'dllhost', 'searchhost', 'searchapp',
    'startmenuexperiencehost', 'shellexperiencehost', 'textinputhost', 'spoolsv', 'wudfhost', 'backgroundtaskhost', 'applicationframehost', 'secure system',
    'userinit', 'logonui', 'smartscreen', 'widgets', 'phoneexperiencehost', 'lockapp', 'useroobebroker', 'systemsettings')

function Get-TraceCategory([string]$Name, [string]$Services, [int]$ProcId, [int]$OwnPid = $PID) {
    $n = $Name.ToLower()
    if (($OwnPid -gt 0 -and $ProcId -eq $OwnPid) -or $n -eq 'wmiprvse') { return @('Measurement (PerfInspector)', '#3E4A5E') }
    $svcs = @()
    if ($Services) { $svcs = @($Services -split ',\s*' | ForEach-Object { $_ -replace '_[0-9a-fA-F]{4,}$', '' }) }
    foreach ($r in $script:TraceCatRules) {
        if ($r.Names -contains $n) { return @($r.Cat, $r.Color) }
        foreach ($sv in $svcs) { if ($r.Svc -contains $sv) { return @($r.Cat, $r.Color) } }
    }
    if ($n -like '*update*') { return @('Updater', '#E07BE0') }
    if ($script:TraceSystemNames -contains $n) { return @('Windows system', '#6B7385') }
    @('Other program', '#2ECC71')
}

function Format-Sec([double]$t) { if ([Math]::Abs($t) -lt 10) { '{0:N2} s' -f $t } else { '{0:N1} s' -f $t } }
function Format-Ms([double]$t) { '{0:N0} ms' -f ($t * 1000) }
function Get-BreakdownColor([string]$k) {
    switch ($k) {
        'Launching (Windows)'              { '#5A6275' }
        'Security scanning'                { '#FF6B6B' }
        'Busy CPU (other processes)'       { '#F5A524' }
        'App working (CPU)'                { '#4F8CFF' }
        'Reading from disk'                { '#B08CFF' }
        'Waiting (network / locks / idle)' { '#2EC4B6' }
        default                            { '#3A4356' }
    }
}

# ---------------------------------------------------------------- analysis of one app start trace
function Get-TraceModel {
    param($Trace, [double]$WindowStart = 0)
    $cores = [int]$Trace.Cores
    if ($cores -lt 1) { $cores = [Environment]::ProcessorCount }
    $mk = $Trace.Marks
    $samples = @($Trace.Samples)
    $post = [double]$mk.PostSec
    $tEnd = 0.0
    if ($null -ne $mk.Window) { $tEnd = [double]$mk.Window }
    elseif ($null -ne $mk.End) { $tEnd = [double]$mk.End }
    elseif ($samples.Count) { $tEnd = [double]$samples[-1].T }
    if ($tEnd -lt 0.05) { $tEnd = 0.05 }
    $procs = $Trace.Procs; $svcMap = $Trace.SvcMap; $own = [int]$Trace.OwnPid
    $keys = Get-TraceKeys $procs

    # the app and every process it started
    $tree = @{}
    foreach ($r in @($mk.RootPid, $mk.WindowPid)) { if ($r) { $tree[[string]$r] = $true } }
    $watch = @($Trace.WatchNames)
    foreach ($k in $keys) {
        $pm = $procs.$k
        if ($null -ne $pm.Created -and [double]$pm.Created -ge -1 -and $watch -contains [string]$pm.Name) { $tree[$k] = $true }
    }
    do {
        $added = $false
        foreach ($k in $keys) {
            if ($tree.ContainsKey($k)) { continue }
            $pm = $procs.$k
            if ($null -ne $pm.Created -and [double]$pm.Created -ge -0.5 -and $tree.ContainsKey([string]$pm.Parent)) { $tree[$k] = $true; $added = $true }
        }
    } while ($added)

    $catOf = @{}
    $st = @{}
    $bk = [ordered]@{ 'Launching (Windows)' = 0.0; 'Security scanning' = 0.0; 'Busy CPU (other processes)' = 0.0; 'App working (CPU)' = 0.0; 'Reading from disk' = 0.0; 'Waiting (network / locks / idle)' = 0.0 }
    $half = 50.0 / $cores
    $pStart = 0.0
    if ($null -ne $mk.Process) { $pStart = [Math]::Max(0, [Math]::Min([double]$mk.Process, $tEnd)) }
    $bk['Launching (Windows)'] = $pStart
    $covered = 0.0; $minAvail = [double]::MaxValue; $peakQueue = 0.0; $peakHF = 0.0; $sysCpu = 0.0; $span = 0.0
    $wStart = $WindowStart
    foreach ($s in $samples) {
        $a = [Math]::Max([double]$s.T0, $wStart); $b = [Math]::Min([double]$s.T, $tEnd); $ov = $b - $a
        if ($ov -le 0) { continue }
        $treeCpu = 0.0; $treeIo = 0.0; $secCpu = 0.0; $secIo = 0.0; $ownCpu = 0.0
        foreach ($k in (Get-TraceKeys $s.P)) {
            $v = $s.P.$k
            if (-not $st.ContainsKey($k)) { $st[$k] = @{ CpuSec = 0.0; CpuPct = 0.0; IoMB = 0.0; PeakCpu = 0.0; PeakWs = 0.0 } }
            $x = $st[$k]; $cpu = [double]$v[0]; $io = [double]$v[1]
            $x.CpuSec += $cpu / 100 * $cores * $ov; $x.CpuPct += $cpu * $ov; $x.IoMB += $io * $ov / 1024
            if ($cpu -gt $x.PeakCpu) { $x.PeakCpu = $cpu }
            if ([double]$v[2] -gt $x.PeakWs) { $x.PeakWs = [double]$v[2] }
            if (-not $catOf.ContainsKey($k)) { $pm = $procs.$k; $catOf[$k] = Get-TraceCategory $(if ($pm) { [string]$pm.Name } else { '' }) ([string]$svcMap.$k) ([int]$k) $own }
            if ($tree.ContainsKey($k)) { $treeCpu += $cpu; $treeIo += $io }
            elseif ($catOf[$k][0] -eq 'Security scan') { $secCpu += $cpu; $secIo += $io }
            elseif ($catOf[$k][0] -like 'Measurement*') { $ownCpu += $cpu }
        }
        $a2 = [Math]::Max($a, $pStart); $ov2 = $b - $a2
        if ($ov2 -gt 0) {
            $others = [double]$s.Cpu - $treeCpu - $ownCpu
            $c = if ($secCpu -ge $half -or $secIo -ge 2048) { 'Security scanning' }
            elseif ([double]$s.Cpu -ge 85 -and $others -gt $treeCpu) { 'Busy CPU (other processes)' }
            elseif ($treeCpu -ge $half) { 'App working (CPU)' }
            elseif ([double]$s.Queue -ge 1.5 -or [double]$s.HardFaults -ge 300 -or $treeIo -ge 1024) { 'Reading from disk' }
            else { 'Waiting (network / locks / idle)' }
            $bk[$c] += $ov2; $covered += $ov2
        }
        if ([double]$s.AvailMB -gt 0 -and [double]$s.AvailMB -lt $minAvail) { $minAvail = [double]$s.AvailMB }
        if ([double]$s.Queue -gt $peakQueue) { $peakQueue = [double]$s.Queue }
        if ([double]$s.HardFaults -gt $peakHF) { $peakHF = [double]$s.HardFaults }
        $sysCpu += [double]$s.Cpu * $ov; $span += $ov
    }
    $notMeasured = ($tEnd - $pStart) - $covered
    if ($wStart -ge 0 -and $notMeasured -gt 0.02) { $bk['Not measured'] = $notMeasured }
    $winLen = [Math]::Max(0.05, $tEnd - $wStart)

    $rows = New-Object Collections.Generic.List[object]
    $allKeys = @($st.Keys) + @($tree.Keys | Where-Object { -not $st.ContainsKey($_) })
    foreach ($k in $allKeys) {
        $pm = $procs.$k
        $x = $st[$k]
        if (-not $x) { $x = @{ CpuSec = 0.0; CpuPct = 0.0; IoMB = 0.0; PeakCpu = 0.0; PeakWs = 0.0 } }
        $inTree = $tree.ContainsKey($k)
        if (-not $inTree -and $x.CpuSec -lt 0.01 -and $x.IoMB -lt 0.1) { continue }
        $name = if ($pm) { [string]$pm.Name } else { "PID $k" }
        if ($inTree) { $cat = 'This app'; $col = '#4F8CFF' }
        else {
            if (-not $catOf.ContainsKey($k)) { $catOf[$k] = Get-TraceCategory $name ([string]$svcMap.$k) ([int]$k) $own }
            $cat = $catOf[$k][0]; $col = $catOf[$k][1]
        }
        $role = if ($k -eq [string]$mk.RootPid) { 'App' } elseif ($inTree) { 'Child process' } else { 'Background' }
        $started = $null
        if ($pm -and $null -ne $pm.Created -and [double]$pm.Created -ge -120) { $started = [Math]::Round([double]$pm.Created, 2) }
        $rows.Add([pscustomobject]@{
                Role = $role; Name = $name; PID = [int]$k; Category = $cat; Color = $col; StartedSec = $started
                AvgCpu = [Math]::Round($x.CpuPct / $winLen, 1); CpuSec = [Math]::Round($x.CpuSec, 2); IoMB = [Math]::Round($x.IoMB, 1)
                PeakCpu = $x.PeakCpu; PeakRamMB = $x.PeakWs; Services = [string]$svcMap.$k; Path = $(if ($pm) { [string]$pm.Path } else { '' })
                Score = $x.CpuSec + $x.IoMB / 50
            })
    }
    $chain = @($rows | Where-Object { $_.Role -ne 'Background' } | Sort-Object @{ Expression = { if ($_.Role -eq 'App') { 0 } else { 1 } } }, @{ Expression = { if ($null -ne $_.StartedSec) { $_.StartedSec } else { 9e9 } } })
    $bg = @($rows | Where-Object { $_.Role -eq 'Background' } | Sort-Object Score -Descending)
    $inter = @($bg | Where-Object { $_.Category -notlike 'Measurement*' -and $_.Score -ge 0.05 } | Select-Object -First 8)

    $marks = New-Object Collections.Generic.List[object]
    $marks.Add(@{ Name = $(if ($Trace.Mode -eq 'Watch') { 'Process started' } else { 'Launch' }); T = 0.0; Color = '#4F8CFF' })
    if ($Trace.Mode -ne 'Watch' -and $null -ne $mk.Process) { $marks.Add(@{ Name = 'Process created'; T = [double]$mk.Process; Color = '#7C5CFF' }) }
    if ($null -ne $mk.InputIdle) { $marks.Add(@{ Name = 'Ready for input'; T = [double]$mk.InputIdle; Color = '#2EC4B6' }) }
    if ($null -ne $mk.Window) { $marks.Add(@{ Name = 'Window visible'; T = [double]$mk.Window; Color = '#2ECC71' }) }
    elseif ($mk.Timeout) { $marks.Add(@{ Name = 'No window (timeout)'; T = $tEnd; Color = '#FF6B6B' }) }

    $model = @{
        TEnd = $tEnd; Rows = $rows.ToArray(); Chain = $chain; Background = $bg; Interferers = $inter; Breakdown = $bk; Marks = $marks.ToArray()
        Cores = $cores; MinAvailMB = $minAvail; PeakQueue = $peakQueue; PeakHF = $peakHF; AvgSysCpu = $(if ($span -gt 0) { $sysCpu / $span } else { 0 })
        Findings = @()
    }
    $model.Findings = Get-TraceFindings $Trace $model
    $model
}

function New-Finding([string]$Sev, [string]$Title, [string]$Text) { [pscustomobject]@{ Sev = $Sev; Title = $Title; Text = $Text } }

function Get-TraceFindings($Trace, $M) {
    $f = New-Object Collections.Generic.List[object]
    $mk = $Trace.Marks
    $bk = $M.Breakdown
    $p0 = if ($null -ne $mk.Process) { [double]$mk.Process } else { 0 }
    $span = [Math]::Max(0.01, $M.TEnd - $p0)
    $summary = $null
    if ($null -ne $mk.Window) {
        $parts = @()
        if ($Trace.Mode -ne 'Watch' -and $null -ne $mk.Process) { $parts += 'process created after ' + (Format-Ms ([double]$mk.Process)) }
        if ($null -ne $mk.InputIdle) { $parts += 'ready for input after ' + (Format-Sec ([double]$mk.InputIdle)) }
        $top = @($bk.GetEnumerator() | Where-Object { $_.Key -notin 'Launching (Windows)', 'Not measured' -and $_.Value -gt 0 } | Sort-Object Value -Descending) | Select-Object -First 1
        if ($top) { $parts += ('most of the time: {0} ({1:N0}%)' -f $top.Key, ($top.Value / $span * 100)) }
        $sev = if ($M.TEnd -ge 10) { 'high' } elseif ($M.TEnd -ge 4) { 'medium' } else { 'ok' }
        $summary = New-Finding $sev ('Window visible after {0}' -f (Format-Sec $M.TEnd)) ((($parts -join '; ') + '.'))
    } elseif ($mk.Timeout) {
        $summary = New-Finding 'high' 'No main window within the timeout' ('The app did not show a window within {0}. It may start in the tray/background, show its window from a different process (enter that process name under "Process name(s)") or hang during the start.' -f (Format-Sec $M.TEnd))
    }
    if ($mk.Error -and $mk.Error -ne 'Cancelled') { $f.Add((New-Finding 'high' 'The trace did not complete' ([string]$mk.Error))) }

    $bgRows = @($M.Background | Where-Object { $_.Category -notlike 'Measurement*' })
    # antivirus / security scanning
    $secAll = @($bgRows | Where-Object { $_.Category -eq 'Security scan' })
    $secCpu = [double]($secAll | Measure-Object CpuSec -Sum).Sum; $secIo = [double]($secAll | Measure-Object IoMB -Sum).Sum
    $secT = [double]$bk['Security scanning']
    if ($secT -ge 0.2 -or $secCpu -ge 0.3 -or $secIo -ge 20) {
        $names = (@($secAll | Sort-Object CpuSec -Descending | Select-Object -First 3) | ForEach-Object { $_.Name }) -join ', '
        $sev = if ($secT -ge 1 -or ($secT / $span) -ge 0.25) { 'high' } else { 'medium' }
        $f.Add((New-Finding $sev 'Antivirus / security scanning slowed the start' ("{0} used {1:N1} CPU-seconds and {2:N0} MB disk I/O while the app started (security scanning was the main activity for {3}). Real-time protection checks every file the app loads - strongest on the first start after a reboot or an app update. If you trust the app, an antivirus exclusion for its program folder can speed up the start; only do this for software you trust." -f $names, $secCpu, $secIo, (Format-Sec $secT))))
    }
    # CPU contention
    $busy = [double]$bk['Busy CPU (other processes)']
    if ($busy -ge 0.3 -and ($busy / $span) -ge 0.15) {
        $names = (@($bgRows | Where-Object { $_.Category -ne 'Security scan' } | Sort-Object CpuSec -Descending | Select-Object -First 3) | ForEach-Object { '{0} ({1:N1} CPU-s)' -f $_.Name, $_.CpuSec }) -join ', '
        $sev = if (($busy / $span) -ge 0.35) { 'high' } else { 'medium' }
        $f.Add((New-Finding $sev 'Other programs kept the CPU busy' ("For {0} the processor was more than 85% busy with other work: {1}. Close or pause these programs, or check them in the Live Monitor." -f (Format-Sec $busy), $names)))
    }
    # disk
    $disk = [double]$bk['Reading from disk']
    if ($disk -ge 0.3 -and ($disk / $span) -ge 0.2) {
        $appIo = [double](@($M.Chain) | Measure-Object IoMB -Sum).Sum
        $others = (@($bgRows | Where-Object { $_.IoMB -ge 5 } | Sort-Object IoMB -Descending | Select-Object -First 3) | ForEach-Object { '{0} ({1:N0} MB)' -f $_.Name, $_.IoMB }) -join ', '
        $txt = "The start waited {0} for the disk. The app read/wrote {1:N0} MB itself (disk queue up to {2:N1}, up to {3:N0} hard page faults/s). This is typical for a cold start (first start after boot) - trace again to compare with a warm start." -f (Format-Sec $disk), $appIo, $M.PeakQueue, $M.PeakHF
        if ($others) { $txt += " Other processes using the disk at the same time: $others." }
        $f.Add((New-Finding $(if (($disk / $span) -ge 0.4) { 'high' } else { 'medium' }) 'The disk was the bottleneck' $txt))
    }
    # waiting
    $wait = [double]$bk['Waiting (network / locks / idle)']
    if ($wait -ge 0.5 -and ($wait / $span) -ge 0.25) {
        $f.Add((New-Finding $(if ($wait -ge 3) { 'high' } else { 'medium' }) 'The app was mostly waiting' ("For {0} neither the app nor the disk was busy - the app was waiting for something: usually network requests (sign-in, licence check, update check, cloud content), a slow or unreachable network/mapped drive, a printer or a locked file. Trace once without network/VPN to confirm." -f (Format-Sec $wait))))
    }
    # the app's own work
    $work = [double]$bk['App working (CPU)']
    if ($work -ge 0.5 -and ($work / $span) -ge 0.4) {
        $cpuSec = [double](@($M.Chain) | Measure-Object CpuSec -Sum).Sum
        $f.Add((New-Finding 'info' "The app's own work took most of the time" ("The app's processes used {0:N1} CPU-seconds ({1:N0}% of the start). Add-ins, plugins, extensions, a large profile or restoring many documents/tabs make this phase longer. Start once with add-ins disabled (e.g. Office apps with /safe) to compare." -f $cpuSec, ($work / $span * 100))))
    }
    # start chain
    $kids = @($M.Chain | Where-Object { $_.Role -eq 'Child process' })
    $upd = @($kids | Where-Object { $_.Name -match 'update|updater|squirrel|setup|install' })
    if ($upd.Count) {
        $f.Add((New-Finding 'medium' 'An updater ran during the start' ("The app started {0} while starting. Update checks at start cost time; many apps let you turn off automatic update checks at start." -f (($upd | ForEach-Object { $_.Name }) -join ', '))))
    }
    if ($kids.Count) {
        $list = ($kids | Select-Object -First 8 | ForEach-Object { if ($null -ne $_.StartedSec) { '{0} (+{1})' -f $_.Name, (Format-Sec $_.StartedSec) } else { $_.Name } }) -join ', '
        $f.Add((New-Finding 'info' 'Start chain' ("The app started {0} more process(es): {1}." -f $kids.Count, $list)))
    }
    # services started on demand
    $ss = @($Trace.ServiceStarts | Where-Object { [double]$_.T -ge -0.5 -and [double]$_.T -le $M.TEnd + 0.5 })
    if ($ss.Count) {
        $f.Add((New-Finding 'medium' 'Windows started services during the start' ("These services changed state while the app started: {0}. A service that has to start first delays the app; if the app always needs it, 'Automatic (Delayed)' for that service can help." -f (($ss | ForEach-Object { '{0} (+{1})' -f $_.Name, (Format-Sec ([double]$_.T)) }) -join ', '))))
    }
    # background maintenance
    $mt = @($bgRows | Where-Object { $_.Category -in 'Search indexing', 'Windows Update', 'Telemetry / diagnostics', 'Prefetch (SysMain)', 'Cloud sync', 'Updater' -and ($_.CpuSec -ge 0.2 -or $_.IoMB -ge 10) })
    if ($mt.Count) {
        $f.Add((New-Finding 'medium' 'Background maintenance was running' ("{0}. These tasks compete for CPU and disk; they usually calm down some minutes after boot or after updates have finished." -f (($mt | ForEach-Object { '{0} ({1}, {2:N1} CPU-s, {3:N0} MB)' -f $_.Name, $_.Category, $_.CpuSec, $_.IoMB }) -join '; '))))
    }
    # memory
    $total = [double]$Trace.TotalMemMB
    if ($M.MinAvailMB -lt [double]::MaxValue -and ($M.MinAvailMB -lt 500 -or ($total -gt 0 -and $M.MinAvailMB / $total -lt 0.08))) {
        $f.Add((New-Finding 'high' 'Low free memory' ("Only {0:N0} MB of RAM were free during the start. Windows has to page memory to disk, which slows every start. Close programs or add RAM." -f $M.MinAvailMB)))
    }
    if ($null -ne $mk.Window -and $M.TEnd -lt ([double]$Trace.IntervalMs / 1000) * 3) {
        $f.Add((New-Finding 'info' 'Very short start' ("The start took less than three sampling intervals ({0} ms). Use 250 ms sampling for more detail." -f $Trace.IntervalMs)))
    }
    $hasIssue = @($f | Where-Object { $_.Sev -in 'high', 'medium' }).Count -gt 0
    if (-not $hasIssue -and $null -ne $mk.Window) { $f.Add((New-Finding 'ok' 'No significant interference found' 'No antivirus, CPU, disk, memory or waiting bottleneck stood out during this start.')) }
    $order = @{ high = 0; medium = 1; info = 2; ok = 3 }
    $sorted = @($f | Sort-Object @{ Expression = { $order[$_.Sev] } })
    if ($summary) { $sorted = @($summary) + $sorted }
    $sorted
}

# ---------------------------------------------------------------- swimlane chart (shared by start trace and boot timeline)
function Get-NiceStep([double]$Range, [int]$Target = 8) {
    $raw = $Range / [Math]::Max(1, $Target)
    foreach ($s in 0.1, 0.2, 0.25, 0.5, 1, 2, 5, 10, 15, 20, 30, 60, 120, 300) { if ($s -ge $raw) { return $s } }
    600
}
function Get-SwimRowHeight($r) { switch ($r.Kind) { 'header' { 24 } 'area' { 36 } 'bars' { 24 } 'ticks' { 28 } default { 24 } } }

function Get-LanePoints {
    param($Samples, [string]$Key, [string]$Prop, [double]$Shift, [double]$XMin, [double]$XMax)
    $pts = New-Object Collections.Generic.List[object]
    $peak = 0.0
    foreach ($s in $Samples) {
        $t0 = [double]$s.T0 + $Shift; $t1 = [double]$s.T + $Shift
        if ($t1 -lt $XMin -or $t0 -gt $XMax) { continue }
        $v = 0.0
        if ($Prop) { $v = [double]$s.$Prop }
        elseif ($Key) { $e = $s.P.$Key; if ($null -ne $e) { $v = [double]$e[0] } }
        if ($v -gt $peak) { $peak = $v }
        $pts.Add(@($t0, $t1, $v))
    }
    @{ Points = $pts.ToArray(); Peak = $peak }
}

function Draw-Swimlanes {
    param($C, $Spec, [double]$W = 0, [double]$H = 0)
    $C.Children.Clear()
    if ($W -le 0) { $W = $C.ActualWidth }
    if ($W -lt 240 -or -not $Spec) { return }
    $rows = @($Spec.Rows)
    $top = 48; $bottom = 26
    $need = $top + $bottom
    foreach ($r in $rows) { $need += Get-SwimRowHeight $r }
    if ($Spec.Empty) { $need = [Math]::Max($need, 160) }
    if ($H -le 0) { $H = $need; $C.Height = $need }
    $labelW = [Math]::Min(270, [Math]::Max(170, $W * 0.24)); $R = 18
    $pw = $W - $labelW - $R
    $xmin = [double]$Spec.XMin; $xmax = [double]$Spec.XMax
    if ($xmax -le $xmin) { $xmax = $xmin + 1 }
    $k = $pw / ($xmax - $xmin)
    Add-CText $C $Spec.Title 8 4 13 '#E6EAF0' -Bold -MaxW ($W - 16)
    if ($Spec.Empty) { Add-CText $C $Spec.Empty 0 ($H / 2 - 10) 12 '#6B7385' -MaxW $W -Align Center; return }
    $plotBottom = $H - $bottom
    if ($Spec.Shade) {
        $sa = [Math]::Max($xmin, [double]$Spec.Shade[0]); $sb = [Math]::Min($xmax, [double]$Spec.Shade[1])
        if ($sb -gt $sa) { Add-CRect $C ($labelW + ($sa - $xmin) * $k) $top (($sb - $sa) * $k) ($plotBottom - $top) '#172033' $Spec.ShadeTip 0 }
    }
    $step = Get-NiceStep ($xmax - $xmin) ([int][Math]::Max(3, $pw / 90))
    $g = [Math]::Ceiling($xmin / $step) * $step
    while ($g -le $xmax + 1e-9) {
        $x = $labelW + ($g - $xmin) * $k
        Add-CLine $C $x $top $x $plotBottom '#202736' 1
        $lbl = if ($step -lt 1) { '{0:0.##} s' -f $g } else { '{0:0} s' -f $g }
        if ($g -gt 1e-9) { $lbl = '+' + $lbl }
        Add-CText $C $lbl ($x - 30) ($plotBottom + 5) 10 '#8A94A6' -MaxW 60 -Align Center
        $g += $step
    }
    $y = $top
    foreach ($r in $rows) {
        $h = Get-SwimRowHeight $r
        switch ($r.Kind) {
            'header' {
                $hc = if ($r.Color) { $r.Color } else { '#9AA4B2' }
                Add-CText $C $r.Label 8 ($y + 6) 11 $hc -Bold -MaxW ($W - 16)
                Add-CLine $C 8 ($y + $h - 1) ($W - $R) ($y + $h - 1) '#262D3A' 1
            }
            'area' {
                $col = [string]$r.Color
                Add-CRect $C 10 ($y + 7) 8 8 $col $null 4
                Add-CText $C $r.Label 24 ($y + 2) 11.5 '#E6EAF0' -MaxW ($labelW - 30)
                if ($r.Sub) { Add-CText $C $r.Sub 24 ($y + 18) 9.5 '#8A94A6' -MaxW ($labelW - 30) }
                $base = $y + $h - 3; $ph = $h - 7
                Add-CLine $C $labelW $base ($labelW + $pw) $base '#232A36' 1
                $pts = @($r.Points)
                if ($pts.Count) {
                    $scale = [Math]::Max(1e-6, [double]$r.Scale)
                    $pc = New-Object Windows.Media.PointCollection
                    $firstX = $null; $lastX = $null
                    foreach ($p in $pts) {
                        $t0 = [Math]::Max($xmin, [double]$p[0]); $t1 = [Math]::Min($xmax, [double]$p[1])
                        if ($t1 -le $t0) { continue }
                        $yy = $base - $ph * [Math]::Min(1, [double]$p[2] / $scale)
                        $x0 = $labelW + ($t0 - $xmin) * $k; $x1 = $labelW + ($t1 - $xmin) * $k
                        if ($null -eq $firstX) { $firstX = $x0; $pc.Add([Windows.Point]::new($x0, $base)) }
                        $pc.Add([Windows.Point]::new($x0, $yy)); $pc.Add([Windows.Point]::new($x1, $yy))
                        $lastX = $x1
                    }
                    if ($null -ne $lastX) {
                        $pc.Add([Windows.Point]::new($lastX, $base))
                        $pg = New-Object Windows.Shapes.Polygon
                        $pg.Points = $pc
                        $pg.Fill = Get-Brush ('#99' + $col.Substring(1))
                        $pg.Stroke = Get-Brush $col
                        $pg.StrokeThickness = 1
                        if ($r.Tip) { $pg.ToolTip = $r.Tip }
                        [void]$C.Children.Add($pg)
                    }
                }
                if ($r.Tip) { Add-CRect $C 0 $y $labelW $h '#01000000' $r.Tip 0 }
            }
            'bars' {
                $col = if ($r.Color) { [string]$r.Color } else { '#4F8CFF' }
                Add-CRect $C 10 ($y + 8) 8 8 $col $null 4
                Add-CText $C $r.Label 24 ($y + 4) 11 '#C9D1DD' -MaxW ($labelW - 30)
                foreach ($bar in @($r.Bars)) {
                    $t0 = [Math]::Max($xmin, [double]$bar.Start); $t1 = [Math]::Min($xmax, [double]$bar.End)
                    if ($t1 -le $t0) { continue }
                    $bx = $labelW + ($t0 - $xmin) * $k; $bw = [Math]::Max(2, ($t1 - $t0) * $k)
                    Add-CRect $C $bx ($y + 4) $bw ($h - 8) $bar.Color $bar.Tip 3
                    if ($bar.Text -and $bw -gt 50) { Add-CText $C $bar.Text ($bx + 4) ($y + 5) 10 '#FFFFFF' -MaxW ($bw - 6) }
                }
            }
            'ticks' {
                Add-CText $C $r.Label 24 ($y + 6) 11 '#C9D1DD' -MaxW ($labelW - 30)
                Add-CRect $C 10 ($y + 10) 8 8 $(if ($r.Color) { [string]$r.Color } else { '#4F8CFF' }) $null 4
                Add-CLine $C $labelW ($y + $h / 2) ($labelW + $pw) ($y + $h / 2) '#232A36' 1
                foreach ($t in @($r.Ticks)) {
                    $tt = [double]$t.T
                    if ($tt -lt $xmin -or $tt -gt $xmax) { continue }
                    $tx = $labelW + ($tt - $xmin) * $k
                    Add-CRect $C ($tx - 1.5) ($y + 5) 3 ($h - 10) $t.Color $t.Tip 1
                }
            }
        }
        $y += $h
    }
    $i = 0
    foreach ($m in @($Spec.Markers)) {
        if ($null -eq $m.T) { continue }
        $t = [double]$m.T
        if ($t -lt $xmin -or $t -gt $xmax) { continue }
        $x = $labelW + ($t - $xmin) * $k
        Add-CLine $C $x ($top - 6) $x $plotBottom $m.Color 1.5 -Dash
        $txt = '{0} ({1})' -f $m.Name, (Format-Sec $t)
        $tx = [Math]::Max(4, [Math]::Min($x + 4, $W - 160))
        Add-CText $C $txt $tx (21 + ($i % 2) * 12) 10 $m.Color -Bold
        $i++
    }
}

function Get-RowTip($r) {
    $t = "{0} (PID {1})`nCategory: {2}`nAverage CPU: {3:N1}% of the machine, peak {4:N1}%`nCPU time: {5:N2} s   I/O: {6:N1} MB" -f $r.Name, $r.PID, $r.Category, $r.AvgCpu, $r.PeakCpu, $r.CpuSec, $r.IoMB
    if ($r.Services) { $t += "`nServices: $($r.Services)" }
    if ($r.Path) { $t += "`n$($r.Path)" }
    $t
}

function Get-TraceLaneSpec {
    param($Trace, $Model, [string]$Focus = 'all', [double]$PreSeconds = 4, [string]$Title = 'Timeline')
    $rows = New-Object Collections.Generic.List[object]
    $spec = @{ Title = $Title; Rows = $rows; Markers = @($Model.Marks); XMin = 0.0; XMax = 1.0; Shade = $null; ShadeTip = 'Start phase (launch until the window was visible)'; Empty = $null }
    $samples = @($Trace.Samples)
    if (-not $samples.Count) { $spec.Empty = 'Waiting for the first samples ...'; return $spec }
    $xmin = [Math]::Max(-$PreSeconds, [double]$samples[0].T0)
    $xmax = [Math]::Max([double]$samples[-1].T, $Model.TEnd)
    if ($xmax - $xmin -lt 1) { $xmax = $xmin + 1 }
    $spec.XMin = $xmin; $spec.XMax = $xmax
    if ($Model.TEnd -gt 0.06 -and $null -ne $Trace.Marks.Process) { $spec.Shade = @(0.0, $Model.TEnd) }
    $rows.Add(@{ Kind = 'header'; Label = 'Whole system' })
    $cpu = Get-LanePoints $samples $null 'Cpu' 0 $xmin $xmax
    $rows.Add(@{ Kind = 'area'; Label = 'CPU - all processes'; Sub = ('peak {0:N0}% of the machine' -f $cpu.Peak); Color = '#8A94A6'; Points = $cpu.Points; Scale = 100; Tip = 'Total CPU usage of the machine' })
    $disk = Get-LanePoints $samples $null 'DiskKBs' 0 $xmin $xmax
    $rows.Add(@{ Kind = 'area'; Label = 'Disk read/write'; Sub = ('peak {0:N1} MB/s' -f ($disk.Peak / 1024)); Color = '#B08CFF'; Points = $disk.Points; Scale = [Math]::Max($disk.Peak, 2048); Tip = 'Throughput of all physical disks' })
    $chain = @($Model.Chain); $bg = @($Model.Interferers)
    if ($Focus -like 'pid:*') { $fp = [int]$Focus.Substring(4); $chain = @($chain | Where-Object { $_.PID -eq $fp }); $bg = @($Model.Background | Where-Object { $_.PID -eq $fp }) }
    elseif ($Focus -eq 'chain') { $bg = @() }
    elseif ($Focus -eq 'bg') { $chain = @(); $bg = @($Model.Background | Where-Object { $_.Category -notlike 'Measurement*' } | Select-Object -First 14) }
    $addProc = {
        param($r)
        $lp = Get-LanePoints $samples ([string]$r.PID) $null 0 $xmin $xmax
        $rows.Add(@{ Kind = 'area'; Label = ('{0}  ({1})' -f $r.Name, $r.PID); Sub = ('{0} - peak {1:N0}% - {2:N1} CPU-s - {3:N0} MB' -f $r.Category, $lp.Peak, $r.CpuSec, $r.IoMB)
                Color = $r.Color; Points = $lp.Points; Scale = [Math]::Max($lp.Peak, 10); Tip = (Get-RowTip $r) })
    }
    if ($chain.Count) {
        $rows.Add(@{ Kind = 'header'; Label = ('{0} - the app and the processes it started' -f $Trace.App); Color = '#4F9DFF' })
        foreach ($r in ($chain | Select-Object -First 12)) { & $addProc $r }
    }
    if ($bg.Count) {
        $rows.Add(@{ Kind = 'header'; Label = 'Busy in the background during the start (other programs and services)'; Color = '#F5A524' })
        foreach ($r in ($bg | Select-Object -First 14)) { & $addProc $r }
    }
    $ss = @($Trace.ServiceStarts)
    if ($ss.Count -and $Focus -in 'all', 'bg') {
        $rows.Add(@{ Kind = 'ticks'; Label = 'Services changed state'; Color = '#B08CFF'; Ticks = @($ss | ForEach-Object { @{ T = [double]$_.T; Color = '#B08CFF'; Tip = ('{0}  +{1}' -f $_.Name, (Format-Sec ([double]$_.T))) } }) })
    }
    $spec
}

# ---------------------------------------------------------------- overview graphic (chain + interference + time breakdown)
function Add-Chip {
    param($C, [double]$X, [double]$Y, [string]$Text, [string]$Color, [string]$Tip)
    $w = [Math]::Min(430, $Text.Length * 6.3 + 28)
    $r = New-Object Windows.Shapes.Rectangle
    $r.Width = $w; $r.Height = 22; $r.RadiusX = 11; $r.RadiusY = 11
    $r.Fill = Get-Brush '#1C2230'; $r.Stroke = Get-Brush $Color; $r.StrokeThickness = 1
    if ($Tip) { $r.ToolTip = $Tip }
    [Windows.Controls.Canvas]::SetLeft($r, $X); [Windows.Controls.Canvas]::SetTop($r, $Y)
    [void]$C.Children.Add($r)
    Add-CRect $C ($X + 9) ($Y + 7) 8 8 $Color $Tip 4
    Add-CText $C $Text ($X + 22) ($Y + 3) 11 '#D5DBE5' -MaxW ($w - 26)
    $w
}
function Add-ChipRow {
    param($C, [string]$Label, [object[]]$Items, [double]$Y, [double]$W, [int]$MaxLines = 1)
    Add-CText $C $Label 8 ($Y + 3) 11 '#8A94A6' -MaxW 148
    $x = 160; $line = 0; $shown = 0
    foreach ($it in $Items) {
        $w = [Math]::Min(430, ([string]$it.Text).Length * 6.3 + 28)
        if ($x + $w -gt $W - 80 -and $shown -gt 0) {
            $line++
            if ($line -ge $MaxLines) { $line--; break }
            $x = 160
        }
        [void](Add-Chip $C $x ($Y + $line * 26) $it.Text $it.Color $it.Tip)
        $x += $w + 8; $shown++
    }
    if ($shown -lt @($Items).Count) { Add-CText $C ('+{0} more' -f (@($Items).Count - $shown)) ($W - 72) ($Y + $line * 26 + 3) 10.5 '#8A94A6' }
    $Y + ($line + 1) * 26 + 2
}
function Draw-Breakdown($C, $Bk, [double]$X, [double]$Y, [double]$W) {
    $total = 0.0
    foreach ($e in $Bk.GetEnumerator()) { $total += [double]$e.Value }
    Add-CText $C 'Where did the time go?  (launch until the window was visible)' $X $Y 11 '#8A94A6' -MaxW $W
    if ($total -le 0) { return }
    $by = $Y + 17; $cx = $X
    $legend = New-Object Collections.Generic.List[string]
    foreach ($e in $Bk.GetEnumerator()) {
        $v = [double]$e.Value
        if ($v -le 0.0005) { continue }
        $sw = $W * $v / $total
        $pct = $v / $total * 100
        Add-CRect $C $cx $by ([Math]::Max(1, $sw - 1)) 18 (Get-BreakdownColor $e.Key) ('{0}: {1} ({2:N0}%)' -f $e.Key, (Format-Sec $v), $pct) 2
        if ($sw -gt 70) { Add-CText $C ('{0:N0}%  {1}' -f $pct, ($e.Key -replace ' \(.*\)', '')) ($cx + 5) ($by + 2) 10 '#FFFFFF' -MaxW ($sw - 8) }
        $legend.Add(('{0} {1}' -f ($e.Key -replace ' \(.*\)', ''), (Format-Sec $v)))
        $cx += $sw
    }
    Add-CText $C ($legend -join '    ') $X ($by + 21) 10 '#9AA4B2' -MaxW $W
}

function Draw-TraceOverview {
    param($C, $Model, $Trace, [double]$W = 0, [double]$H = 0, [switch]$Live)
    $C.Children.Clear()
    if ($W -le 0) { $W = $C.ActualWidth }
    if ($H -le 0) { $H = $C.ActualHeight }
    if ($W -lt 300 -or $H -lt 150) { return }
    if (-not $Model -or -not $Trace) {
        Add-CText $C 'Start chain' 8 4 13 '#E6EAF0' -Bold
        Add-CText $C 'No trace yet - choose an app above and click "Start trace".' 0 ($H / 2 - 22) 13 '#8A94A6' -MaxW $W -Align Center
        Add-CText $C 'You will see the chain from launch to visible window, what was busy in the background and where the time went.' 0 ($H / 2) 11.5 '#6B7385' -MaxW $W -Align Center
        return
    }
    $mk = $Trace.Marks
    $title = if ($Live) { "LIVE - $($Trace.App)" } else { "Start chain - $($Trace.App)" }
    Add-CText $C $title 8 4 13 '#E6EAF0' -Bold -MaxW ($W * 0.55)
    if ($null -ne $mk.Window) { $res = 'Window visible after ' + (Format-Sec ([double]$mk.Window)); $rc = '#2ECC71' }
    elseif ($mk.Timeout) { $res = 'No window (timeout)'; $rc = '#FF6B6B' }
    elseif ($Live) { $res = 'recording ...'; $rc = '#F5A524' }
    else { $res = '-'; $rc = '#8A94A6' }
    Add-CText $C $res ($W - 340) 2 14 $rc -Bold -MaxW 332 -Align Right

    $steps = New-Object Collections.Generic.List[object]
    foreach ($m in @($Model.Marks)) { $steps.Add($m) }
    if ($Live -and $null -eq $mk.Window) {
        if ($null -eq $mk.Process) {
            $steps.Clear()
            $steps.Add(@{ Name = $(if ($Trace.Mode -eq 'Watch') { 'Waiting for you to start the app' } else { 'Recording background, then launching' }); T = $null; Color = '#F5A524' })
        }
        $steps.Add(@{ Name = 'Window visible'; T = $null; Color = '#3A4356' })
    }
    $n = $steps.Count; $gap = 42
    $bw = [Math]::Min(240, ($W - 16 - ($n - 1) * $gap) / $n)
    $y = 28; $bh = 44; $prevT = $null
    for ($i = 0; $i -lt $n; $i++) {
        $s = $steps[$i]; $x = 8 + $i * ($bw + $gap)
        $rect = New-Object Windows.Shapes.Rectangle
        $rect.Width = $bw; $rect.Height = $bh; $rect.RadiusX = 8; $rect.RadiusY = 8
        $rect.Fill = Get-Brush '#1C2230'; $rect.Stroke = Get-Brush $s.Color; $rect.StrokeThickness = 1.5
        [Windows.Controls.Canvas]::SetLeft($rect, $x); [Windows.Controls.Canvas]::SetTop($rect, $y)
        [void]$C.Children.Add($rect)
        Add-CText $C $s.Name ($x + 10) ($y + 5) 11.5 '#C9D1DD' -Bold -MaxW ($bw - 16)
        $tt = if ($null -ne $s.T) { if ([double]$s.T -eq 0) { '0 s' } else { '+' + (Format-Sec ([double]$s.T)) } } else { 'waiting ...' }
        Add-CText $C $tt ($x + 10) ($y + 22) 14 $s.Color -Bold -MaxW ($bw - 16)
        if ($i -gt 0) {
            $ax = $x - $gap + 4; $ay = $y + $bh / 2
            Add-CLine $C $ax $ay ($x - 8) $ay '#5A6275' 2
            $tri = New-Object Windows.Shapes.Polygon
            $tp = New-Object Windows.Media.PointCollection
            $tp.Add([Windows.Point]::new($x - 9, $ay - 5)); $tp.Add([Windows.Point]::new($x - 2, $ay)); $tp.Add([Windows.Point]::new($x - 9, $ay + 5))
            $tri.Points = $tp
            $tri.Fill = Get-Brush '#5A6275'
            [void]$C.Children.Add($tri)
            if ($null -ne $s.T -and $null -ne $prevT) { Add-CText $C ('+' + (Format-Sec ([double]$s.T - $prevT))) ($ax - 8) ($ay - 18) 9.5 '#8A94A6' -MaxW ($gap + 8) -Align Center }
        }
        if ($null -ne $s.T) { $prevT = [double]$s.T }
    }
    $y = $y + $bh + 10
    $chainItems = @($Model.Chain | Select-Object -First 10 | ForEach-Object {
            $st = if ($null -ne $_.StartedSec) { ' +' + (Format-Sec $_.StartedSec) } else { '' }
            @{ Text = ('{0}{1} - {2:N1} CPU-s' -f $_.Name, $st, $_.CpuSec); Color = '#4F8CFF'; Tip = (Get-RowTip $_) } })
    if ($chainItems.Count) { $y = Add-ChipRow $C 'App processes' $chainItems $y $W 1 }
    else { Add-CText $C 'App processes' 8 ($y + 3) 11 '#8A94A6'; Add-CText $C '-' 160 ($y + 3) 11 '#6B7385'; $y += 28 }
    $ss = @($Trace.ServiceStarts | Where-Object { [double]$_.T -ge -0.5 -and [double]$_.T -le $Model.TEnd + 0.5 })
    $bgItems = @($Model.Interferers | ForEach-Object { @{ Text = ('{0} - {1} - {2:N0}% CPU - {3:N0} MB' -f $_.Name, $_.Category, $_.AvgCpu, $_.IoMB); Color = $_.Color; Tip = (Get-RowTip $_) } })
    if ($bgItems.Count) { $y = Add-ChipRow $C 'Busy in background' $bgItems $y $W $(if ($ss.Count) { 1 } else { 2 }) }
    else { Add-CText $C 'Busy in background' 8 ($y + 3) 11 '#8A94A6'; Add-CText $C 'nothing significant' 160 ($y + 3) 11 '#2ECC71'; $y += 28 }
    if ($ss.Count) {
        $svcItems = @($ss | ForEach-Object { @{ Text = ('{0} +{1}' -f $_.Name, (Format-Sec ([double]$_.T))); Color = '#B08CFF'; Tip = [string]$_.DisplayName } })
        $y = Add-ChipRow $C 'Services started' $svcItems $y $W 1
    }
    $yb = [Math]::Max($y + 2, $H - 52)
    Draw-Breakdown $C $Model.Breakdown 8 $yb ($W - 16)
}

function Show-TraceFindings($Findings) {
    $p = $UI.TrFindings
    $p.Children.Clear()
    if (-not $Findings -or @($Findings).Count -eq 0) {
        Add-DetailText $p 'Run a trace to see what slowed the start down.' 12.5 '#8A94A6'
        return
    }
    foreach ($f in $Findings) {
        $col = switch ($f.Sev) { 'high' { '#FF6B6B' } 'medium' { '#F5A524' } 'ok' { '#2ECC71' } default { '#4F9DFF' } }
        $b = New-Object Windows.Controls.Border
        $b.BorderBrush = Get-Brush $col
        $b.BorderThickness = New-Object Windows.Thickness 3, 0, 0, 0
        $b.Background = Get-Brush '#1A1F29'
        $b.Padding = New-Object Windows.Thickness 10, 8, 10, 8
        $b.Margin = New-Object Windows.Thickness 0, 0, 0, 8
        $sp = New-Object Windows.Controls.StackPanel
        Add-DetailText $sp $f.Title 13 '#FFFFFF' -Bold
        Add-DetailText $sp $f.Text 12 '#C9D1DD' -Margin '0,4,0,0'
        $b.Child = $sp
        [void]$p.Children.Add($b)
    }
}

# ---------------------------------------------------------------- renderers (also used for PNG / report export)
function Render-TraceOverview {
    param($C, [double]$W = 0, [double]$H = 0)
    Draw-TraceOverview $C $script:TraceModel $script:CurrentTrace $W $H
}
function Get-TraceFocus {
    $i = $UI.TrFocus.SelectedIndex
    if ($i -ge 0 -and $i -lt @($script:TraceFocusKeys).Count) { return $script:TraceFocusKeys[$i] }
    'all'
}
function Render-TraceTimeline {
    param($C, [double]$W = 0, [double]$H = 0)
    if (-not $script:CurrentTrace -or -not $script:TraceModel) {
        Draw-Swimlanes $C @{ Title = 'Timeline'; Rows = @(); Markers = @(); XMin = 0; XMax = 1; Empty = 'The live timeline of every process appears here while a trace is recorded.' } $W $H
        return
    }
    $spec = Get-TraceLaneSpec $script:CurrentTrace $script:TraceModel (Get-TraceFocus) 4 ('Timeline - {0}   (shaded = launch until window visible)' -f $script:CurrentTrace.App)
    Draw-Swimlanes $C $spec $W $H
}

# ---------------------------------------------------------------- recording an app start
function Start-StartTrace {
    if ($script:TraceRunning) { return }
    if ($script:TestRunning -or $script:Manual) { Show-Info 'Finish the running app start test first.'; return }
    $mode = if ($UI.TrMode.SelectedIndex -eq 1) { 'Watch' } else { 'Launch' }
    $exe = $UI.TrExe.Text.Trim().Trim('"')
    $watch = $UI.TrWatch.Text.Trim()
    if (-not $watch -and $exe -like '*.lnk') {
        try { $t = (New-Object -ComObject WScript.Shell).CreateShortcut($exe).TargetPath; if ($t) { $watch = [IO.Path]::GetFileNameWithoutExtension($t) } } catch { }
    }
    if ($mode -eq 'Launch') {
        if (-not $exe) { Show-Info 'Choose the application to start (Browse...).'; return }
        if ($exe -notlike 'shell:*' -and -not (Test-Path -LiteralPath $exe) -and -not (Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue)) { Show-ErrorMessage "File not found:`n$exe"; return }
        if ($exe -like 'shell:*' -and -not $watch) { Show-Info 'For shell:AppsFolder entries enter the process name of the app under "Process name(s)".'; return }
    } else {
        if (-not $watch -and $exe -and $exe -notlike 'shell:*') { $watch = [IO.Path]::GetFileNameWithoutExtension($exe) }
        if (-not $watch) { Show-Info 'Enter the process name of the app you are going to start (e.g. winword, chrome, Teams) or choose its .exe with Browse.'; return }
    }
    $timeout = 0; $post = 0
    if (-not [int]::TryParse($UI.TrTimeout.Text, [ref]$timeout) -or $timeout -lt 5 -or $timeout -gt 600) { Show-Info 'Timeout must be a number between 5 and 600 seconds.'; return }
    if (-not [int]::TryParse($UI.TrPost.Text, [ref]$post) -or $post -lt 0 -or $post -gt 60) { Show-Info 'Keep recording must be a number between 0 and 60 seconds.'; return }
    $interval = @(250, 500, 1000)[[Math]::Max(0, $UI.TrInterval.SelectedIndex)]
    $names = if ($watch) { @($watch -split '[,;]' | ForEach-Object { $_.Trim() -replace '\.exe$', '' } | Where-Object { $_ }) } elseif ($exe -notlike 'shell:*') { @([IO.Path]::GetFileNameWithoutExtension($exe)) } else { @() }
    $running = @()
    if ($names.Count) { $running = @(Get-Process -Name $names -ErrorAction SilentlyContinue) }
    if ($running.Count) {
        if (-not (Confirm-Action ("'{0}' is already running ({1} instance(s)).`n`nMany apps only hand the start over to the running instance - that is not a real start. Close the app first for a meaningful trace.`n`nContinue anyway?" -f ($names -join ', '), $running.Count))) { return }
    }
    $app = if ($names.Count) { $names[0] } else { $exe }
    $S = $script:Sync
    $S.Cancel = $false; $S.TraceStop = $false; $S.TraceReady = $false; $S.TraceSamplerDone = $false; $S.TraceClock = $null
    $S.TraceSamples = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList))
    $S.TraceProcs = [hashtable]::Synchronized(@{})
    $S.TraceSvcMap = [hashtable]::Synchronized(@{})
    $S.TraceMarks = [hashtable]::Synchronized(@{})
    $script:TraceRunning = $true
    $script:TraceDone = 0
    $script:TraceRequest = @{ Mode = $mode; Exe = $exe; Args = $UI.TrArgs.Text; Watch = $watch; Names = $names; Timeout = $timeout; Post = $post; Interval = $interval; App = $app }
    $UI.BtnTrStart.IsEnabled = $false; $UI.BtnTrStop.IsEnabled = $true
    $UI.BtnTestRun.IsEnabled = $false
    $maxSec = $timeout + $post + 25
    if ($mode -eq 'Watch') { $maxSec += 300 }
    $onDone = {
        param($r, $e)
        if ($e) { $script:Sync.TraceMarks.Error = $e.Message; $script:Sync.TraceStop = $true; $script:Sync.Cancel = $true }
        $script:TraceDone++
        if ($script:TraceDone -ge 2) { Complete-StartTrace }
    }
    Start-AsyncTask -Status 'Preparing trace (reading all processes) ...' -Parameters @{ Sync = $S; IntervalMs = $interval; MaxSeconds = $maxSec } -Script {
        param($Sync, $IntervalMs, $MaxSeconds)
        Invoke-TraceSampler -Sync $Sync -IntervalMs $IntervalMs -MaxSeconds $MaxSeconds
    } -OnComplete $onDone
    Start-AsyncTask -Status 'Preparing trace ...' -Parameters @{ Mode = $mode; Exe = $exe; Arguments = $UI.TrArgs.Text; WatchName = $watch; TimeoutSec = $timeout; PostSec = $post; Sync = $S } -Script {
        param($Mode, $Exe, $Arguments, $WatchName, $TimeoutSec, $PostSec, $Sync)
        Invoke-TraceLaunch -Mode $Mode -Exe $Exe -Arguments $Arguments -WatchName $WatchName -TimeoutSec $TimeoutSec -PostSec $PostSec -Sync $Sync
    } -OnComplete $onDone
}

function Get-RelMarks($Mk, [double]$Origin, [int]$PostSec) {
    $rel = { param($v) if ($null -eq $v) { $null } else { [Math]::Round([double]$v - $Origin, 3) } }
    [pscustomobject]@{
        Process = (& $rel $Mk.Process); InputIdle = (& $rel $Mk.InputIdle); Window = (& $rel $Mk.Window); End = (& $rel $Mk.End)
        Timeout = [bool]$Mk.Timeout; Error = $Mk.Error; RootPid = $Mk.RootPid; WindowPid = $Mk.WindowPid; PostSec = $PostSec
    }
}

function Update-TraceLive {
    if (([DateTime]::Now - $script:TraceLastLive).TotalMilliseconds -lt 600) { return }
    $script:TraceLastLive = [DateTime]::Now
    $S = $script:Sync; $req = $script:TraceRequest
    if (-not $req -or -not $S.TraceSamples) { return }
    $n = $S.TraceSamples.Count
    if ($n -lt 1) { return }
    $mk = $S.TraceMarks
    $launched = $null -ne $mk.Launch
    $last = [double]$S.TraceSamples[$n - 1].T
    $origin = if ($launched) { [double]$mk.Launch } else { $last }
    $pre = if ($launched) { 4 } else { 15 }
    $data = ConvertTo-TraceData $S $origin (-$pre - 2)
    $tmp = [pscustomobject]@{
        App = $req.App; Mode = $req.Mode; Marks = (Get-RelMarks $mk $origin 0); Samples = $data.Samples; Procs = $data.Procs; SvcMap = $data.SvcMap
        ServiceStarts = @(); Cores = [Environment]::ProcessorCount; TotalMemMB = $script:TotalMemMB; IntervalMs = $req.Interval; WatchNames = $req.Names; OwnPid = $PID
    }
    if (-not $launched) { $tmp.Marks.Process = $null }
    $model = Get-TraceModel $tmp $(if ($launched) { 0 } else { -$pre })
    $title = if ($launched) { "LIVE - recording the start of $($req.App)" } else { 'LIVE - background activity right now (waiting for the start)' }
    $spec = Get-TraceLaneSpec $tmp $model 'all' $pre $title
    Draw-Swimlanes $UI.TrTimeline $spec 0 0
    Draw-TraceOverview $UI.TrOverview $model $tmp 0 0 -Live
}

function Complete-StartTrace {
    $S = $script:Sync; $req = $script:TraceRequest
    $script:TraceRunning = $false
    $UI.BtnTrStart.IsEnabled = $true; $UI.BtnTrStop.IsEnabled = $false
    Set-TestButtons $script:TestRunning
    $mk = $S.TraceMarks
    if ($null -eq $mk.Launch) {
        $msg = if ($mk.Error) { [string]$mk.Error } else { 'Trace ended before the app was started.' }
        Set-Status "Trace ended: $msg"
        if ($msg -ne 'Cancelled') { Show-Info $msg 'Start trace' }
        Render-TraceOverview $UI.TrOverview
        Render-TraceTimeline $UI.TrTimeline
        return
    }
    $origin = [double]$mk.Launch
    $marks = Get-RelMarks $mk $origin $req.Post
    $data = ConvertTo-TraceData $S $origin
    $svcStarts = @()
    try {
        $clock = $S.TraceClock
        $wallLaunch = ([datetime]$clock.Wall).AddSeconds($origin - [double]$clock.Qpc)
        $endRel = if ($null -ne $marks.End) { [double]$marks.End } else { 60 }
        $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7036; StartTime = $wallLaunch.AddSeconds(-1); EndTime = $wallLaunch.AddSeconds($endRel + 1) } -ErrorAction Stop)
        $map = @{}
        if ($script:LastSnap) { foreach ($sv in $script:LastSnap.Services) { $map[[string]$sv.DisplayName] = $sv.Name } }
        $seen = @{}
        $svcStarts = @(foreach ($e in ($evs | Sort-Object TimeCreated)) {
                $dn = [string]$e.Properties[0].Value
                if (-not $dn -or $seen.ContainsKey($dn)) { continue }
                $seen[$dn] = $true
                [pscustomobject]@{ T = [Math]::Round(($e.TimeCreated - $wallLaunch).TotalSeconds, 2); Name = $(if ($map[$dn]) { $map[$dn] } else { $dn }); DisplayName = $dn }
            })
    } catch { }
    $t = [pscustomobject]@{
        Id = [guid]::NewGuid().ToString(); App = $req.App; Exe = $req.Exe; Mode = $req.Mode; Created = (Get-Date).ToString('o'); Computer = $env:COMPUTERNAME
        Marks = $marks; Samples = $data.Samples; Procs = $data.Procs; SvcMap = $data.SvcMap; ServiceStarts = $svcStarts
        Cores = [Environment]::ProcessorCount; TotalMemMB = $script:TotalMemMB; IntervalMs = $req.Interval; WatchNames = $req.Names; OwnPid = $PID
    }
    $script:Traces.Add($t)
    Update-TraceHistory -Select $t
    $res = if ($null -ne $marks.Window) { 'window visible after ' + (Format-Sec ([double]$marks.Window)) } elseif ($marks.Timeout) { 'no window within the timeout' } else { [string]$marks.Error }
    Set-Status "Trace of $($req.App) finished: $res"
}

function Get-TraceDurationText($t) {
    if ($null -ne $t.Marks.Window) { 'window after ' + (Format-Sec ([double]$t.Marks.Window)) }
    elseif ($t.Marks.Timeout) { 'no window (timeout)' }
    else { 'incomplete' }
}

function Update-TraceHistory {
    param($Select)
    $script:SuppressCombo = $true
    try {
        $apps = @($script:Traces | ForEach-Object { [string]$_.App } | Sort-Object -Unique)
        $appItems = @('All apps') + $apps
        $curApp = $null
        if ($UI.TrAppFilter.SelectedIndex -gt 0) { $curApp = [string]$UI.TrAppFilter.SelectedItem }
        if ($Select -and $curApp -and $Select.App -ne $curApp) { $curApp = $null }
        $UI.TrAppFilter.ItemsSource = $appItems
        $UI.TrAppFilter.SelectedIndex = $(if ($curApp) { [Math]::Max(0, [Array]::IndexOf($appItems, $curApp)) } else { 0 })
        $list = @($script:Traces | Where-Object { -not $curApp -or $_.App -eq $curApp } | Sort-Object { [datetime]$_.Created } -Descending)
        $script:TraceHistList = $list
        $UI.TrHistory.ItemsSource = @($list | ForEach-Object { '{0:dd.MM. HH:mm:ss}   {1}   -   {2}' -f ([datetime]$_.Created), $_.App, (Get-TraceDurationText $_) })
        $sel = 0
        $want = if ($Select) { $Select } else { $script:CurrentTrace }
        for ($i = 0; $i -lt $list.Count; $i++) { if ($want -and $list[$i].Id -eq $want.Id) { $sel = $i } }
        if ($list.Count) { $UI.TrHistory.SelectedIndex = $sel }
    } finally { $script:SuppressCombo = $false }
    if (@($script:TraceHistList).Count) { Show-Trace $script:TraceHistList[$sel] }
}

function Show-Trace($t) {
    $script:CurrentTrace = $t
    $script:TraceModel = Get-TraceModel $t
    $m = $script:TraceModel
    $keys = New-Object Collections.Generic.List[string]; $labels = New-Object Collections.Generic.List[string]
    $keys.Add('all'); $labels.Add('Everything')
    $keys.Add('chain'); $labels.Add("Only $($t.App) and its processes")
    $keys.Add('bg'); $labels.Add('Only background activity')
    foreach ($r in (@($m.Chain) + @($m.Interferers))) { $keys.Add("pid:$($r.PID)"); $labels.Add(('{0} (PID {1}) - {2}' -f $r.Name, $r.PID, $r.Category)) }
    $script:SuppressCombo = $true
    try {
        $script:TraceFocusKeys = $keys.ToArray()
        $UI.TrFocus.ItemsSource = $labels.ToArray()
        $UI.TrFocus.SelectedIndex = 0
    } finally { $script:SuppressCombo = $false }
    Render-TraceOverview $UI.TrOverview
    Update-TraceFocusView
    Show-TraceFindings $m.Findings
}

function Update-TraceFocusView {
    if (-not $script:TraceModel) { return }
    $f = Get-TraceFocus
    $rows = @($script:TraceModel.Rows | Sort-Object @{ Expression = { switch ($_.Role) { 'App' { 0 } 'Child process' { 1 } default { 2 } } } }, @{ Expression = { $_.Score }; Descending = $true })
    switch -Wildcard ($f) {
        'chain' { $rows = @($rows | Where-Object { $_.Role -ne 'Background' }) }
        'bg'    { $rows = @($rows | Where-Object { $_.Role -eq 'Background' }) }
        'pid:*' { $fp = [int]$f.Substring(4); $rows = @($rows | Where-Object { $_.PID -eq $fp }) }
    }
    Set-GridItems $UI.TrGrid $rows
    Render-TraceTimeline $UI.TrTimeline
}

function Save-TraceFile {
    if (-not $script:CurrentTrace) { Show-Info 'Record or open a trace first.'; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'PerfInspector trace (*.json)|*.json'
    $dlg.FileName = 'StartTrace_{0}_{1:yyyyMMdd_HHmmss}' -f ($script:CurrentTrace.App -replace '[^\w\-]', '_'), ([datetime]$script:CurrentTrace.Created)
    if (-not $dlg.ShowDialog($script:Window)) { return }
    try {
        $script:CurrentTrace | ConvertTo-Json -Depth 8 -Compress | Set-Content -Path $dlg.FileName -Encoding UTF8
        Set-Status "Trace saved to $($dlg.FileName)"
    } catch { Show-ErrorMessage "Could not save the trace: $($_.Exception.Message)" }
}
function Open-TraceFile {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = 'PerfInspector trace (*.json)|*.json'
    if (-not $dlg.ShowDialog($script:Window)) { return }
    try {
        $t = Get-Content -LiteralPath $dlg.FileName -Raw | ConvertFrom-Json
        if (-not $t.Samples -or -not $t.Marks) { throw 'This is not a PerfInspector start trace.' }
        $existing = @($script:Traces | Where-Object { $_.Id -eq $t.Id })
        if ($existing.Count) { $t = $existing[0] } else { $script:Traces.Add($t) }
        Update-TraceHistory -Select $t
        Set-Status "Trace opened: $($dlg.FileName)"
    } catch { Show-ErrorMessage "Could not open the trace: $($_.Exception.Message)" }
}
function Save-TraceCharts {
    if (-not $script:CurrentTrace) { Show-Info 'Record or open a trace first.'; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'PNG image|*.png'
    $dlg.FileName = 'StartTrace_{0}_{1:yyyyMMdd_HHmmss}' -f ($script:CurrentTrace.App -replace '[^\w\-]', '_'), ([datetime]$script:CurrentTrace.Created)
    if (-not $dlg.ShowDialog($script:Window)) { return }
    $base = [IO.Path]::Combine([IO.Path]::GetDirectoryName($dlg.FileName), [IO.Path]::GetFileNameWithoutExtension($dlg.FileName))
    $w = [Math]::Max(1100, $UI.TrTimeline.ActualWidth)
    try {
        [IO.File]::WriteAllBytes("${base}_overview.png", (Get-ChartPngBytes 'Render-TraceOverview' $w 262))
        [IO.File]::WriteAllBytes("${base}_timeline.png", (Get-ChartPngBytes 'Render-TraceTimeline' $w 0))
        Set-Status "Saved ${base}_overview.png and ${base}_timeline.png"
    } catch { Show-ErrorMessage "Could not save the charts: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- boot timeline
function New-BootEvent($T, [string]$Type, [string]$Name, $Dur, [string]$Details, $Desk) {
    $before = ''
    if ($null -ne $T -and $null -ne $Desk) { $before = $(if ([double]$T -le [double]$Desk) { 'Yes' } else { 'No' }) }
    [pscustomobject]@{ T = $(if ($null -ne $T) { [Math]::Round([double]$T, 2) } else { $null }); Type = $Type; Name = $Name; DurationSec = $(if ($null -ne $Dur) { [Math]::Round([double]$Dur, 2) } else { $null }); BeforeDesktop = $before; Details = $Details }
}

function Get-BootTimelineModel {
    param($Tl, $Rec, [bool]$OnlyDesktop, [string]$Filter)
    $rows = New-Object Collections.Generic.List[object]
    $events = New-Object Collections.Generic.List[object]
    $findings = New-Object Collections.Generic.List[string]
    $markers = New-Object Collections.Generic.List[object]
    $recOnly = $false; $shift = 0.0; $recSamples = @()
    if ($Rec) {
        $shift = ([datetime]$Rec.BootTime - [datetime]$Tl.T0).TotalSeconds
        $recSamples = @($Rec.Samples)
        if ([Math]::Abs($shift) -gt 600) { $recOnly = $true; $shift = 0.0 }
    }
    $fm = { param($a, $b) -not $Filter -or (Test-Contains $a $Filter) -or (Test-Contains $b $Filter) }
    $desk = if ($recOnly) { $null } else { $Tl.DesktopT }
    if ($recOnly) {
        $exp = @(Get-TraceKeys $Rec.Procs | ForEach-Object { $Rec.Procs.$_ } | Where-Object { $_.Name -eq 'explorer' -and [int]$_.Session -gt 0 -and $null -ne $_.Created } | Sort-Object { [double]$_.Created }) | Select-Object -First 1
        if ($exp) { $desk = [double]$exp.Created; $markers.Add(@{ Name = 'Explorer started (desktop)'; T = $desk; Color = '#2ECC71' }) }
    } else {
        foreach ($m in @($Tl.Markers)) { $markers.Add(@{ Name = $m.Name; T = [double]$m.T; Color = $m.Color }) }
    }
    $endCand = New-Object Collections.Generic.List[double]
    $endCand.Add(30)
    if ($null -ne $desk) { $endCand.Add([double]$desk + 15) }
    if (-not $recOnly -and $Tl.BootEndT) { $endCand.Add([double]$Tl.BootEndT) }
    if ($recSamples.Count) { $endCand.Add([double]$recSamples[-1].T + $shift) }
    $xmax = if ($OnlyDesktop -and $null -ne $desk) { [double]$desk * 1.03 + 2 } else { [Math]::Min(900, ($endCand | Measure-Object -Maximum).Maximum) }
    $xmin = 0.0
    $deskTxt = if ($null -ne $desk) { $desk } else { $null }

    # Windows boot phases
    if (-not $recOnly) {
        if (@($Tl.Phases).Count) {
            $rows.Add(@{ Kind = 'header'; Label = 'Windows boot phases (reported by Windows)'; Color = '#4F9DFF' })
            foreach ($p in $Tl.Phases) {
                $e = [double]$p.Start + [double]$p.Duration
                $nm = $p.Name
                if ($nm -eq 'Waiting at sign-in screen') { $nm += ' (approx. position)' }
                $rows.Add(@{ Kind = 'bars'; Label = ('{0}  {1}' -f $p.Name, (Format-Sec $p.Duration)); Color = $p.Color
                        Bars = @(@{ Start = [double]$p.Start; End = $e; Color = $p.Color; Text = (Format-Sec $p.Duration); Tip = ('{0}: {1} (from {2} to {3} after boot start)' -f $nm, (Format-Sec $p.Duration), (Format-Sec $p.Start), (Format-Sec $e)) }) })
                $events.Add((New-BootEvent $p.Start 'Boot phase' $nm $p.Duration '' $deskTxt))
            }
        } else {
            $why = if ($script:IsAdmin) { 'Boot phases are not available for this boot yet (Windows writes the boot report a few minutes after the boot; after a Fast Startup shutdown there is none - use Restart).' } else { 'Boot phases need administrator rights (Restart as administrator).' }
            $rows.Add(@{ Kind = 'header'; Label = $why; Color = '#F5A524' })
        }
        foreach ($d in @($Tl.Durations)) { $events.Add((New-BootEvent $null 'Phase duration' $d.Name $d.Seconds 'Duration reported by Windows' $deskTxt)) }
        $pol = @($Tl.Policies)
        if ($pol.Count) {
            $rows.Add(@{ Kind = 'bars'; Label = 'Group Policy'; Color = '#E07BE0'; Bars = @($pol | ForEach-Object { @{ Start = [double]$_.T; End = [double]$_.T + [double]$_.Duration; Color = '#E07BE0'; Text = $_.Name; Tip = ('{0}: {1}' -f $_.Name, (Format-Sec $_.Duration)) } }) })
            foreach ($p in $pol) { $events.Add((New-BootEvent $p.T 'Group Policy' $p.Name $p.Duration '' $deskTxt)) }
        }
    }
    foreach ($m in $markers) { $events.Add((New-BootEvent $m.T 'Milestone' $m.Name $null '' $deskTxt)) }

    # services and programs
    $rows.Add(@{ Kind = 'header'; Label = 'Services and programs that started (hover a line for the name)'; Color = '#9AA4B2' })
    $slow = @{}
    foreach ($d in @($Tl.Slowdowns)) { if ([int]$d.EventId -eq 103) { foreach ($n in @($d.Name, $d.File)) { if ($n) { $slow[([string]$n).ToLower()] = [double]$d.DegradationMs } } } }
    if (-not $recOnly) {
        $svc = @($Tl.ServiceStarts | Where-Object { [double]$_.T -ge $xmin -and [double]$_.T -le $xmax -and (& $fm $_.DisplayName $_.Name) } | Sort-Object { [double]$_.T })
        $ticks = foreach ($s in $svc) {
            $isSlow = $slow.ContainsKey(([string]$s.Name).ToLower()) -or $slow.ContainsKey(([string]$s.DisplayName).ToLower())
            @{ T = [double]$s.T; Color = $(if ($isSlow) { '#FF6B6B' } else { '#4F8CFF' }); Tip = ('{0}  ({1})  +{2}{3}' -f $s.DisplayName, $s.Name, (Format-Sec ([double]$s.T)), $(if ($isSlow) { '  - reported as slowing down the boot' } else { '' })) }
        }
        $rows.Add(@{ Kind = 'ticks'; Label = ('Services started ({0})' -f $svc.Count); Color = '#4F8CFF'; Ticks = @($ticks) })
        foreach ($s in $svc) { $events.Add((New-BootEvent $s.T 'Service started' $s.DisplayName $null $s.Name $deskTxt)) }
    }
    $progs = @()
    if ($Rec) {
        $progs = @(Get-TraceKeys $Rec.Procs | ForEach-Object { $pm = $Rec.Procs.$_; if ($null -ne $pm.Created) { [pscustomobject]@{ Name = [string]$pm.Name; PID = [int]$_; T = [double]$pm.Created + $shift; Session = [int]$pm.Session; Path = [string]$pm.Path } } })
    } else { $progs = @($Tl.ProcessStarts) }
    $progs = @($progs | Where-Object { [double]$_.T -ge $xmin -and [double]$_.T -le $xmax -and (& $fm $_.Name $_.Path) } | Sort-Object { [double]$_.T })
    $pt = foreach ($p in $progs) { @{ T = [double]$p.T; Color = $(if ([int]$p.Session -gt 0) { '#2ECC71' } else { '#6B7385' }); Tip = ('{0} (PID {1})  +{2}{3}' -f $p.Name, $p.PID, (Format-Sec ([double]$p.T)), $(if ($p.Path) { "`n$($p.Path)" } else { '' })) } }
    $rows.Add(@{ Kind = 'ticks'; Label = ('Programs started ({0}){1}' -f $progs.Count, $(if ($Rec) { '' } else { ' - still running' })); Color = '#2ECC71'; Ticks = @($pt) })
    foreach ($p in $progs) { $events.Add((New-BootEvent $p.T 'Program started' $p.Name $null $(if ([int]$p.Session -gt 0) { "user session - $($p.Path)" } else { "system - $($p.Path)" }) $deskTxt)) }
    if (-not $recOnly) {
        foreach ($d in @($Tl.Slowdowns)) { $events.Add((New-BootEvent $null 'Slowdown reported' $d.Name ([double]$d.DegradationMs / 1000) ('{0}, total {1:N0} ms' -f $d.Type, $d.TotalMs) $deskTxt)) }
    }

    # recorded activity
    $topCpu = @(); $secRows = @()
    if ($Rec) {
        $cores = [int]$Rec.Cores; if ($cores -lt 1) { $cores = 1 }
        $statEnd = if ($null -ne $desk) { [Math]::Min($xmax, [double]$desk) } else { $xmax }
        $rows.Add(@{ Kind = 'header'; Label = ('Activity recorded during this boot - CPU per process (statistics until {0})' -f $(if ($null -ne $desk) { 'the desktop' } else { 'the end of the view' })); Color = '#F5A524' })
        $cpu = Get-LanePoints $recSamples $null 'Cpu' $shift $xmin $xmax
        $rows.Add(@{ Kind = 'area'; Label = 'CPU - all processes'; Sub = ('peak {0:N0}%' -f $cpu.Peak); Color = '#8A94A6'; Points = $cpu.Points; Scale = 100; Tip = 'Total CPU usage' })
        $dk = Get-LanePoints $recSamples $null 'DiskKBs' $shift $xmin $xmax
        $rows.Add(@{ Kind = 'area'; Label = 'Disk read/write'; Sub = ('peak {0:N1} MB/s' -f ($dk.Peak / 1024)); Color = '#B08CFF'; Points = $dk.Points; Scale = [Math]::Max($dk.Peak, 2048); Tip = 'Disk throughput' })
        $st = @{}
        foreach ($s in $recSamples) {
            $a = [Math]::Max([double]$s.T0 + $shift, $xmin); $b = [Math]::Min([double]$s.T + $shift, $statEnd); $ov = $b - $a
            if ($ov -le 0) { continue }
            foreach ($k in (Get-TraceKeys $s.P)) {
                $v = $s.P.$k
                if (-not $st.ContainsKey($k)) { $st[$k] = @{ CpuSec = 0.0; IoMB = 0.0; First = $null; Peak = 0.0 } }
                $x = $st[$k]
                $x.CpuSec += [double]$v[0] / 100 * $cores * $ov; $x.IoMB += [double]$v[1] * $ov / 1024
                if ([double]$v[0] -gt $x.Peak) { $x.Peak = [double]$v[0] }
                if ($null -eq $x.First -and ([double]$v[0] -ge 0.5 -or [double]$v[1] -ge 256)) { $x.First = $a }
            }
        }
        $procRows = foreach ($k in $st.Keys) {
            $pm = $Rec.Procs.$k
            $name = if ($pm) { [string]$pm.Name } else { "PID $k" }
            $svcs = [string]$Rec.SvcMap.$k
            $cat = Get-TraceCategory $name $svcs ([int]$k) ([int]$Rec.RecorderPid)
            if ($cat[0] -like 'Measurement*') { continue }
            if (-not (& $fm $name $svcs)) { continue }
            [pscustomobject]@{ Name = $name; PID = [int]$k; Category = $cat[0]; Color = $cat[1]; CpuSec = $st[$k].CpuSec; IoMB = $st[$k].IoMB; First = $st[$k].First; Services = $svcs; Path = $(if ($pm) { [string]$pm.Path } else { '' }); Score = $st[$k].CpuSec + $st[$k].IoMB / 50 }
        }
        $procRows = @($procRows | Sort-Object Score -Descending)
        foreach ($r in ($procRows | Select-Object -First 16)) {
            $lp = Get-LanePoints $recSamples ([string]$r.PID) $null $shift $xmin $xmax
            $lbl = if ($r.Services) { '{0}: {1}' -f $r.Name, $r.Services } else { $r.Name }
            $rows.Add(@{ Kind = 'area'; Label = $lbl; Sub = ('{0} - {1:N1} CPU-s - {2:N0} MB I/O' -f $r.Category, $r.CpuSec, $r.IoMB); Color = $r.Color; Points = $lp.Points; Scale = [Math]::Max($lp.Peak, 10)
                    Tip = ("{0} (PID {1})`n{2}`nUntil desktop: {3:N1} CPU-seconds, {4:N0} MB I/O{5}{6}" -f $r.Name, $r.PID, $r.Category, $r.CpuSec, $r.IoMB, $(if ($r.Services) { "`nServices: $($r.Services)" } else { '' }), $(if ($r.Path) { "`n$($r.Path)" } else { '' })) })
        }
        foreach ($r in ($procRows | Select-Object -First 40)) { $events.Add((New-BootEvent $r.First 'Activity' $(if ($r.Services) { "$($r.Name): $($r.Services)" } else { $r.Name }) $null ('{0} - {1:N1} CPU-s, {2:N0} MB I/O until desktop' -f $r.Category, $r.CpuSec, $r.IoMB) $deskTxt)) }
        $topCpu = @($procRows | Select-Object -First 5)
        $secRows = @($procRows | Where-Object { $_.Category -eq 'Security scan' })
    } else {
        $rows.Add(@{ Kind = 'header'; Label = 'No activity recording for this boot - click "Record next boot..." and restart to see which processes used CPU and disk until the desktop appeared.'; Color = '#6B7385' })
    }

    # findings
    if ($recOnly) { $findings.Add(('This recording is from the boot on {0:g} - boot phases and services of that boot are not available, only the recorded activity.' -f ([datetime]$Rec.BootTime))) }
    elseif ($Tl.Matched) {
        $findings.Add(('Desktop ready {0} after the boot started; boot complete (system idle) after {1}.' -f (Format-Sec $Tl.MainPathSec), $(if ($Tl.BootEndT) { Format-Sec $Tl.BootEndT } else { '-' })))
    } elseif ($null -ne $Tl.DesktopT) {
        $findings.Add(('Explorer (desktop) started {0} after the boot - detailed boot phases are not available for this boot.' -f (Format-Sec $Tl.DesktopT)))
    }
    if (-not $recOnly) {
        if ([double]$Tl.FirmwareSec -gt 0) { $findings.Add(('Firmware (UEFI/BIOS) took {0} before Windows started - not included above; check fast boot options in the firmware setup if this is long.' -f (Format-Sec $Tl.FirmwareSec))) }
        if ([double]$Tl.LogonWaitSec -gt 1) { $findings.Add(('{0} were spent at the sign-in screen (entering password/PIN) - that is your time, not a performance problem.' -f (Format-Sec $Tl.LogonWaitSec))) }
        $longest = @($Tl.Durations | Where-Object { $_.Name -notin 'Waiting at sign-in screen', 'Post boot (until idle)' } | Sort-Object Seconds -Descending | Select-Object -First 3)
        if ($longest.Count) { $findings.Add('Longest boot phases: ' + (($longest | ForEach-Object { '{0} {1}' -f $_.Name, (Format-Sec $_.Seconds) }) -join ', ') + '.') }
        $pol = @($Tl.Policies | Where-Object { [double]$_.Duration -ge 3 })
        if ($pol.Count) { $findings.Add('Group Policy processing took ' + (($pol | ForEach-Object { '{0} {1}' -f $_.Name, (Format-Sec $_.Duration) }) -join ', ') + ' (common on company PCs, slower without network to the domain).') }
        $sd = @($Tl.Slowdowns | Sort-Object DegradationMs -Descending | Select-Object -First 4)
        if ($sd.Count) { $findings.Add('Windows reported these as slowing down this boot: ' + (($sd | ForEach-Object { '{0} (+{1:N1} s, {2})' -f $_.Name, ($_.DegradationMs / 1000), $_.Type }) -join ', ') + '.') }
        if ($null -ne $desk) {
            $before = @($Tl.ServiceStarts | Where-Object { [double]$_.T -le [double]$desk } | Sort-Object { [double]$_.T } -Descending)
            if ($before.Count) { $findings.Add(('{0} services started before the desktop appeared; the last ones: {1}.' -f $before.Count, (($before | Select-Object -First 4 | ForEach-Object { '{0} (+{1})' -f $_.DisplayName, (Format-Sec ([double]$_.T)) }) -join ', '))) }
        }
    }
    if ($topCpu.Count) { $findings.Add('Most CPU until the desktop: ' + (($topCpu | ForEach-Object { '{0} {1:N1} CPU-s' -f $(if ($_.Services) { "$($_.Name) ($($_.Services))" } else { $_.Name }), $_.CpuSec }) -join ', ') + '.') }
    if ($secRows.Count) {
        $sc = [double]($secRows | Measure-Object CpuSec -Sum).Sum; $si = [double]($secRows | Measure-Object IoMB -Sum).Sum
        if ($sc -ge 2 -or $si -ge 100) { $findings.Add(('Antivirus / security scanning used {0:N1} CPU-seconds and {1:N0} MB disk I/O until the desktop ({2}).' -f $sc, $si, (($secRows | ForEach-Object { $_.Name }) -join ', '))) }
    }
    if ($Tl.RecordingScheduled) { $findings.Add('A boot activity recording is scheduled - restart Windows (use Restart, not Shut down) and open this view again afterwards.') }

    $title = if ($recOnly) { 'Recorded boot {0:g}' -f ([datetime]$Rec.BootTime) } else { 'Boot on {0:g} - seconds after the boot started{1}' -f ([datetime]$Tl.T0), $(if ($Rec) { ' - with activity recording' } else { '' }) }
    $spec = @{ Title = $title; Rows = $rows.ToArray(); Markers = $markers.ToArray(); XMin = $xmin; XMax = $xmax; Shade = $(if ($null -ne $desk) { @(0.0, [double]$desk) } else { $null }); ShadeTip = 'Until the desktop was ready'; Empty = $null }
    $sortedEvents = @($events | Sort-Object @{ Expression = { if ($null -ne $_.T) { [double]$_.T } else { 1e9 } } }, Type)
    @{ Spec = $spec; Rows = $sortedEvents; Findings = $findings.ToArray() }
}

function Render-BootTimeline {
    param($C, [double]$W = 0, [double]$H = 0)
    $spec = $script:BootTimelineSpec
    if (-not $spec) { $spec = @{ Title = 'Boot timeline'; Rows = @(); Markers = @(); XMin = 0; XMax = 1; Empty = 'Click "Analyze boot & autostart" to build the boot timeline.' } }
    Draw-Swimlanes $C $spec $W $H
}

function Update-BootTimeline {
    $b = $script:BootData
    if (-not $b -or -not $b.Timeline) { Render-BootTimeline $UI.BtTimeline; return }
    try {
        $res = Get-BootTimelineModel $b.Timeline $script:BootRecording ([bool]$UI.BtOnlyDesktop.IsChecked) $UI.BtFilter.Text.Trim()
    } catch {
        Set-Status "Boot timeline could not be built: $($_.Exception.Message)"
        return
    }
    $script:BootTimelineSpec = $res.Spec
    $script:BootTimelineFindings = $res.Findings
    $script:BootTimelineRows = $res.Rows
    Set-GridItems $UI.BtGrid $res.Rows
    $UI.BtSummary.Text = (@($res.Findings) | ForEach-Object { [char]0x2022 + ' ' + $_ }) -join "`n"
    Render-BootTimeline $UI.BtTimeline
    $UI.BtnBtCancel.IsEnabled = [bool]$b.Timeline.RecordingScheduled
}

function Update-BootRecordingList {
    $dir = Join-Path $env:ProgramData 'PerfInspector\BootTraces'
    $files = @()
    if (Test-Path $dir) { $files = @(Get-ChildItem -Path $dir -Filter 'boottrace_*.json' -ErrorAction SilentlyContinue | Sort-Object Name -Descending) }
    $script:BootRecFiles = $files
    $labels = New-Object Collections.Generic.List[string]
    $labels.Add('No activity recording (event log data only)')
    $dates = @()
    foreach ($f in $files) {
        $d = $null
        try { $d = [datetime]::ParseExact(($f.BaseName -replace '^boottrace_', ''), 'yyyyMMdd_HHmmss', [Globalization.CultureInfo]::InvariantCulture) } catch { }
        $dates += $d
        $labels.Add($(if ($d) { 'Recording of the boot on ' + $d.ToString('g') } else { $f.Name }))
    }
    $sel = 0
    if ($script:BootRecPath) {
        for ($i = 0; $i -lt $files.Count; $i++) { if ($files[$i].FullName -eq $script:BootRecPath) { $sel = $i + 1 } }
    } elseif (-not $script:BootRecAutoDone -and $script:BootData) {
        for ($i = 0; $i -lt $files.Count; $i++) {
            if ($dates[$i] -and [Math]::Abs(($dates[$i] - $script:BootData.LastBoot).TotalSeconds) -lt 180) { $sel = $i + 1; break }
        }
        $script:BootRecAutoDone = $true
    }
    $script:SuppressCombo = $true
    try { $UI.BtRecording.ItemsSource = $labels.ToArray(); $UI.BtRecording.SelectedIndex = $sel } finally { $script:SuppressCombo = $false }
    Select-BootRecording $sel -NoRefresh
}

function Select-BootRecording([int]$Index, [switch]$NoRefresh) {
    if ($Index -le 0 -or $Index -gt @($script:BootRecFiles).Count) {
        $script:BootRecording = $null; $script:BootRecPath = $null
    } else {
        $f = $script:BootRecFiles[$Index - 1]
        if ($script:BootRecPath -ne $f.FullName -or -not $script:BootRecording) {
            try {
                $script:BootRecording = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
                $script:BootRecPath = $f.FullName
            } catch {
                Show-ErrorMessage "Could not read the boot recording:`n$($_.Exception.Message)"
                $script:BootRecording = $null; $script:BootRecPath = $null
            }
        }
    }
    if (-not $NoRefresh) { Update-BootTimeline }
}

function Register-BootRecording {
    if (-not (Test-AdminOrWarn 'Recording the next boot')) { return }
    if (-not $script:ScriptPath) { Show-ErrorMessage 'Start PerfInspector from its .ps1 file to use the boot recording.'; return }
    $sec = 180
    $dir = Join-Path $env:ProgramData 'PerfInspector'
    $msg = "PerfInspector will record the CPU and disk activity of every process during the next boot ($sec seconds from the moment Windows starts its services).`n`n" +
    "- A one-time scheduled task 'PerfInspector Boot Trace' is created. It runs as SYSTEM and removes itself after the recording.`n" +
    "- A copy of this script is stored in $dir.`n- The recording itself adds a small load (one measurement per second).`n`n" +
    "Use RESTART (not Shut down): with Fast Startup a shutdown is not a full boot.`n`nSchedule the recording?"
    if (-not (Confirm-Action $msg 'Record next boot')) { return }
    try {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $copy = Join-Path $dir 'PerfInspector.ps1'
        if ($script:ScriptPath -ne $copy) { Copy-Item -LiteralPath $script:ScriptPath -Destination $copy -Force }
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $act = New-ScheduledTaskAction -Execute $psExe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -BootTraceRecord -BootTraceSeconds {1}' -f $copy, $sec)
        $trg = New-ScheduledTaskTrigger -AtStartup
        $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
        Register-ScheduledTask -TaskName 'PerfInspector Boot Trace' -TaskPath '\PerfInspector\' -Action $act -Trigger $trg -Principal $pr -Settings $set -Force -ErrorAction Stop | Out-Null
        $UI.BtnBtCancel.IsEnabled = $true
        if ($script:BootData) { $script:BootData.Timeline.RecordingScheduled = $true; Update-BootTimeline }
        $script:BootRecAutoDone = $false; $script:BootRecPath = $null
        if (Confirm-Action "The recording of the next boot is scheduled.`n`nSave your work first. Restart Windows now?" 'Restart now?') { Restart-Computer }
        else { Set-Status 'Boot recording scheduled - it runs at the next restart.' }
    } catch { Show-ErrorMessage "Could not schedule the boot recording:`n$($_.Exception.Message)" }
}

function Unregister-BootRecording {
    if (-not (Test-AdminOrWarn 'Cancelling the boot recording')) { return }
    try {
        Unregister-ScheduledTask -TaskName 'PerfInspector Boot Trace' -TaskPath '\PerfInspector\' -Confirm:$false -ErrorAction Stop
        Set-Status 'Scheduled boot recording cancelled.'
    } catch { Set-Status "No scheduled boot recording found ($($_.Exception.Message))." }
    $UI.BtnBtCancel.IsEnabled = $false
    if ($script:BootData) { $script:BootData.Timeline.RecordingScheduled = $false; Update-BootTimeline }
}

# ---------------------------------------------------------------- report
function Add-ExtraReportSections($sb) {
    $enc = { param($t) [Net.WebUtility]::HtmlEncode([string]$t) }
    if ($script:CurrentTrace -and $script:TraceModel) {
        $t = $script:CurrentTrace; $m = $script:TraceModel
        [void]$sb.Append("<h2>App start trace - $(& $enc $t.App)</h2><p class='muted'>Recorded $(& $enc ([datetime]$t.Created).ToString('g')) - $(& $enc (Get-TraceDurationText $t))</p>")
        [void]$sb.Append((Get-ChartImgTag 'Render-TraceOverview' 1100 262))
        [void]$sb.Append((Get-ChartImgTag 'Render-TraceTimeline' 1100 0))
        [void]$sb.Append('<h3>What slowed the start down</h3><ul>' + ((@($m.Findings) | ForEach-Object { "<li><b>$(& $enc $_.Title)</b> - $(& $enc $_.Text)</li>" }) -join '') + '</ul>')
        [void]$sb.Append('<h3>Processes</h3>' + (ConvertTo-HtmlTable @($m.Rows | Sort-Object Score -Descending) @('Role', 'Name', 'PID', 'Category', 'StartedSec', 'AvgCpu', 'CpuSec', 'IoMB', 'PeakRamMB', 'Services', 'Path')))
    }
    if ($script:BootData -and $script:BootTimelineSpec) {
        [void]$sb.Append('<h2>Boot timeline (until desktop)</h2>')
        [void]$sb.Append((Get-ChartImgTag 'Render-BootTimeline' 1100 0))
        [void]$sb.Append('<ul>' + ((@($script:BootTimelineFindings) | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join '') + '</ul>')
        [void]$sb.Append((ConvertTo-HtmlTable @($script:BootTimelineRows) @('T', 'Type', 'Name', 'DurationSec', 'BeforeDesktop', 'Details')))
    }
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
        if ($UI.MainTabs.SelectedIndex -eq 5 -and -not $script:BootData -and -not $script:BootBusy) { Start-BootAnalysis }
    })

# Live monitor
$script:LiveTimer = New-Object Windows.Threading.DispatcherTimer
$script:LiveTimer.Interval = [TimeSpan]::FromSeconds(5)
$script:LiveTimer.Add_Tick({ if ($UI.LiveAuto.IsChecked -and -not $script:TestRunning -and -not $script:Manual -and -not $script:TraceRunning) { Start-LiveRefresh } })
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
            0 { Export-Items $script:BootTimelineRows 'BootTimeline' @('T', 'Type', 'Name', 'DurationSec', 'BeforeDesktop', 'Details') }
            1 { Export-Items $b.Boots 'BootHistory' @('Date', 'BootSec', 'MainPathSec', 'PostBootSec', 'Rating') }
            2 { Export-Items $b.StartupApps 'StartupApps' @('EnabledText', 'Name', 'Publisher', 'Description', 'Location', 'Scope', 'Running', 'StartedAfterBootSec', 'Delay', 'Command', 'ExePath') }
            3 { Export-Items $b.Services 'ServicesAtBoot' @('DisplayName', 'Name', 'StartType', 'State', 'StartedAfterBootSec', 'BootDelayMs', 'Recommendation', 'PathName') }
            4 { Export-Items $b.Degradation 'BootSlowdowns' @('Date', 'EventId', 'Type', 'Name', 'TotalMs', 'DegradationMs', 'File') }
            5 { Export-Items $b.Issues 'ServiceErrors' @('Date', 'EventId', 'Service', 'Message') }
        }
    })
$UI.BtnBootChartPng.Add_Click({
        switch ($UI.BootTabs.SelectedIndex) {
            0 { Save-ChartPng 'Render-BootTimeline' 'BootTimeline' $UI.BtTimeline }
            1 { Save-ChartPng 'Render-BootChart' 'BootHistory' $UI.BootChart }
            2 { Save-ChartPng 'Render-AppBootChart' 'StartupApps' $UI.AppBootChart }
            3 { Save-ChartPng 'Render-SvcBootChart' 'ServicesAtBoot' $UI.SvcBootChart }
            default { Show-Info 'This view has no chart. Select "Boot timeline", "Boot history", "Startup apps" or "Services at boot".' }
        }
    })
$UI.BootChart.Add_SizeChanged({ Render-BootChart $UI.BootChart })
$UI.AppBootChart.Add_SizeChanged({ Render-AppBootChart $UI.AppBootChart })
$UI.SvcBootChart.Add_SizeChanged({ Render-SvcBootChart $UI.SvcBootChart })

# Start trace
$script:TrHints = @(
    'Launch mode: PerfInspector records the background for a moment, starts the app, follows every process it starts and keeps recording until the main window is visible. Close the app before you start the trace (cold start).',
    'Wait mode: click "Start trace", then start the app yourself the usual way (Start menu, taskbar, double-click a document). Recording runs before and after your click. Enter the process name of the app (e.g. winword, chrome, Teams).'
)
$UI.TrHint.Text = $script:TrHints[0]
$UI.TrMode.Add_SelectionChanged({ $UI.TrHint.Text = $script:TrHints[[Math]::Max(0, $UI.TrMode.SelectedIndex)] })
$UI.BtnTrBrowse.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Applications and shortcuts (*.exe;*.lnk;*.bat;*.cmd)|*.exe;*.lnk;*.bat;*.cmd|All files (*.*)|*.*'
        $dlg.DereferenceLinks = $false
        if ($dlg.ShowDialog($script:Window)) {
            $UI.TrExe.Text = $dlg.FileName
            $tn = [IO.Path]::GetFileNameWithoutExtension($dlg.FileName)
            if ($dlg.FileName -like '*.lnk') {
                try { $t = (New-Object -ComObject WScript.Shell).CreateShortcut($dlg.FileName).TargetPath; if ($t) { $tn = [IO.Path]::GetFileNameWithoutExtension($t) } } catch { }
            }
            $UI.TrWatch.Text = $tn
        }
    })
$UI.BtnTrStart.Add_Click({ Start-StartTrace })
$UI.BtnTrStop.Add_Click({ $script:Sync.Cancel = $true; $script:Sync.TraceStop = $true; Set-Status 'Stopping the trace ...' })
$UI.TrAppFilter.Add_SelectionChanged({ if (-not $script:SuppressCombo) { Update-TraceHistory } })
$UI.TrHistory.Add_SelectionChanged({
        if ($script:SuppressCombo) { return }
        $i = $UI.TrHistory.SelectedIndex
        if ($i -ge 0 -and $i -lt @($script:TraceHistList).Count) { Show-Trace $script:TraceHistList[$i] }
    })
$UI.TrFocus.Add_SelectionChanged({ if (-not $script:SuppressCombo) { Update-TraceFocusView } })
$UI.BtnTrSave.Add_Click({ Save-TraceFile })
$UI.BtnTrLoad.Add_Click({ Open-TraceFile })
$UI.BtnTrExport.Add_Click({ Export-Items @($UI.TrGrid.Items) 'StartTrace' @('Role', 'Name', 'PID', 'Category', 'StartedSec', 'AvgCpu', 'CpuSec', 'IoMB', 'PeakRamMB', 'Services', 'Path') })
$UI.BtnTrPng.Add_Click({ Save-TraceCharts })
$UI.TrOverview.Add_SizeChanged({ if (-not $script:TraceRunning) { Render-TraceOverview $UI.TrOverview } })
$UI.TrTimeline.Add_SizeChanged({ param($sender, $e) if ($e.WidthChanged -and -not $script:TraceRunning) { Render-TraceTimeline $UI.TrTimeline } })
Show-TraceFindings @()

# Boot timeline
$UI.BtRecording.Add_SelectionChanged({ if (-not $script:SuppressCombo) { Select-BootRecording $UI.BtRecording.SelectedIndex } })
$UI.BtOnlyDesktop.Add_Click({ Update-BootTimeline })
$UI.BtFilter.Add_TextChanged({ Update-BootTimeline })
$UI.BtnBtRecord.Add_Click({ Register-BootRecording })
$UI.BtnBtCancel.Add_Click({ Unregister-BootRecording })
$UI.BtTimeline.Add_SizeChanged({ param($sender, $e) if ($e.WidthChanged) { Render-BootTimeline $UI.BtTimeline } })

# Job pump + startup
$script:JobTimer = New-Object Windows.Threading.DispatcherTimer
$script:JobTimer.Interval = [TimeSpan]::FromMilliseconds(200)
$script:JobTimer.Add_Tick({ Invoke-JobPump })
$script:JobTimer.Start()

$script:Window.Add_ContentRendered({
        Import-Baseline
        Render-StartChart $UI.StartChart
        Render-TraceOverview $UI.TrOverview
        Render-TraceTimeline $UI.TrTimeline
        Render-BootTimeline $UI.BtTimeline
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

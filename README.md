# PerfInspector

**A modern GUI performance analyzer for Windows - written in pure PowerShell.**

PerfInspector measures how applications, services and the boot process perform on a Windows machine. It shows what runs heavier in the background than usual, measures application start times, explains which services can be turned off, and analyzes boot time and autostart entries. Every result can be exported.

- Single file (`PerfInspector.ps1`), no modules, no installation, no internet connection required
- Dark WPF interface with live charts
- Works with Windows PowerShell 5.1 and PowerShell 7+

---
<img width="1423" height="886" alt="image" src="https://github.com/user-attachments/assets/5452913d-e9ad-4afb-862d-c073ed882bfc" />

# PerfInspector

**A modern GUI performance analyzer for Windows - written in pure PowerShell.**

PerfInspector measures how applications, services and the boot process perform on a Windows machine. It shows what runs heavier in the background than usual, measures application start times, **traces an app start live to show what really happens in the background and why it is slow**, explains which services can be turned off, and shows a **detailed boot timeline up to the desktop**. Every result can be exported.

- Single file (`PerfInspector.ps1`), no modules, no installation, no internet connection required
- Dark WPF interface with live charts
- Works with Windows PowerShell 5.1 and PowerShell 7+

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Starting the tool](#starting-the-tool)
- [Usage](#usage)
  - [Live Monitor](#1-live-monitor)
  - [Services](#2-services)
  - [Recommendations](#3-recommendations)
  - [App Start Test](#4-app-start-test)
  - [Start Trace - what happens when an app starts](#5-start-trace--what-happens-when-an-app-starts)
  - [Boot & Autostart](#6-boot--autostart)
  - [Boot timeline until the desktop](#boot-timeline-until-the-desktop)
  - [Exporting results](#7-exporting-results)
- [Administrator vs. limited mode](#administrator-vs-limited-mode)
- [Where data is stored](#where-data-is-stored)
- [How measurements work](#how-measurements-work)
- [Safety](#safety)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Features

| Area | What it does |
|---|---|
| **Live Monitor** | CPU, RAM and disk/network I/O of every process, live CPU/RAM chart, baseline recording and "above usual" detection |
| **Services** | All services with resource usage, impact rating, description, executable, account, dependencies; start / stop / restart; change startup type with automatic backup |
| **Recommendations** | Which services are safe to disable, can be set to Manual, depend on your usage, or are third-party auto-start services worth reviewing - each with a reason |
| **App Start Test** | Automatic multi-run launch test (process created → ready for input → main window visible) and a manual stopwatch mode; stacked time chart and statistics (min / max / avg / median / std. deviation / cold vs. warm start) |
| **Start Trace** | Live trace of an app start: the chain of processes the app starts, every program/service busy in the background (antivirus, search indexing, Windows Update, cloud sync, updaters ...), services started on demand, a "where did the time go" breakdown and plain-language findings on what slowed the start down. Filter to one app or one process. |
| **Boot timeline** | Boot phases until the desktop (drivers, devices, services, logon, Explorer), services and programs started with their exact time, Group Policy, reported slowdowns, and an optional recording of the CPU/disk activity of every process during the next boot |
| **Boot & Autostart** | Boot duration history, boot slowdown events (apps, drivers, services), all autostart entries (registry, startup folders, scheduled tasks, Store apps) with enable/disable, services at boot with their start time after boot, service errors since boot |
| **Export** | Every table to CSV (Excel), JSON or HTML; every chart to PNG; traces as JSON (re-open later); full HTML report with all charts embedded |

## Requirements

- Windows 10 or Windows 11 (Windows Server 2016+ should work as well)
- Windows PowerShell 5.1 (pre-installed) **or** PowerShell 7+
- .NET Framework 4.5+ (pre-installed on Windows 10/11)
- **Administrator rights recommended** - see [Administrator vs. limited mode](#administrator-vs-limited-mode)

## Installation

1. Download `PerfInspector.ps1` from this repository (or clone it):
   ```powershell
   git clone https://github.com/<your-user>/PerfInspector.git
   cd PerfInspector
   ```
2. If you downloaded the file through a browser, remove the "downloaded from the internet" mark:
   ```powershell
   Unblock-File .\PerfInspector.ps1
   ```

No further installation is needed.

## Starting the tool

**Recommended (as Administrator):** open PowerShell with *Run as administrator*, then:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\PerfInspector.ps1
```

With PowerShell 7:

```powershell
pwsh.exe -ExecutionPolicy Bypass -File .\PerfInspector.ps1
```

**Hide the console window** while the GUI is open:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\PerfInspector.ps1 -HideConsole
```

| Parameter | Description |
|---|---|
| `-HideConsole` | Hides the PowerShell console window while PerfInspector is running |
| `-BootTraceRecord` | Internal - used by the scheduled task created with *Record next boot...*. Do not use it manually. |

If you start the tool without administrator rights, the header shows **LIMITED MODE** and a **Restart as administrator** button.

> **Tip:** Create a desktop shortcut with the target
> `powershell.exe -ExecutionPolicy Bypass -File "C:\Tools\PerfInspector.ps1" -HideConsole`
> and enable *Advanced → Run as administrator* in the shortcut properties.

---

## Usage

The navigation is on the left. The status bar at the bottom shows what the tool is currently doing.

### 1. Live Monitor

Shows the current state of the machine.

- **Cards:** CPU usage, memory, number of processes, running services, uptime
- **Chart:** CPU and memory over the last 60 samples
- **Process table:** name, PID, CPU %, memory, disk/network I/O, threads, handles, usage status, hosted services, path

**Controls**

| Control | Function |
|---|---|
| Search | Filters by process name, path, hosted service or PID |
| Only above usual / high usage | Shows only flagged processes |
| Auto refresh + interval | Refreshes every 2 / 5 / 10 / 30 seconds |
| Record baseline (30 s) | Records the normal resource usage of this PC (see below) |
| Clear baseline | Deletes the baseline; fixed thresholds are used again |
| End process | Terminates the selected process(es) after confirmation |
| Export... | Exports the current table |

**Detecting "more than usual" with a baseline**

1. Bring the PC into its normal state (no installs, updates or heavy tasks running).
2. Click **Record baseline (30 s)**. The tool takes 10 samples over about 30 seconds.
3. From now on every process and service is compared with the baseline. Rows that use clearly more CPU, RAM or I/O than usual are shown in **red** with a status like
   `! Above usual: CPU 12.0% (usual 1.0%)`.

Without a baseline, fixed thresholds are used (CPU ≥ 25 %, RAM ≥ 2 GB per app / 500 MB per service, I/O ≥ 20 MB/s).

> Processes with several instances (e.g. `chrome`) are compared as one total per application.

### 2. Services

Lists every Windows service.

| Column | Meaning |
|---|---|
| State / Startup type | Running/Stopped; Automatic, Automatic (Delayed), Manual, Disabled |
| CPU % / Memory / I/O | Usage of the process hosting the service |
| Impact | Low / Medium / High; *(shared)* = the service runs together with other services in one `svchost` process |
| Usage status | Comparison with baseline or thresholds |
| Recommendation | See [Recommendations](#3-recommendations) |

**Views:** All services, Running, Automatic start, Above usual / high usage, Third-party, With recommendation.

**Details panel (right):** select a service to see its recommendation and reason, description, executable, account, resource usage, the services it depends on and the services that depend on it.

**Actions** (administrator rights required):

- **Start / Stop / Restart** - running dependent services are listed before they are stopped
- **Set startup type** - Automatic, Automatic (Delayed), Manual or Disabled
- **Restore original startup types** - reverts every startup-type change made with PerfInspector

### 3. Recommendations

A prioritized list of services you may want to change.

| Recommendation | Meaning | Suggested action |
|---|---|---|
| **Investigate (above usual)** | Currently uses more resources than usual | Restart the service or check the related application |
| **Safe to disable** | Not needed on typical PCs (e.g. telemetry, Retail Demo, Fax) | Disable |
| **Set to Manual** | Only needed occasionally; Windows starts it on demand | Set to Manual |
| **Conditional** | Depends on whether you use the feature (e.g. Bluetooth, printing, Xbox, Windows Search) | Read the reason, then decide |
| **Review (third-party)** | Non-Windows service that starts with Windows | Check the publisher; set to Manual if not needed permanently |

The summary shows how many services are in each group and how much RAM could be freed.

**Buttons:** *Set selected to Manual*, *Disable selected*, *Restore original startup types*, *Export*.
**Double-click** a row to open the service in the Services view.

> Core Windows services are marked **Keep (critical)** and are protected - PerfInspector refuses to disable them or set them to Manual.

### 4. App Start Test

Measures how long applications take to start.

#### Automatic launch test

1. Click **Browse...** and choose an `.exe`, `.lnk` shortcut, `.bat` or `.cmd`
   (Store apps: enter `shell:AppsFolder\<AppID>` and a process name to watch).
2. Optional: arguments, number of **Runs** (1-100), **Pause** between runs, **Timeout**.
3. **Process name(s) to watch** - needed for launchers that start a different process (e.g. Teams, Store apps, some shortcuts). Several names can be separated by `,` or `;`.
4. **Close the application after each run** - keep enabled to measure cold starts.
5. Click **Run test**. Results appear live in the chart and table. **Cancel** stops after the current step.

Measured per run:

| Value | Meaning |
|---|---|
| Process (ms) | Time until the process was created |
| Input idle (ms) | Time until the app was ready to process input |
| Window (ms) | Time until the main window was visible |
| RAM (MB) / CPU time (ms) | Memory and CPU time used at that moment |

> Close the application before testing. If it is already running, single-instance apps may hand the launch over to the running instance and the results are not meaningful. The tool warns you in that case.

#### Manual measurement

Use this to measure an app the way you normally start it (Start menu, taskbar, desktop):

1. Optional: enter the **process name** (e.g. `winword`, `chrome`).
2. Click **Start stopwatch**.
3. Start the application yourself.
4. Click **App is ready** as soon as you can work with it.
   Optional: *Stop automatically when the main window appears*.

If a process name was given, process start and main window are detected automatically and shown as separate phases.

#### Chart and statistics

- **Stacked bar chart** per run: process created → ready for input → main window → user confirmed ready; dashed line = average
- **Statistics** per application and mode: successful runs, min/max, average, median, standard deviation, first run (cold) vs. following runs (warm), average RAM
- **Export results...**, **Save chart as PNG...**, **Clear results**

### 5. Start Trace - what happens when an app starts

Records **everything** that happens on the machine while an application starts - not only the app itself - and explains why the start is slow.

#### Recording a trace

| Mode | How it works |
|---|---|
| **Launch the app for me** | Choose the app with **Browse...** and click **Start trace**. PerfInspector records the background for ~1.5 s, starts the app, follows every process it starts and keeps recording until the main window is visible (plus *Keep recording after window*). |
| **Wait until I start it myself** | Enter the **process name** (e.g. `winword`, `chrome`, `Teams`) or choose the .exe, click **Start trace** and then start the app the way you normally do - Start menu, taskbar, double-click on a document. The tool waits up to 5 minutes. |

Options: **Timeout** (max. wait for the window), **Keep recording after window**, **Sample every** 250 / 500 / 1000 ms. **Stop** ends the recording.

> Close the app before tracing - otherwise many apps only hand the start to the running instance. Leave PerfInspector's Live Monitor alone during the trace (it pauses automatically).

While recording, the timeline and the chain update **live**.

#### What you see

**1. Start chain (top graphic)** - the whole start in one picture:

```
[ Launch 0 s ] --+45 ms--> [ Process created ] --+0,8 s--> [ Ready for input ] --+1,5 s--> [ Window visible +2,3 s ]
App processes:       myapp +0,02 s · myapp-updater +1,10 s
Busy in background:  MsMpEng · Security scan · 18% CPU · 40 MB     SearchIndexer · Search indexing · 5% CPU
Services started:    Spooler +0,40 s
Where did the time go?  [Security scanning 35% | App working 30% | Reading from disk 10% | Waiting 25%]
```

The **Where did the time go** bar splits the start time into:

| Segment | Meaning |
|---|---|
| Launching (Windows) | From the click until the process exists |
| Security scanning | Antivirus / Defender was busy scanning |
| Busy CPU (other processes) | The CPU was > 85 % busy with other programs |
| App working (CPU) | The app itself was computing (its normal start work, add-ins, plugins) |
| Reading from disk | Disk queue / hard page faults / app reading files (cold start) |
| Waiting (network / locks / idle) | Nothing was busy - the app waited for network, sign-in, licence check, network drives, locked files ... |

**2. Timeline (swim lanes)** - one lane per process with its CPU usage over time:

- *Whole system*: total CPU and disk throughput
- *The app and the processes it started* (blue)
- *Busy in the background*: the programs and services that were active at the same time, coloured by category - **Security scan** (red), **Search indexing**, **Windows Update**, **Telemetry**, **Prefetch (SysMain)**, **Cloud sync**, **Updater**, **Windows system**, **Other program**
- *Services changed state*: services Windows started or stopped during the start
- Dashed lines mark launch, process created, ready for input and window visible; the shaded area is the start phase. Hover a lane for details (PID, services, path, CPU time, I/O).

**3. What slowed the start down (right panel)** - findings in plain language, e.g. *Antivirus / security scanning slowed the start*, *The disk was the bottleneck*, *The app was mostly waiting*, *An updater ran during the start*, *Windows started services during the start*, *Background maintenance was running*, *Low free memory* - each with the measured numbers and what you can do.

**4. Process table** - role (App / Child process / Background), category, start time, average CPU, CPU time, I/O, peak RAM, services and path.

#### Filtering to one app

| Control | Function |
|---|---|
| **App** | Shows only the traces of one application in the trace list |
| **Trace** | Switch between all traces recorded in this session (newest first) - compare a cold and a warm start |
| **Focus** | *Everything*, *Only the app and its processes*, *Only background activity*, or **one single process** - filters the timeline and the table |

**Save trace... / Open trace...** store a trace as JSON and load it later (also on another PC). **Export table...** and **Save charts as PNG...** export the results.

> Measuring uses WMI. Its host process (`WmiPrvSE`) and PerfInspector itself are shown as *Measurement (PerfInspector)* and excluded from the analysis.

### 6. Boot & Autostart

Click **Analyze boot & autostart** (runs automatically the first time you open the tab).

**Cards:** last full boot, last start incl. Fast Startup, last boot duration, average boot, number of autostart entries, Fast Startup state.

| Sub-tab | Content |
|---|---|
| **Boot timeline (until desktop)** | See [Boot timeline until the desktop](#boot-timeline-until-the-desktop) |
| **Boot history** | Duration of the last recorded boots, split into *main path* (until desktop) and *post boot* (until the system is idle), with a rating |
| **Startup apps** | All autostart entries: status, publisher, location (Registry Run/RunOnce, startup folders, scheduled tasks at boot/logon, Store apps), running yes/no, seconds after boot the process started, command. Chart shows the start order. |
| **Services at boot** | Automatic and trigger-started services with the time after boot they started and the boot delay Windows reported for them. Red bar = reported boot delay, purple = delayed start. |
| **Boot slowdowns** | Applications, drivers and services Windows logged as slowing down the boot |
| **Service errors since boot** | Services that failed, timed out or crashed |

**Enable / disable selected startup app** - works like the Startup tab in Task Manager: the entry is not deleted and can be re-enabled at any time. Takes effect at the next sign-in.

#### Boot timeline until the desktop

The first sub-tab shows the boot of this PC second by second - from the start of Windows until the desktop is ready:

| Lane | Content |
|---|---|
| **Windows boot phases** | Boot loader, boot drivers, kernel init, devices, session init (services start), logon processing, waiting at the sign-in screen, Explorer / desktop init, post boot - as reported by Windows (needs administrator rights) |
| **Group Policy** | Computer and user policy processing time (company PCs) |
| **Services started** | One line per service at the moment it started - **red** = Windows reported it as slowing down the boot |
| **Programs started** | One line per program (green = user session, grey = system) |
| **Activity recorded during this boot** | Only with a boot recording: CPU and disk of the whole system and one lane per process / service host that was busy - this shows **who was doing what until the desktop appeared** |

Dashed markers: *Winlogon started*, *Explorer started*, *Desktop ready*, *Boot complete (idle)*. The summary above the chart lists the key facts: time until desktop, firmware (UEFI/BIOS) time, time spent at the sign-in screen, longest phases, Group Policy, reported slowdowns, services before the desktop, top CPU users and antivirus activity during the boot. The table lists every event chronologically with *Before desktop* yes/no.

**Options:** *Only until desktop* (zoom to the time until the desktop), *Filter* (show only services/programs containing a text).

**Recording the next boot** (administrator):

1. Click **Record next boot...** and confirm. A one-time scheduled task *PerfInspector Boot Trace* (runs as SYSTEM) is created and the script is copied to `C:\ProgramData\PerfInspector`.
2. **Restart** Windows (not *Shut down* - with Fast Startup a shutdown is no full boot).
3. The recorder measures every process once per second for 180 s, saves the result and removes the task itself.
4. Open PerfInspector → Boot & Autostart. The recording of the current boot is selected automatically under **Activity recording**; older recordings can be selected there too.

*Cancel scheduled recording* removes the task if you change your mind.

> Without a recording the timeline is built from the Windows event logs only (phases, service start times, programs that are still running).

Options: **Include Microsoft scheduled tasks**, **Export current view...**, **Save chart as PNG...**

### 7. Exporting results

| What | How | Formats |
|---|---|---|
| Any table | *Export...* button of the view | CSV (Excel, uses your regional list separator), JSON, HTML |
| Any chart | *Save chart as PNG...* / *Save charts as PNG...* | PNG |
| Start trace | *Save trace...* | JSON (can be opened again with *Open trace...*) |
| Everything | **Full report (HTML)** in the header | One HTML file with system info, live snapshot, flagged processes and services, recommendations, start tests, the current start trace (chain, timeline, findings), boot analysis and boot timeline - all charts embedded |

Tip: run the boot analysis and an app start test before creating the full report so that all sections are filled.

---

## Administrator vs. limited mode

| Feature | Limited mode | Administrator |
|---|:---:|:---:|
| Live monitor, processes, services list | ✅ | ✅ |
| Recommendations | ✅ | ✅ |
| App start tests | ✅ | ✅ |
| Startup apps (current user) incl. enable/disable | ✅ | ✅ |
| Boot history, boot phases and boot slowdown events | ❌ | ✅ |
| Start trace | ✅ | ✅ (more process details) |
| Record next boot | ❌ | ✅ |
| Start / stop services, change startup type | ❌ | ✅ |
| Enable/disable startup entries for all users (HKLM) | ❌ | ✅ |
| Paths of processes owned by other users | partly | ✅ |

## Where data is stored

All data is stored in `%LOCALAPPDATA%\PerfInspector`:

| File | Content |
|---|---|
| `baseline.json` | Recorded baseline |
| `service-changes.json` | Original startup type of every service changed with PerfInspector (used by *Restore*) |
| `service-changes_restored_<date>.json` | Archived change log after a restore |

Boot recordings are stored in `C:\ProgramData\PerfInspector\BootTraces` (`boottrace_<boot time>.json`, plus `recorder.log`). The copy of the script used by the boot recording is `C:\ProgramData\PerfInspector\PerfInspector.ps1`.

Deleting the folders resets the tool. Exports and saved traces are stored wherever you choose.

## How measurements work

| Value | Source |
|---|---|
| Process CPU / RAM / I/O | `Win32_PerfFormattedData_PerfProc_Process` (CPU normalized to all logical processors, RAM = private working set) |
| Service usage | Usage of the hosting process (`Win32_Service.ProcessId`) |
| App start times | `Process.Start`, `WaitForInputIdle`, `MainWindowHandle` with a high-resolution stopwatch |
| Boot duration and slowdowns | Event log *Microsoft-Windows-Diagnostics-Performance/Operational*, events 100-110 |
| Service start after boot | *System* log, Service Control Manager event 7036 (first state change after boot) |
| Last start with Fast Startup | *System* log, Kernel-Boot event 27 |
| Startup app start after boot | Creation time of the running process |
| Start trace / boot recording | `Win32_PerfRawData_PerfProc_Process` sampled every 250-1000 ms (CPU, I/O, parent process), physical disk and memory counters, process creation times, Service Control Manager events |
| Boot phases | Fields of Diagnostics-Performance event 100 (boot loader, PnP, session init, Winlogon, Explorer, sign-in wait ...) |
| Firmware time | Registry value `FwPOSTTime` |

**Notes**

- Windows does not report power consumption per application. CPU and disk/network activity are used as indicators for background load.
- With **Fast Startup** enabled, *Shut down* + power on is a hybrid boot, not a full boot. Use **Restart** when you want to measure a real boot.
- Windows writes the boot diagnostics event a few minutes after boot; right after a restart it may not be there yet.

## Safety

- Every change asks for confirmation first.
- Core Windows services cannot be disabled or set to Manual with this tool.
- Every service startup-type change is saved and can be reverted with **Restore original startup types**.
- Startup apps are only disabled, never deleted.
- The tool sends no data anywhere; everything stays on your machine.

> Changing services can affect Windows features. Read the reason for each recommendation, change one thing at a time, and test before changing more.

---

## Troubleshooting

**"Running scripts is disabled on this system"**
Start the script with `-ExecutionPolicy Bypass` as shown above, or allow local scripts for your user:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
Unblock-File .\PerfInspector.ps1
```

**The window does not open / closes immediately**
Start it from an open PowerShell window (not by double-click) so error messages stay visible, and do not use `-HideConsole` while troubleshooting.

**Boot history shows "n/a"**
Run as administrator. If it is still empty, the *Diagnostics-Performance* log may be disabled: Event Viewer → Applications and Services Logs → Microsoft → Windows → Diagnostics-Performance → Operational → *Enable Log*. Then restart the PC.

**App start test shows "Timeout - no window detected"**
The started file probably launches a different process. Enter that process name under *Process name(s) to watch* (find it in the Live Monitor while the app is running).

**"Startup type: FAILED - access denied"**
Some services are protected by Windows and cannot be changed even as administrator.

**Start trace shows "No main window within the timeout"**
The window belongs to another process (launcher, Store app). Enter that process name under *Process name(s)*.

**Boot timeline shows no phases**
Run as administrator. Windows writes the boot report a few minutes after the boot, and not at all after a Fast Startup shutdown - restart and wait a few minutes.

**The boot recording was not created**
Check `C:\ProgramData\PerfInspector\BootTraces\recorder.log` and the task in Task Scheduler (folder *PerfInspector*). Use *Restart*, not *Shut down*.

**CSV opens in one column in Excel**
CSV files use your regional list separator. Open them in Excel via *Data → From Text/CSV* if your Excel uses a different separator.

**Values show 0 % CPU right after start**
Windows performance counters need two samples. The values are correct from the second refresh on.

## FAQ

**Does PerfInspector change anything automatically?**
No. It only reads data until you click an action button and confirm.

**Does it run on Windows Server?**
Yes, as long as the desktop experience (WPF) is installed. Server Core is not supported.

**Can I run it remotely?**
No. It analyzes the machine it runs on. Copy the script to the target machine and start it there.

**How do I undo service changes?**
Click **Restore original startup types** on the Services or Recommendations page.

**How do I undo a disabled startup app?**
Select it in *Boot & Autostart → Startup apps* and click **Enable / disable selected startup app** again, or re-enable it in Task Manager.

---

## License

Add the license of your choice here (for example MIT) and include a `LICENSE` file in the repository.

---



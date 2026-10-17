# PerfInspector

**A modern GUI performance analyzer for Windows - written in pure PowerShell.**

PerfInspector measures how applications, services and the boot process perform on a Windows machine. It shows what runs heavier in the background than usual, measures application start times, explains which services can be turned off, and analyzes boot time and autostart entries. Every result can be exported.

- Single file (`PerfInspector.ps1`), no modules, no installation, no internet connection required
- Dark WPF interface with live charts
- Works with Windows PowerShell 5.1 and PowerShell 7+

---
<img width="1423" height="886" alt="image" src="https://github.com/user-attachments/assets/5452913d-e9ad-4afb-862d-c073ed882bfc" />

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
  - [Boot & Autostart](#5-boot--autostart)
  - [Exporting results](#6-exporting-results)
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
| **Boot & Autostart** | Boot duration history, boot slowdown events (apps, drivers, services), all autostart entries (registry, startup folders, scheduled tasks, Store apps) with enable/disable, services at boot with their start time after boot, service errors since boot |
| **Export** | Every table to CSV (Excel), JSON or HTML; every chart to PNG; full HTML report with all charts embedded |

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

### 5. Boot & Autostart

Click **Analyze boot & autostart** (runs automatically the first time you open the tab).

**Cards:** last full boot, last start incl. Fast Startup, last boot duration, average boot, number of autostart entries, Fast Startup state.

| Sub-tab | Content |
|---|---|
| **Boot history** | Duration of the last recorded boots, split into *main path* (until desktop) and *post boot* (until the system is idle), with a rating |
| **Startup apps** | All autostart entries: status, publisher, location (Registry Run/RunOnce, startup folders, scheduled tasks at boot/logon, Store apps), running yes/no, seconds after boot the process started, command. Chart shows the start order. |
| **Services at boot** | Automatic and trigger-started services with the time after boot they started and the boot delay Windows reported for them. Red bar = reported boot delay, purple = delayed start. |
| **Boot slowdowns** | Applications, drivers and services Windows logged as slowing down the boot |
| **Service errors since boot** | Services that failed, timed out or crashed |

**Enable / disable selected startup app** - works like the Startup tab in Task Manager: the entry is not deleted and can be re-enabled at any time. Takes effect at the next sign-in.

Options: **Include Microsoft scheduled tasks**, **Export current view...**, **Save chart as PNG...**

### 6. Exporting results

| What | How | Formats |
|---|---|---|
| Any table | *Export...* button of the view | CSV (Excel, uses your regional list separator), JSON, HTML |
| Any chart | *Save chart as PNG...* | PNG |
| Everything | **Full report (HTML)** in the header | One HTML file with system info, live snapshot, flagged processes and services, recommendations, start tests and boot analysis - all charts embedded |

Tip: run the boot analysis and an app start test before creating the full report so that all sections are filled.

---

## Administrator vs. limited mode

| Feature | Limited mode | Administrator |
|---|:---:|:---:|
| Live monitor, processes, services list | ✅ | ✅ |
| Recommendations | ✅ | ✅ |
| App start tests | ✅ | ✅ |
| Startup apps (current user) incl. enable/disable | ✅ | ✅ |
| Boot history and boot slowdown events | ❌ | ✅ |
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

Deleting the folder resets the tool. Exports are saved wherever you choose.

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


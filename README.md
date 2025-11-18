# SMB-Performance-Analyser
A PowerShell script for benchmarking SMB file copy performance, capturing network health, VPN/client context, and environment metadata—all logged to a CSV for easy analysis and sharing.


# Overview
This script helps you measure SMB file copy throughput (download and upload) between your client and a remote share, while logging live network health (ping), VPN/client detection, and system details. Results are saved to a CSV for easy comparison across scenarios (different VPNs, connectors, client locations, file sizes, etc.).


# Features
- Download & Upload tests with configurable runs and wait intervals
- Live network health (ping stats) captured during each copy
- VPN/client detection (Cloudflare WARP, WireGuard, Entra Private Access)
- Environment logging: OS version, power plan, WAN IP, NIC details
- Interactive prompts for client location and connector metadata
- Flexible CSV output for downstream analysis


# Quick Start
1. Prepare your test file:

   - Place your ISO on both the remote SMB share and your local folder. Customise logfile as needed.
   - Default paths:
        - Remote: \\10.10.5.7\MyShare\test_file.iso
        - Local: C:\Software\copy\test_file.iso
        - CSV: C:\Software\copy\perf_runs_v1.csv

2. Run the script:
    .\ComparativeSMBPerfScript_v1.ps1

3. View results
    - Console output shows per-run stats and network health.
    - CSV log saved to C:\Software\copy\perf_runs_v1.csv (customisable).   


# Parameters
| Parameter                | Description                                                      | Default Value                      | Example Usage                                  |
|--------------------------|------------------------------------------------------------------|------------------------------------|------------------------------------------------|
| `-RemoteFolder`          | UNC path to the remote SMB share                                 | `\\10.10.5.7\MyShare`              | `-RemoteFolder "\\filesrv01\eng"`              |
| `-LocalFolder`           | Local folder for test file                                       | `C:\Software\copy`                 | `-LocalFolder "C:\temp"`                       |
| `-FileName`              | Name of the test file to copy                                    | `test_file.iso`                    | `-FileName "win11_install.iso"`                |
| `-Runs`                  | Number of runs for each direction (download/upload)              | `3`                                | `-Runs 5`                                      |
| `-WaitBetweenRunsSeconds`| Seconds to wait between runs                                     | `5`                                | `-WaitBetweenRunsSeconds 10`                   |
| `-LogCsv`                | Path to the CSV log file                                         | `C:\Software\copy\perf_runs_v1.csv`| `-LogCsv "D:\PerfLogs\my_test_results.csv"`     |



## Auto‑Detected & Collected Metadata

The script automatically discovers environment, network, and run‑time metrics and writes them to the console and CSV (when available). No manual input is needed for the items below.

### Client / VPN Detection
- **Active access product**: determines whether one of the following is active and sets `ProductUsed`:
  - `Cloudflare WARP`
  - `WireGuard`
  - `Entra Private Access` (Global Secure Access)
  - `None`
- **Client version (best‑effort)**:
  - **WARP**: from uninstall registry and/or executable file version
  - **WireGuard**: from uninstall registry and/or `C:\Program Files\WireGuard\wireguard.exe`
  - **Entra Private Access (GSA)**: from running service executables and/or uninstall registry
- **Derived field**: `VpnClientVersion` (populated when a single client is active)

### Device Identity & Host
- **DeviceId** and **TenantId** (parsed from `dsregcmd /status`)
- **Hostname** (`$env:COMPUTERNAME`)
- **Operating System** (caption, version, build) via CIM/WMI
- **Active Power Plan** (from `powercfg /GETACTIVESCHEME`)

### WAN / Public Network Context (best‑effort)
- **WanIP**
- **WanCity**, **WanRegion**, **WanCountry**
- **WanOrg** (ISP/ASN org where available)
- **WanSource** (which public API responded)
> Collected by querying multiple public IP info endpoints with graceful fallback.

### Network Route & Interface Snapshot
- **ActiveIfAlias** (interface alias used for the route)
- **ActiveIfMtu**
- **ActiveIfLinkSpeed**
- **Server IP resolution** (attempts to resolve the UNC server host to an IPv4 address for routing context)

### Copy Run Telemetry (per run)
- **Direction**: `Download` or `Upload`
- **StartUTC** / **EndUTC**
- **Seconds** (elapsed time)
- **FileMB** (size auto‑computed from the **source** file of that run)
- **Mbps** (calculated from size and elapsed time)
- **SourcePath** / **TargetPath**
- **CopyEngine** (`CopyItem` by default; Explorer UI engine if you switch it in the script)
- **ScriptVersion**

### Live External Ping (per run, to 8.8.8.8)
- **PingAvgMs**
- **PingMinMs**
- **PingMaxMs**
- **PingLossPct**
> A background job samples once per second; stats are snapshotted after each run.

### Connector Metadata (only when Entra Private Access is active)
- **ConnectorVersion**
- **ConnectorVMLocation**
- **ConnectorRegion**
> Values are prompted with sensible defaults; where possible, client/service versions are also detected as noted above.


# FAQ
Q: Can I use a folder of files instead of a single file? 
A: The script processes one file per run. To test multiple files, run the script separately for each file.

Q: Does it auto-detect file size? 
A: Yes, the script logs the actual size of the file used for each run. 

Q: How do I change where logs are saved? 
A: Use the -LogCsv parameter to specify your preferred log file location. 

Q: What happens if a file is missing? 
A: The script exits with a clear error message and does not log a row for that run.

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
- Auto-generates a random, incompressible test file if one isn't present (no manual ISO needed)
- Flexible CSV output for downstream analysis


# Quick Start
1. Prepare your test file:

   - Place your ISO on both the remote SMB share and your local folder. Customise logfile as needed.
   - Default paths:
        - Remote: \\\epa01.cyberdyne.local\software
        - Local: C:\Software\copy
        - Filename: 200mb.pdf
        - CSV: C:\Software\copy\perf_runs_v1.3.csv
   - No file yet? The script auto-generates one for you. If the local test file is missing,
     it creates a random, incompressible file of `-TestFileSizeMB` (default 200 MB) at the local
     path — a one-time operation that's then reused for every run. The first upload run copies it
     to the remote share, so the download test finds it there automatically. Random content means
     VPN/SMB compression can't inflate your throughput numbers. Pass `-NoAutoGenerate` to keep the
     old behaviour of exiting with an error when the file is absent.

2. Run the script:
    .\SMBPerformanceComparisonScript_v1.3ps1

3. View results
    - Console output shows per-run stats and network health.
    - CSV log saved to C:\Software\copy\perf_runs_v1.csv (customisable).   


# Parameters
| Parameter                | Description                                                      | Default Value                         | Example Usage                                  |
|--------------------------|------------------------------------------------------------------|---------------------------------------|------------------------------------------------|
| `-RemoteFolder`          | UNC path to the remote SMB share                                 | `\\epa01.cyberdyne.local\software`    | `-RemoteFolder "\\filesrv01\eng"`              |
| `-LocalFolder`           | Local folder for test file                                       | `C:\Software\copy`                    | `-LocalFolder "C:\temp"`                       |
| `-FileName`              | Name of the test file to copy                                    | `200mb.pdf.iso`                       | `-FileName "win11_install.iso"`                |
| `-Runs`                  | Number of runs for each direction (download/upload)              | `3`                                   | `-Runs 5`                                      |
| `-WaitBetweenRunsSeconds`| Seconds to wait between runs                                     | `5`                                   | `-WaitBetweenRunsSeconds 10`                   |
| `-LogCsv`                | Path to the CSV log file                                         | `C:\Software\copy\perf_runs_v1.3.csv` | `-LogCsv "D:\PerfLogs\my_test_results.csv"`    |
| `-TestFileSizeMB`        | Size (MB) of the auto-generated test file when none exists       | `200`                                 | `-TestFileSizeMB 1024`                         |
| `-NoAutoGenerate`        | Disable auto-generation; exit with an error if the file is absent| _(off)_                               | `-NoAutoGenerate`                              |



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
A: If the local test file is missing, the script auto-generates a random, incompressible file of `-TestFileSizeMB` (default 200 MB) and reuses it for every run; the first upload run seeds it onto the remote share. Use `-NoAutoGenerate` to instead exit with a clear error.

Q: Why is the auto-generated file filled with random bytes? 
A: Random data is incompressible, so VPN clients (e.g. WARP) or SMB compression can't shrink it in transit and inflate your throughput numbers. Generation is a one-time cost (~0.5–1s for 200 MB on SSD).

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


# FAQ
Q: Can I use a folder of files instead of a single file?
A: The script processes one file per run. To test multiple files, run the script separately for each file or use a wrapper script.

Q: Does it auto-detect file size?
A: Yes, the script logs the actual size of the file used for each run.
Q: How do I change where logs are saved?
A: Use the -LogCsv parameter to specify your preferred log file location.
Q: What happens if a file is missing?
A: The script exits with a clear error message and does not log a row for that run.

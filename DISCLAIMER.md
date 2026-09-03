# Disclaimer

**SMB Performance Analyser is a personal community tool - not a Microsoft product.**

This software is built and maintained by Zaher Butt to measure SMB file-share
throughput over a network path, so that transport performance can be reasoned
about with evidence rather than impressions. It is **not affiliated with,
endorsed by, or supported by Microsoft**. Use of this tool does not create any
Microsoft support obligation.

## What that means in practice

- **No warranty.** Provided as-is, without warranty of any kind, express or
  implied. The author and Microsoft accept no liability for any direct,
  indirect, incidental, consequential or other damages arising from its use.
- **No support.** There is no support contract, SLA, or guaranteed response
  time. Issues and questions are best-effort only via the public GitHub
  repository.
- **No telemetry.** The script runs locally and writes its results to the local
  filesystem of the host it runs on. It does not transmit data anywhere.
- **Output is observational, not authoritative.** The tool reports what it
  measures from the vantage point of the host it runs on. Interpretation of
  those measurements, and any decision or action based on them, is the user's
  responsibility.
- **Your data stays yours.** Results remain in your environment unless you
  choose to share them.

## Test files

The script generates incompressible test data so that compression in the
transport path cannot distort the throughput figures. Test files are created
and removed by the script; make sure the target share has enough free space
before running it.

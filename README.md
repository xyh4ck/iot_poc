
# IoT Vulnerability PoC 

This repository collects notes and proof-of-concept (PoC) materials used to reproduce and understand vulnerabilities in IoT devices/firmware.

## Contents

### D-Link DI-7400G+

- **CVE-2025-57105 Command Injection**
  - Write-up: `CVE-2025-57105_Command_Injection/CVE-2025-57105 Command Injection.md`
  - Notes: command injection via `mng_platform.asp` / `wayos_ac_server.asp` (see write-up for prerequisites and verification steps)

- **DI_7400G+ msp_info.htm Command Injection**
  - Write-up: `D-Link_DI_7400G+_Command_Injection/DI_7400G+_command_injection.md`
  - Notes: command injection via `/msp_info.htm` (see write-up for details)

## Repository Layout

- `CVE-2025-57105_Command_Injection/`
  - `CVE-2025-57105 Command Injection.md`
  - `images/`
- `D-Link_DI_7400G+_Command_Injection/`
  - `DI_7400G+_command_injection.md`
  - `images/`

## Quick Start

- Open the corresponding write-up under each directory.
- Follow the verification steps in the document.
- If emulation is required, the write-ups may reference tools such as FirmAE.

## Disclaimer

This repository is intended for **authorized security research and educational purposes only**.

- Do not test against systems you do not own or do not have explicit permission to assess.
- You are responsible for complying with applicable laws and regulations.
- The author(s) assume no liability for any misuse or damage.



# IoT Vulnerability PoC 

This repository collects notes and proof-of-concept (PoC) materials used to reproduce and understand vulnerabilities in IoT devices/firmware.

## Contents

### D-Link
#### DI_7400G+
- **01 Command Injection mng_platform** (CVE-2025-57105)
  - Write-up: `D-Link/DI_7400G+/01_Command_Injection_mng_platform/README.md`
  - Notes: command injection via `mng_platform.asp` / `wayos_ac_server.asp`

- **02 Command Injection msp_info_htm**  (CVE-2025-15357)
  - Write-up: `D-Link/DI_7400G+/02_Command_Injection_msp_info_htm/README.md`
  - Notes: command injection via `/msp_info.htm`

### Tenda
#### AC20

- **01 Buffer Overflow PowerSaveSet** (CVE-2025-15356)
  - Write-up: `Tenda/AC20/01_Buffer_Overflow_PowerSaveSet/README.md`
  - Notes: buffer overflow via `/goform/PowerSaveSet`

#### AC23

- **01 Buffer Overflow PowerSaveSet**
  - Write-up: `Tenda/AC23/01_Buffer_Overflow_PowerSaveSet/README.md`
  - Notes: buffer overflow via `/goform/PowerSaveSet`

- **02 Buffer Overflow WifiExtraSet**
  - Write-up: `Tenda/AC23/02_Buffer_Overflow_WifiExtraSet/README.md`
  - Notes: buffer overflow via `/goform/WifiExtraSet`

#### A7000R

- **01 setUnloadUserData RCE**
  - Write-up: `TOTOLINK/A7000R/01_setUnloadUserData_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

- **02 CloudACMunualUpdateUserdata RCE**
  - Write-up: `TOTOLINK/A7000R/02_CloudACMunualUpdateUserdata_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

## Disclaimer

This repository is intended for **authorized security research and educational purposes only**.

- Do not test against systems you do not own or do not have explicit permission to assess.
- You are responsible for complying with applicable laws and regulations.
- The author(s) assume no liability for any misuse or damage.

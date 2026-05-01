
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

- **01 Buffer Overflow PowerSaveSet** (CVE-2026-0640)
  - Write-up: `Tenda/AC23/01_Buffer_Overflow_PowerSaveSet/README.md`
  - Notes: buffer overflow via `/goform/PowerSaveSet`

- **02 Buffer Overflow WifiExtraSet** (CVE-2026-1420)
  - Write-up: `Tenda/AC23/02_Buffer_Overflow_WifiExtraSet/README.md`
  - Notes: buffer overflow via `/goform/WifiExtraSet`

#### HG10

- **01 Buffer Overflow nextHop** (CVE-2026-6988)
  - Write-up: `Tenda/HG10/01_Buffer_Overflow_nextHop/README.md`
  - Notes: buffer overflow via `/boaform/formRouting`

### Totolink

#### A7000R

- **01 setUnloadUserData RCE** (CVE-2026-1547)
  - Write-up: `TOTOLINK/A7000R/01_setUnloadUserData_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

- **02 CloudACMunualUpdateUserdata RCE** (CVE-2026-1548)
  - Write-up: `TOTOLINK/A7000R/02_CloudACMunualUpdateUserdata_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

- **03 setUploadUserData RCE** (CVE-2026-1601)
  - Write-up: `TOTOLINK/A7000R/03_setUploadUserData_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

- **04 setUpgradeFW RCE** (CVE-2026-1623)
  - Write-up: `TOTOLINK/A7000R/04_setUpgradeFW_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

#### A800R

- **01 Buffer Overflow setAppEasyWizardConfig** (CVE-2026-6157)
  - Write-up: `TOTOLINK/A800R/01_Buffer_Overflow_setAppEasyWizardConfig.md`
  - Notes: buffer overflow via `/cgi-bin/cstecgi.cgi`

- **02 Buffer Overflow setWiFiMultipleConfig** (CVE-2026-7503)
  - Write-up: `TOTOLINK/A800R/02_Buffer_Overflow_setWiFiMultipleConfig.md`
  - Notes: buffer overflow via `/cgi-bin/cstecgi.cgi`

#### N300RHv4

- **01 setWebWlanIdx RCE** (CVE-2026-3301)
  - Write-up: `TOTOLINK/N300RHv4/01_setWebWlanIdx_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

- **02 setUpgradeUboot RCE** (CVE-2026-6158)
  - Write-up: `TOTOLINK/N300RHv4/02_setUpgradeUboot_RCE.md`
  - Notes: command injection via `/cgi-bin/cstecgi.cgi`

- **03 setUploadSetting ECFNP** (CVE-2026-7633)
  - Write-up: `TOTOLINK/N300RHv4/03_setUploadSetting_ECFNP.md`
  - Notes: external control of file name or path via `/cgi-bin/cstecgi.cgi`


## Disclaimer

This repository is intended for **authorized security research and educational purposes only**.

- Do not test against systems you do not own or do not have explicit permission to assess.
- You are responsible for complying with applicable laws and regulations.
- The author(s) assume no liability for any misuse or damage.

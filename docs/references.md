# References and Credits

Blue-Tap builds on decades of Bluetooth security research. This page credits the researchers, papers, and tools that inform Blue-Tap's detection and exploitation capabilities.

---

## Citing Blue-Tap

If you use Blue-Tap in academic research, security assessments, or publications, please cite it as follows:

### BibTeX

```bibtex
@software{bluetap2026,
  author       = {Ballikonda, Santhosh},
  title        = {{Blue-Tap}: Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems},
  version      = {2.6.2},
  year         = {2026},
  url          = {https://github.com/Indspl0it/blue-tap},
  license      = {GPL-3.0-or-later},
  note         = {101 modules, 25 CVE detections, 16-protocol fuzzer with DarkFirmware support}
}
```

### Plain Text

> Santhosh Ballikonda. *Blue-Tap: Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems*, v2.6.2, 2026. Available at: https://github.com/Indspl0it/blue-tap

### IEEE Style

> S. Ballikonda, "Blue-Tap: Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems," version 2.6.2, 2026. [Online]. Available: https://github.com/Indspl0it/blue-tap

---

## Researcher Credits

The vulnerabilities detected and exploited by Blue-Tap were discovered by security researchers across industry and academia. Blue-Tap implements detection logic and proof-of-concept techniques based on their published work.

### BlueBorne (2017)

**Researchers:** Ben Seri, Gregory Vishnepolsky (Armis Labs)

**CVEs:** CVE-2017-0781, CVE-2017-0782, CVE-2017-0783, CVE-2017-0785, CVE-2017-13258, CVE-2017-13260, CVE-2017-13261, CVE-2017-13262

**Impact:** First set of Bluetooth vulnerabilities demonstrating full remote code execution over the air with zero user interaction. Affected Android, Linux, Windows, and iOS. The BNEP and SDP attack vectors showed that Bluetooth's pre-authentication attack surface was far larger than previously understood.

**Publications:**

- B. Seri and G. Vishnepolsky, "BlueBorne: A New Airborne Attack Vector," Armis Labs, Technical Report, Sep. 2017.
- B. Seri and G. Vishnepolsky, "The Dangers of Bluetooth Implementations: Unveiling Zero Day Vulnerabilities and Security Flaws in Modern Bluetooth Stacks," Armis Labs, White Paper, 2017.

**Blue-Tap modules:** `assessment.cve_2017_0785`, `assessment.cve_2017_0783`, `assessment.cve_2017_13258`, `exploitation.dos_cve_2017_0781_bnep_heap`, `exploitation.dos_cve_2017_0782_bnep_underflow`

---

### KNOB Attack (2019)

**Researchers:** Daniele Antonioli, Nils Ole Tippenhauer, Kasper Rasmussen

**CVE:** CVE-2019-9506

**Impact:** Demonstrated that a man-in-the-middle attacker can force Bluetooth BR/EDR connections to negotiate a 1-byte encryption key, enabling real-time brute-force decryption of all traffic. Affected every Bluetooth BR/EDR device. Led to the Bluetooth SIG mandating a 7-byte minimum key length in Bluetooth 5.1+.

**Publications:**

- D. Antonioli, N. O. Tippenhauer, and K. Rasmussen, "The KNOB is Broken: Exploiting Low Entropy in the Encryption Key Negotiation of Bluetooth BR/EDR," in *Proceedings of the 28th USENIX Security Symposium*, 2019, pp. 1047--1064.

**Blue-Tap modules:** `exploitation.knob`

---

### BIAS Attack (2020)

**Researchers:** Daniele Antonioli, Nils Ole Tippenhauer, Kasper Rasmussen

**CVE:** CVE-2020-10135

**Impact:** Showed that Bluetooth Secure Connections authentication can be bypassed by impersonating one side of a previously established pairing. An attacker who knows the BD_ADDR of a paired device can complete authentication without knowing the link key.

**Publications:**

- D. Antonioli, N. O. Tippenhauer, and K. Rasmussen, "BIAS: Bluetooth Impersonation AttackS," in *Proceedings of the 2020 IEEE Symposium on Security and Privacy (SP)*, 2020, pp. 549--562.

**Blue-Tap modules:** `exploitation.bias`

---

### BlueFrag (2020)

**Researchers:** Andy Nguyen (Google)

**CVE:** CVE-2020-0022

**Impact:** A critical Android Bluetooth RCE vulnerability in the L2CAP reassembly logic. A malformed ACL fragment with a length mismatch triggers a heap buffer overflow, allowing remote code execution with Bluetooth daemon privileges. Affected Android 8.0 through 9.0 (critical) and caused DoS on Android 10.

**Publications:**

- A. Nguyen, "CVE-2020-0022: An Android 8.0-9.0 Bluetooth Zero-Click RCE -- BlueFrag," insinuator.net, Feb. 2020.

**Blue-Tap modules:** `assessment.cve_2020_0022`, `exploitation.dos_cve_2020_0022_bluefrag`

---

### BadChoice / BadVibes / BadKarma (2020)

**Researchers:** Andy Nguyen (Google)

**CVEs:** CVE-2020-12351, CVE-2020-12352 (BadChoice), CVE-2020-24490 (BadVibes)

**Impact:** A family of Linux kernel Bluetooth vulnerabilities. BadChoice (CVE-2020-12352) is an information disclosure via the A2MP protocol that leaks kernel heap data. BadVibes (CVE-2020-24490) is a heap buffer overflow in BLE extended advertising data. Combined, they enable remote kernel exploitation over Bluetooth.

**Publications:**

- A. Nguyen, "BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution," Google Security Blog, Oct. 2020.

**Blue-Tap modules:** `assessment.cve_2020_12352`

---

### BLURtooth / CTKD (2020)

**Researchers:** Jianliang Wu, Yuhong Nan, Vireshwar Kumar, Dave (Jing) Tian, Antonio Bianchi, Mathias Payer, Dongyan Xu

**CVE:** CVE-2020-15802

**Impact:** Cross-Transport Key Derivation (CTKD) allows an attacker to derive keys for one transport (BR/EDR or BLE) by pairing on the other. This means a weaker BLE pairing can compromise the BR/EDR link key, or vice versa. Affects dual-mode devices supporting both transports.

**Publications:**

- J. Wu et al., "BLURtooth: Exploiting Cross-Transport Key Derivation in Bluetooth Classic and Bluetooth Low Energy," USENIX Security, 2020 (poster).
- Bluetooth SIG, "BLURtooth Vulnerability," Advisory, Sep. 2020.

**Blue-Tap modules:** `exploitation.ctkd`

---

### BLUFFS (2023)

**Researchers:** Daniele Antonioli

**CVE:** CVE-2023-24023

**Impact:** A family of 6 novel attacks on Bluetooth session establishment that force weak session keys. Unlike KNOB (which targets key length), BLUFFS targets the session key derivation procedure itself, showing that even fully patched devices with Bluetooth 5.4 can be forced to derive weak session keys. This is an architectural flaw in the Bluetooth specification, not an implementation bug.

**Publications:**

- D. Antonioli, "BLUFFS: Bluetooth Forward and Future Secrecy Attacks and Defenses," in *Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security (CCS)*, 2023, pp. 636--650.

**Blue-Tap modules:** `exploitation.bluffs`

---

### SweynTooth (2019--2020)

**Researchers:** Matheus E. Garbelini, Sudipta Chattopadhyay, Sun Sumei, Ernest Kurniawan (Singapore University of Technology and Design)

**CVEs:** CVE-2019-19192, CVE-2019-19194, CVE-2019-19195, CVE-2019-19196, CVE-2020-10061, CVE-2020-10069, CVE-2020-13593

**Impact:** A family of 18 BLE vulnerabilities affecting SoC implementations from major vendors (Texas Instruments, NXP, Cypress, Dialog Semiconductor, Microchip, STMicroelectronics, Telink). Demonstrated that BLE stack implementations in embedded chipsets are riddled with parsing bugs, including zero-length LTK installation, public key crashes, ATT deadlocks, and invalid L2CAP fragments.

**Publications:**

- M. E. Garbelini, S. Chattopadhyay, S. Sumei, and E. Kurniawan, "SweynTooth: Unleashing Mayhem Over Bluetooth Low Energy," in *Proceedings of the 2020 USENIX Annual Technical Conference (ATC)*, 2020, pp. 911--925.

**Blue-Tap modules:** `exploitation.dos_cve_2019_19192_att_deadlock`, `exploitation.dos_cve_2019_19196_key_size`

---

### Passkey Entry / Method Confusion (2020--2022)

**Researchers:** Maximilian von Tschirschnitz, Ludwig Peuckert, Fabian Franzen, Jens Grossklags (Technical University of Munich)

**CVEs:** CVE-2020-26558, CVE-2022-25836, CVE-2022-25837

**Impact:** Demonstrated that Secure Simple Pairing's method selection can be manipulated by an attacker to downgrade from a secure method (Numeric Comparison) to an insecure one (JustWorks or Passkey Entry with a reflected public key). This allows a MitM attacker to pair with the target without user confirmation.

**Publications:**

- M. von Tschirschnitz, L. Peuckert, F. Franzen, and J. Grossklags, "Method Confusion Attack on Bluetooth Pairing," in *Proceedings of the 2021 IEEE Symposium on Security and Privacy (SP)*, 2021.

**Blue-Tap modules:** `assessment.cve_2020_26558`, `assessment.cve_2022_25837`

---

### HID Injection / HOGP Bypass (2023)

**Researcher:** Marc Newlin (SkySafe)

**CVE:** CVE-2023-45866

**Impact:** Discovered that multiple Bluetooth stacks (Android, Linux, macOS, iOS) accept HID connections from unauthenticated devices, allowing an attacker to inject keystrokes without user confirmation. This enables keystroke injection attacks against locked devices from up to 100 meters.

**Publications:**

- M. Newlin, "Bluetooth HID Hosts in BlueZ, Android, macOS, and iOS Accept Unencrypted HID Connections," SkySafe Advisory, Dec. 2023.

**Blue-Tap modules:** `assessment.cve_2023_45866`, `assessment.cve_2020_0556`

---

### L2CAP Use-After-Free Family (2022)

**Researchers:** Various (Linux kernel community, Qualcomm security team)

**CVEs:** CVE-2022-42896, CVE-2022-42895, CVE-2022-3564, CVE-2022-3640

**Impact:** Multiple use-after-free and information disclosure vulnerabilities in the Linux kernel's L2CAP implementation. CVE-2022-42896 involves LE Credit Based Connection handling with PSM 0 that triggers a UAF. CVE-2022-42895 leaks uninitialized EFS data in L2CAP configuration responses.

**Blue-Tap modules:** `assessment.cve_2022_42896`, `assessment.cve_2022_42895`

---

### Android BLE / GATT Vulnerabilities (2022--2024)

**Researchers:** Various (Google Android Security team, external reporters)

**CVEs:** CVE-2022-20345, CVE-2022-0204, CVE-2023-35681, CVE-2024-34722

**Impact:** Buffer overflows and integer overflows in Android's BLE and GATT implementations. CVE-2022-20345 involves L2CAP eCred handling where more than 5 CIDs overflow a fixed buffer. CVE-2023-35681 is an EATT reconfiguration integer overflow. These are RCE-grade vulnerabilities reachable over the air.

**Blue-Tap modules:** `assessment.cve_2022_20345`, `assessment.cve_2022_0204`, `assessment.cve_2023_35681`, `assessment.cve_2024_34722`

---

### JustWorks Silent Pairing (2019)

**Researchers:** Various (Android Security Bulletin)

**CVE:** CVE-2019-2225

**Impact:** Android's Bluetooth stack would silently complete JustWorks pairing without any user interaction if the remote device presented a NoInputNoOutput IO capability. This allowed an attacker to pair with an Android device and establish a trusted connection without any visible prompt.

**Blue-Tap modules:** `assessment.cve_2019_2225`

---

### Airoha RACE Command Vulnerabilities (2025)

**CVEs:** CVE-2025-20700, CVE-2025-20701, CVE-2025-20702

**Impact:** Vulnerabilities in Airoha chipsets (used in TWS earbuds and automotive Bluetooth modules) where the proprietary RACE command interface lacks authentication. Allows GATT-level and BR/EDR-level unauthorized access, and link key extraction on affected devices.

**Blue-Tap modules:** `assessment.cve_2025_20700`, `assessment.cve_2025_20701`, `assessment.cve_2025_20702`

---

### AVDTP / AVRCP Vulnerabilities (2022--2023)

**Researchers:** Various (BlueZ maintainers, Android Security)

**CVEs:** CVE-2022-39176, CVE-2022-39177, CVE-2023-27349, CVE-2021-0507

**Impact:** Out-of-bounds reads and heap overflows in media profile implementations. CVE-2022-39176 leaks heap data via malformed AVRCP GET_CAPABILITIES. CVE-2022-39177 crashes BlueZ via malformed AVDTP SET_CONFIGURATION. These affect all devices using BlueZ for Bluetooth audio.

**Blue-Tap modules:** `assessment.cve_2022_39176`, `assessment.cve_2021_0507`, `exploitation.dos_cve_2022_39177_avdtp_setconf`, `exploitation.dos_cve_2023_27349_avrcp_event`

---

## Foundational Research and Specifications

### Bluetooth Core Specification

- Bluetooth SIG, "Bluetooth Core Specification v5.4," Bluetooth Special Interest Group, 2023. Available: https://www.bluetooth.com/specifications/specs/core-specification/

### Bluetooth Security Analysis

- J. Padgette et al., "Guide to Bluetooth Security," NIST Special Publication 800-121 Rev. 2, National Institute of Standards and Technology, May 2017.
- M. Cominelli, F. Gringoli, and R. M. Aarts, "Even Connections on the Edge Can Be Harmful," in *IEEE Transactions on Information Forensics and Security*, 2024.

### Automotive Bluetooth Security

- K. Koscher et al., "Experimental Security Analysis of a Modern Automobile," in *Proceedings of the 2010 IEEE Symposium on Security and Privacy*, 2010.
- C. Miller and C. Valasek, "A Survey of Remote Automotive Attack Surfaces," Black Hat USA, 2014.
- T. Kilcoyne and S. Chandra, "Bluetooth Security in Automotive: A Survey of Bluetooth Security Issues in Vehicles," SAE Technical Paper 2022-01-0106, 2022.

### Bluetooth Fuzzing

- M. E. Garbelini et al., "BrakTooth: Causing Havoc on Bluetooth Link Manager via Directed Fuzzing," in *Proceedings of the 31st USENIX Security Symposium*, 2022, pp. 1025--1042.
- D. Mantz et al., "InternalBlue: Bluetooth Binary Patching and Experimentation Framework," in *Proceedings of the 17th International Conference on Mobile Systems, Applications, and Services (MobiSys)*, 2019.
- A. Schulman and D. Levin, "Fuzzing Bluetooth Stacks with the AFL Fuzzer," DEF CON 25, 2017.

### DarkFirmware / Firmware Patching

- J. Ruge, J. Classen, F. Gringoli, and M. Hollick, "Frankenstein: Advanced Wireless Fuzzing to Exploit New Bluetooth Escalation Targets," in *Proceedings of the 29th USENIX Security Symposium*, 2020.
- D. Mantz, J. Classen, M. Schulz, and M. Hollick, "InternalBlue: Bluetooth Binary Patching and Experimentation Framework," in *Proceedings of the 17th ACM International Conference on Mobile Systems, Applications, and Services*, 2019, pp. 79--90.

---

## Related Tools

Blue-Tap complements and builds upon the work of other Bluetooth security tools:

| Tool | Authors | Purpose | Relationship to Blue-Tap |
|------|---------|---------|--------------------------|
| [InternalBlue](https://github.com/seemoo-lab/internalblue) | SEEMOO Lab (TU Darmstadt) | Broadcom/Cypress firmware patching | Inspired DarkFirmware approach for RTL8761B |
| [BrakTooth ESP32 PoC](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks) | Matheus Garbelini et al. | BT Classic fuzzing via ESP32 | Blue-Tap's LMP fuzzer covers similar ground with DarkFirmware |
| [SweynTooth](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks) | Matheus Garbelini et al. | BLE SoC vulnerability toolkit | Blue-Tap integrates SweynTooth detection as DoS checks |
| [Bluing](https://github.com/fO-000/bluing) | fO-000 | BT/BLE scanning and analysis | Complementary reconnaissance tool |
| [BtleJuice](https://github.com/DigitalSecurity/btlejuice) | Digital Security | BLE MitM framework | Complementary for BLE interception scenarios |
| [Scapy](https://scapy.net/) | Philippe Biondi et al. | Packet crafting library | Used by Blue-Tap for low-level packet construction |

---

## Acknowledgments

Blue-Tap is developed by **Santhosh Ballikonda** ([@Indspl0it](https://github.com/Indspl0it)).

Special thanks to:

- The **Bluetooth SIG** for maintaining public specifications and security advisories
- The **Linux kernel Bluetooth subsystem maintainers** for BlueZ and kernel-side fixes that informed detection logic
- The **Android Security team** at Google for responsible disclosure and detailed security bulletins
- **Daniele Antonioli** (EURECOM) for foundational Bluetooth security research (KNOB, BIAS, BLUFFS)
- **Matheus Garbelini** (SUTD) for SweynTooth and BrakTooth research
- **Andy Nguyen** (Google) for BlueFrag and BleedingTooth
- **Marc Newlin** (SkySafe) for HID injection research
- The **SEEMOO Lab** at TU Darmstadt for InternalBlue firmware patching research
- The broader **Bluetooth security research community** whose published work makes tools like Blue-Tap possible

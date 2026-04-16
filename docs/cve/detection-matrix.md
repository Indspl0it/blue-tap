# CVE Detection Matrix

Blue-Tap's vulnerability detection is built on a core philosophy: **behavioral observation over version matching**. Rather than fingerprinting a target's software version and consulting a lookup table (which misses backported patches and custom builds), Blue-Tap sends carefully crafted packets and observes how the target responds. A differential response -- one that differs between patched and unpatched implementations -- is the gold standard for confirming a vulnerability exists on a specific device, right now.

This approach has two models:

- **Behavioral** -- active probing with crafted packets that elicit a differential response from vulnerable vs. patched targets. The probe itself is non-intrusive: it observes the response without crashing or modifying the target. This is Blue-Tap's primary detection method and the most reliable.
- **Compliance** -- spec-violation testing that sends invalid inputs and checks whether the target correctly rejects them per the Bluetooth specification. A target that accepts invalid input has a parsing flaw, which may or may not be exploitable -- but it definitively violates the spec and indicates a missing bounds check.

Non-CVE checks are also included for posture assessment (pairing method, writable surfaces, service exposure).

---

## Behavioral Checks

Checks that actively probe the target and observe a response differential. These are the highest-confidence detections: a positive result means the vulnerability was directly observed, not inferred.

### L2CAP Protocol Family

L2CAP (Logical Link Control and Adaptation Protocol) is the multiplexing layer that sits above HCI and below most Bluetooth profiles. It handles channel management, segmentation, and reassembly. L2CAP vulnerabilities are particularly dangerous because L2CAP is always active on any Bluetooth device -- there is no way to disable it without disabling Bluetooth entirely. An L2CAP flaw means pre-authentication, zero-click remote attack surface.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2018-9359/60/61 | Android L2CAP Heap Jitter | Truncated CMD_CONN_REQ (missing SCID); SCID jitter on malformed response | No |
| CVE-2019-3459 | L2CAP MTU Info Leak | CONF_REQ with malformed MTU option (len=0); heap pointer leak via jitter across 3 probes | No |
| CVE-2020-0022 | BlueFrag Boundary Probe | Fragmented Echo: packet 1 = L2CAP header only, packet 2 = 95 bytes (1 short); crash = vulnerable | No |
| CVE-2020-12352 | BadChoice A2MP Info Leak | A2MP GET_INFO_REQ with invalid ctrl_id; info_data jitter reveals heap data | No |
| CVE-2022-42895 | L2CAP EFS Info Leak | CONF_REQ WITHOUT EFS option; checks if CONF_RSP contains uninitialized EFS data | No |

??? tip "How to run L2CAP checks"
    ```bash
    # Run all L2CAP behavioral checks
    blue-tap vulnscan TARGET --category l2cap

    # Run a specific CVE check
    blue-tap vulnscan TARGET --checks cve_2019_3459

    # BlueFrag requires a DarkFirmware adapter
    blue-tap vulnscan TARGET --checks cve_2020_0022 -i hci1
    ```

### BNEP Protocol Family

BNEP (Bluetooth Network Encapsulation Protocol) carries Ethernet frames over Bluetooth for PAN (Personal Area Network) profiles. It was a primary target of the BlueBorne attack family because BNEP connection setup can be initiated without authentication on many stacks. The info leak variants exploit extension header parsing: by sending a header that claims to be longer than the actual data, the target reads past the end of the received buffer and returns heap memory in its response.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2017-0783 | BlueBorne BNEP Heap Overflow | SETUP_CONNECTION_REQ with swapped NAP/PANU UUIDs; vulnerable if response_code=0x0000 | No |
| CVE-2017-13258/13260/13261/13262 | BNEP Extension Header Info Leak Family | 3 General Ethernet frames with extension header length > actual data; jitter = OOB read (covers 4 related CVEs) | No |

??? tip "How to run BNEP checks"
    ```bash
    # Run all BNEP checks
    blue-tap vulnscan TARGET --category bnep

    # The BNEP info leak probe covers 4 CVEs in a single check
    blue-tap vulnscan TARGET --checks cve_2017_13258
    ```

### SDP Protocol Family

SDP (Service Discovery Protocol) is how Bluetooth devices advertise and discover available services. It runs over L2CAP and is reachable without authentication. SDP parsing flaws typically involve continuation state handling -- SDP responses can be split across multiple packets using a continuation token, and bugs in how this state is tracked across requests can leak memory or cause denial of service.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2017-0785 | BlueBorne SDP DoS | Continuation state replay across different service searches | No |

??? tip "How to run SDP checks"
    ```bash
    blue-tap vulnscan TARGET --checks cve_2017_0785
    ```

### AVRCP Protocol Family

AVRCP (Audio/Video Remote Control Profile) controls media playback over Bluetooth. It is present on virtually every audio device: headphones, speakers, car head units, and smart TVs. AVRCP vulnerabilities matter because the profile auto-connects when an audio link is established, creating a large attack surface on consumer devices that users expect to "just work" without security prompts.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2022-39176 | AVRCP OOB Read | GET_CAPABILITIES with params_len=1 but no data; BlueZ < 5.60 leaks heap | No |

??? tip "How to run AVRCP checks"
    ```bash
    blue-tap vulnscan TARGET --checks cve_2022_39176
    ```

### HID Protocol Family

HID (Human Interface Device) profile enables keyboards, mice, and game controllers over Bluetooth. HID vulnerabilities are high-impact because an attacker who can inject HID input can type arbitrary commands on the target device. The checks below test whether HID connections are accepted without proper authentication, which would allow an attacker to pair a rogue keyboard.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2020-0556 | HID/HOGP Unauthenticated | Tests L2CAP PSM 0x0011 (Control) + 0x0013 (Interrupt) unbonded acceptance | No |

??? tip "How to run HID checks"
    ```bash
    blue-tap vulnscan TARGET --checks cve_2020_0556
    ```

### Pairing Protocol Family

Pairing is the mechanism by which Bluetooth devices establish trust and derive encryption keys. Flaws in pairing affect the entire security model: if pairing can be bypassed or downgraded, all subsequent communication on that link is compromised. These checks require an active pairing attempt with the target, which means the target's user may see a pairing prompt.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2019-2225 | Android JustWorks Silent Pairing | JustWorks via bluetoothctl with NoInputNoOutput agent; detects silent completion | Yes |
| CVE-2020-26558 | Passkey Mutual Auth Bypass | LE SC pairing: capture target's public key, echo it back; vulnerable if accepted | Yes |
| CVE-2022-25837 | SSP Method Confusion | Compare SSP strong method vs NoInputNoOutput downgrade; differential indicates vulnerability | Yes |

??? tip "How to run pairing checks"
    ```bash
    # These checks initiate pairing -- the target user may see a prompt
    blue-tap vulnscan TARGET --category pairing

    # Run with explicit pairing consent
    blue-tap vulnscan TARGET --checks cve_2019_2225 --allow-pairing
    ```

### BLE SMP Family

SMP (Security Manager Protocol) handles pairing and key distribution for BLE (Bluetooth Low Energy) connections. Unlike Classic Bluetooth pairing which uses LMP, BLE uses SMP over a dedicated L2CAP channel. SMP flaws can allow pairing bypass, key extraction, or cross-transport attacks where a BLE vulnerability compromises the Classic Bluetooth link.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2024-34722 | BLE Legacy Pairing Bypass | Wrong SMP_PAIRING_CONFIRM then Random; vulnerable if SMP continues past confirm check | No |

??? tip "How to run BLE SMP checks"
    ```bash
    blue-tap vulnscan TARGET --checks cve_2024_34722
    ```

### Vendor-Specific: Airoha

Airoha is a MediaTek subsidiary whose Bluetooth chipsets are found in many TWS (True Wireless Stereo) earbuds and automotive infotainment systems. The RACE (Remote Access and Control Engine) interface is Airoha's proprietary debug/control protocol. These CVEs allow unauthenticated access to RACE commands, enabling authentication bypass and link-key extraction -- effectively a full compromise of any bonded device.

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2025-20700 | Airoha GATT RACE Auth Bypass | Airoha chipset-specific GATT behavioral probe | No |
| CVE-2025-20701 | Airoha BR/EDR RACE Auth Bypass | Airoha chipset-specific BR/EDR behavioral probe | No |
| CVE-2025-20702 | Airoha RACE Link-Key Extraction | Airoha chipset-specific link-key extraction probe | No |

??? tip "How to run Airoha checks"
    ```bash
    blue-tap vulnscan TARGET --checks cve_2025_20700,cve_2025_20701,cve_2025_20702
    ```

### Raw ACL

| CVE | Name | Detection Method | Pairing |
|-----|------|------------------|---------|
| CVE-2020-0022 | BlueFrag Boundary Probe | Fragmented Echo: packet 1 = L2CAP header only, packet 2 = 95 bytes (1 short); crash = vulnerable | No |

!!! warning "DarkFirmware Required"
    CVE-2020-0022 (BlueFrag) requires a DarkFirmware-capable adapter for raw ACL transmission. See [Hardware Compatibility](../reference/hardware-compatibility.md) for supported adapters.

---

## Compliance Checks

Checks whether the target correctly rejects invalid inputs per the Bluetooth specification. A compliance failure means the target has a parsing bug -- it accepted something the spec says must be rejected. These are lower-confidence than behavioral checks (a parsing bug may not always be exploitable), but they definitively prove a code defect exists.

| CVE | Name | Protocol | What It Tests |
|-----|------|----------|---------------|
| CVE-2018-9365 | SMP Cross-Transport | BLE SMP | SMP_PAIRING_REQ to BR/EDR CID 0x0007; patched stacks return SMP_PAIRING_FAILED(0x05) |
| CVE-2021-0507 | AVRCP Event ID OOB | AVRCP | REGISTER_NOTIFICATION with event_id=0x00; must be REJECTED (valid range 0x01-0x0D) |
| CVE-2022-0204 | BlueZ GATT Heap Overflow | GATT | Prepare Write with offset=1, len=512 (total 513); vulnerable if accepts |
| CVE-2022-20345 | Android BLE L2CAP eCred Overflow | BLE L2CAP | L2CAP_CREDIT_BASED_CONN_REQ with 6 CIDs (max=5); buffer overflow |
| CVE-2022-42896 | LE Credit PSM Zero UAF | BLE L2CAP | LE credit-based PSM=0; expects LE_PSM_NOT_SUPPORTED response |
| CVE-2023-35681 | EATT Integer Overflow | GATT | EATT reconfiguration with mtu=1, mps=1; vulnerable if result=0x0000 |
| CVE-2023-45866 | HID Pre-Auth Write | HID | Enumerate BLE GATT HID Service (0x1812), Report char (0x2A4D); check if writable pre-auth |
| CVE-2026-23395 | L2CAP ECFC Duplicate Identifier | BLE L2CAP | Two ECFC_CONN_REQ with identical Identifier; tests duplicate handling |

??? tip "How to run compliance checks"
    ```bash
    # Run all compliance checks
    blue-tap vulnscan TARGET --mode compliance

    # Run all checks (behavioral + compliance)
    blue-tap vulnscan TARGET

    # Run a specific compliance check
    blue-tap vulnscan TARGET --checks cve_2023_45866
    ```

---

## Non-CVE Checks

These posture assessment checks do not map to specific CVEs but reveal security-relevant configuration and exposure. They answer questions like "Can I pair with this device without user interaction?" and "Are there services accessible without authentication?"

| Check ID | Category | Description |
|----------|----------|-------------|
| pairing_method | BLE | Detect active pairing method (JustWorks, Numeric Comparison, etc.) |
| writable_gatt | BLE | Enumerate writable GATT characteristics without authentication |
| eatt_support | BLE | Detect Enhanced ATT support |
| service_exposure | RFCOMM | Identify RFCOMM services accessible without authentication |
| hidden_rfcomm | RFCOMM | Detect RFCOMM channels not advertised in SDP |
| encryption_enforcement | RFCOMM | Test whether connections are accepted without encryption |
| authorization_model | RFCOMM | Test authorization enforcement on services |
| automotive_diagnostics | RFCOMM | Detect automotive-specific diagnostic interfaces |
| pin_lockout | Posture | Test PIN lockout behavior after failed attempts |
| device_class | Posture | Verify device class matches expected type |
| lmp_features | Posture | Analyze LMP feature bits for security implications |

??? tip "How to run posture checks"
    ```bash
    # Run all non-CVE posture checks
    blue-tap vulnscan TARGET --mode posture

    # Run RFCOMM-specific checks
    blue-tap vulnscan TARGET --category rfcomm

    # Run a specific non-CVE check
    blue-tap vulnscan TARGET --checks service_exposure
    ```

---

## Module Mapping

Source file locations within `blue_tap/modules/assessment/checks/`:

| Check Source File | CVEs Covered |
|-------------------|--------------|
| `cve_checks_sdp.py` | CVE-2017-0785 |
| `cve_checks_bnep.py` | CVE-2017-0783, CVE-2017-13258/60/61/62 |
| `cve_checks_l2cap.py` | CVE-2018-9359/60/61, CVE-2019-3459, CVE-2020-12352, CVE-2022-42895, CVE-2022-42896, CVE-2022-20345, CVE-2026-23395 |
| `cve_checks_avrcp.py` | CVE-2021-0507, CVE-2022-39176 |
| `cve_checks_gatt.py` | CVE-2022-0204, CVE-2023-35681 |
| `cve_checks_hid.py` | CVE-2020-0556, CVE-2023-45866 |
| `cve_checks_pairing.py` | CVE-2019-2225, CVE-2020-26558, CVE-2022-25837 |
| `cve_checks_ble_smp.py` | CVE-2018-9365, CVE-2024-34722 |
| `cve_checks_airoha.py` | CVE-2025-20700, CVE-2025-20701, CVE-2025-20702 |
| `cve_checks_raw_acl.py` | CVE-2020-0022 |
| `non_cve_checks_rfcomm.py` | service_exposure, hidden_rfcomm, encryption_enforcement, authorization_model, automotive_diagnostics |
| `non_cve_checks_ble.py` | pairing_method, writable_gatt, eatt_support |
| `non_cve_checks_posture.py` | pin_lockout, device_class, lmp_features |

---

## Finding Statuses

| Status | Meaning |
|--------|---------|
| `confirmed` | Vulnerability positively identified via behavioral differential or compliance failure |
| `inconclusive` | Probe ran but response was ambiguous |
| `pairing_required` | Check requires pairing context that was not available |
| `not_applicable` | Target does not support the protocol or prerequisite is missing |

---

## Quick Reference

```bash
# Full vulnerability scan (all behavioral + compliance + posture checks)
blue-tap vulnscan TARGET

# List all available checks
blue-tap vulnscan list

# Behavioral checks only
blue-tap vulnscan TARGET --mode behavioral

# Compliance checks only
blue-tap vulnscan TARGET --mode compliance

# Posture checks only
blue-tap vulnscan TARGET --mode posture

# Specific protocol category
blue-tap vulnscan TARGET --category l2cap

# Specific CVE(s)
blue-tap vulnscan TARGET --checks cve_2020_0022,cve_2022_42895

# With explicit adapter
blue-tap vulnscan TARGET -i hci0

# With session logging
blue-tap -s my-assessment vulnscan TARGET

# JSON output for automation
blue-tap vulnscan TARGET --json
```

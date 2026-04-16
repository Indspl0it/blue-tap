<p align="center">
  <img src="assets/banner.svg" alt="Blue-Tap Banner" width="100%"/>
</p>

<p align="center">
  <b>Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-green" alt="License GPL-3.0"/>
  <img src="https://img.shields.io/badge/version-2.5.0-orange" alt="Version 2.5.0"/>
</p>

---

Blue-Tap is a Bluetooth Classic and BLE penetration testing toolkit built for automotive IVI security assessments. It operates at both the HCI layer and below-HCI via DarkFirmware on RTL8761B.

- **Discovers, fingerprints, and assesses** Bluetooth devices with 30+ CVE checks and non-CVE exposure analysis
- **Exploits** protocol vulnerabilities: BIAS, KNOB, BLUFFS, SSP downgrade, encryption downgrade, connection hijacking
- **Extracts data and intercepts audio** via PBAP, MAP, HFP, A2DP, AVRCP, AT commands, OBEX
- **Fuzzes 12 Bluetooth protocols** with a response-guided engine, crash database, and minimization

## Installation

```bash
git clone https://github.com/Indspl0it/blue-tap.git
cd blue-tap
pip install -e .
```

Verify:

```bash
sudo blue-tap --version
sudo blue-tap adapter list
```

## Documentation

Full documentation: **[docs/](docs/index.md)**

- [Features and Command Reference](docs/features.md)
- [Usage Guide](docs/usage-guide.md)
- [Hardware Compatibility](docs/reference/hardware-compatibility.md)
- [Troubleshooting](docs/reference/troubleshooting.md)
- [Platform Notes](docs/reference/platform-notes.md)
- [Vulnscan CVE Matrix](docs/vulnscan-cve-matrix.md)
- [Changelog](docs/CHANGELOG.md)

## Legal Disclaimer

Blue-Tap is provided for authorized security testing and research purposes only. You must have explicit written permission from the owner of any device you test. Unauthorized access to Bluetooth devices is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and similar laws worldwide. The authors accept no liability for misuse. Report vulnerabilities responsibly to the affected manufacturer.

## License

[GNU General Public License v3.0](LICENSE) — Copyright (C) 2026 Santhosh Ballikonda

---

**Santhosh Ballikonda** — [@Indspl0it](https://github.com/Indspl0it)

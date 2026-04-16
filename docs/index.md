---
title: Home
description: Blue-Tap -- Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems
---

<style>
.md-typeset .hero-title {
  font-size: 2.8rem;
  font-weight: 700;
  margin-bottom: 0;
  line-height: 1.1;
}
.md-typeset .hero-tagline {
  font-size: 1.25rem;
  color: var(--md-default-fg-color--light);
  margin-top: 0.5rem;
  margin-bottom: 2rem;
}
.md-typeset .hero-badges {
  margin-bottom: 2rem;
}
</style>

<div class="hero-title">
Blue-Tap
</div>
<p class="hero-tagline">
Bluetooth &amp; BLE penetration testing toolkit purpose-built for automotive IVI systems.
</p>

<div class="hero-badges" markdown>

[![Version](https://img.shields.io/badge/version-2.6.0-indigo?style=flat-square)](#)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.10-3776AB?style=flat-square&logo=python&logoColor=white)](#)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20(Kali)-557C94?style=flat-square&logo=kalilinux&logoColor=white)](#)
[![Modules](https://img.shields.io/badge/modules-101-cyan?style=flat-square)](#)

</div>

---

## Why Blue-Tap?

Automotive infotainment (IVI) systems present a unique attack surface. They run legacy Bluetooth stacks, expose sensitive profiles like phonebook access and messaging, and often lack the security hardening found in modern mobile devices. Standard Bluetooth security tools focus on individual protocol tests -- Blue-Tap combines discovery, vulnerability assessment, exploitation, post-exploitation, and fuzzing into a single operator workflow designed specifically for automotive targets.

Blue-Tap operates at two layers. At the **host level**, it uses standard BlueZ APIs and raw HCI sockets to cover everything from device discovery through data extraction. At the **controller level**, its DarkFirmware capability patches RTL8761B adapters to reach the Link Manager Protocol and Link Controller -- the 40-45% of Bluetooth CVEs that are invisible to host-only tools.

---

## Key Capabilities

<div class="grid cards" markdown>

-   :material-radar: **Discovery & Reconnaissance**

    ---

    Classic and BLE device scanning, service enumeration, profile fingerprinting, and deep target analysis across 14+ Bluetooth profiles. Identifies open RFCOMM channels, exposed SDP services, and unauthenticated GATT characteristics that reveal a target's attack surface before any active testing begins.

-   :material-shield-bug-outline: **Vulnerability Assessment**

    ---

    21+ CVE detections covering KNOB, BIAS, BLURtooth, BlueBorne, and more. 30 denial-of-service checks targeting L2CAP, SDP, RFCOMM, and BNEP. Each finding includes severity classification, affected protocol, and remediation guidance -- structured for direct inclusion in pentest reports.

-   :material-bug-outline: **Protocol Fuzzing**

    ---

    16-protocol mutation fuzzer with crash detection, corpus management, and coverage-guided strategies. 6,685+ seeds across Classic and BLE protocols. The fuzzer tracks crashes, deduplicates findings, and produces structured crash reports suitable for CVE triage.

-   :material-hammer-wrench: **Exploitation & Post-Exploitation**

    ---

    Active attacks, encryption downgrades, audio eavesdropping (A2DP/HFP), contact extraction (PBAP/MAP), file transfer (OPP), and media control (AVRCP). Post-exploitation modules demonstrate real-world impact -- from silently recording phone calls to exfiltrating an entire phonebook.

-   :material-chip: **DarkFirmware (Below-HCI)**

    ---

    RTL8761B firmware patching for LMP injection, link-layer monitoring, and memory read/write -- reaching the 40-45% of CVEs invisible to host-level tools. Enables BrakTooth-style oversized LMP, in-flight packet modification, and direct controller memory inspection.

-   :material-file-chart-outline: **Reporting & Sessions**

    ---

    Professional HTML and JSON reports with per-module adapters. Persistent session management for multi-phase pentests and repeatable workflows. Named sessions let you pause an assessment and resume it later with full state preserved.

</div>

---

## Architecture

The toolkit is organized into four layers. **Interfaces** handle user interaction -- the CLI, report generation, and playbook automation. **Modules** contain all domain behavior, grouped by operator workflow phase. **Framework** provides the stable contracts, module registry, envelope builders, and reporting infrastructure that modules depend on. **Hardware** abstracts adapter management, scanning, spoofing, and DarkFirmware controller access.

```mermaid
mindmap
  root((Blue-Tap))
    Interfaces
      CLI
        Click commands
      ReportGenerator
        HTML / JSON
      PlaybookLoader
        Automation
    Modules
      discovery
      reconnaissance
      assessment
      exploitation
      post_exploitation
      fuzzing
    Framework
      contracts
        RunEnvelope
        ExecutionRecord
      registry
        ModuleDescriptor
      envelopes
      reporting
        adapters
        renderers
      sessions
      runtime
    Hardware
      adapter
      scanner
      spoofer
      DarkFirmware
        RTL8761B
      OBEX client
```

Data flows top-down: the CLI dispatches commands to modules, modules use framework contracts to structure their results as `RunEnvelope` objects, and report adapters transform those envelopes into human-readable output. Every module registers itself via `ModuleDescriptor`, which means the registry, CLI, and reporting layer discover modules automatically -- no hardcoded lists.

For a deeper dive into the architecture, see the [Architecture Overview](developer/architecture.md).

---

## Quick Links

<div class="grid cards" markdown>

-   :material-rocket-launch-outline: **Getting Started**

    ---

    Install Blue-Tap, set up your hardware, and run your first scan in under 10 minutes.

    [:octicons-arrow-right-24: Installation](getting-started/installation.md)

-   :material-book-open-variant: **User Guide**

    ---

    Full CLI reference and walk-throughs for every module family -- discovery through fuzzing.

    [:octicons-arrow-right-24: CLI Reference](guide/cli-reference.md)

-   :material-routes: **Workflows**

    ---

    End-to-end penetration test recipes -- from quick assessment to full campaign to audio eavesdropping.

    [:octicons-arrow-right-24: Full Pentest](workflows/full-pentest.md)

-   :material-shield-check-outline: **CVE Coverage**

    ---

    Detection matrix, DoS matrix, and the expansion roadmap for upcoming CVE coverage.

    [:octicons-arrow-right-24: Detection Matrix](cve/detection-matrix.md)

-   :material-puzzle-outline: **Developer Guide**

    ---

    Architecture deep-dive, module system internals, and how to write your own modules and report adapters.

    [:octicons-arrow-right-24: Architecture](developer/architecture.md)

-   :material-frequently-asked-questions: **Troubleshooting**

    ---

    Common issues with adapters, permissions, BlueZ compatibility, and Bluetooth stacks.

    [:octicons-arrow-right-24: Troubleshooting](reference/troubleshooting.md)

</div>

---

## At a Glance

| Dimension | Details |
|---|---|
| **Module families** | Discovery, Reconnaissance, Assessment, Exploitation, Post-Exploitation, Fuzzing |
| **Total modules** | 101 across 6 families |
| **CVE detections** | 21+ (KNOB, BIAS, BLURtooth, BlueBorne, Invalid Curve, and more) |
| **DoS checks** | 30 (L2CAP, SDP, RFCOMM, BNEP, AVCTP) |
| **Fuzzer protocols** | 16 (Classic + BLE) |
| **Fuzzer seeds** | 6,685+ |
| **Below-HCI** | RTL8761B via DarkFirmware (LMP injection, memory R/W, link-layer monitor) |
| **Output formats** | HTML report, JSON export, CLI live events |
| **Session support** | Persistent, multi-phase, resumable |

---

## Getting Started

The fastest path to a working setup:

1. **[Install Blue-Tap](getting-started/installation.md)** -- clone, pip install, verify with `blue-tap doctor`
2. **[Set up hardware](getting-started/hardware-setup.md)** -- configure your Bluetooth adapter and optional DarkFirmware
3. **[Run the quick start](getting-started/quick-start.md)** -- discover, recon, scan, and report in five commands
4. **[Try the IVI Simulator](getting-started/ivi-simulator.md)** -- practice against a deliberately vulnerable target with no real vehicle needed

---

!!! warning "Legal Disclaimer"

    Blue-Tap is a **security research and authorized penetration testing tool**. Use it only against devices you own or have explicit written authorization to test. Unauthorized access to Bluetooth devices is illegal in most jurisdictions. The authors assume no liability for misuse.

!!! info "License"

    Blue-Tap is released under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE](https://github.com/Indspl0it/blue-tap/blob/main/LICENSE) for the full text.

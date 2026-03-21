"""Interactive device picker — scan and select Bluetooth devices by number."""


from bt_tap.utils.output import (
    console, info, success, warning, error,
    device_table, section, CYAN, PURPLE,
)


# Cache last scan results so we don't re-scan within the same session
_cached_devices: list[dict] = []


def _scan_devices(scan_duration: int = 8, hci: str = "hci0",
                    include_ble: bool = False) -> list[dict]:
    """Run a BT scan and return device list."""
    global _cached_devices

    section("Device Discovery", style="bt.cyan")

    if include_ble:
        from bt_tap.core.scanner import scan_all
        info(f"Scanning Classic + BLE ({scan_duration}s)...")
        devices = scan_all(scan_duration, hci)
    else:
        from bt_tap.core.scanner import scan_classic
        info(f"Scanning Classic BT ({scan_duration}s)...")
        devices = scan_classic(scan_duration, hci)

    if devices:
        _cached_devices = devices
        success(f"Found {len(devices)} device(s)")
    else:
        warning("No devices found — check adapter is up and nearby devices are discoverable")

    return devices


def pick_device(
    prompt: str = "Select device",
    scan_duration: int = 8,
    hci: str = "hci0",
    rescan: bool = False,
) -> str | None:
    """Scan for devices and let the user pick one by number.

    Returns the selected MAC address, or None if cancelled.
    Reuses cached scan results if available (pass rescan=True to force).
    """
    devices = _cached_devices if (_cached_devices and not rescan) else _scan_devices(scan_duration, hci)

    if not devices:
        return None

    # Show numbered table
    console.print(device_table(devices))
    console.print()

    # Prompt for selection
    while True:
        try:
            choice = console.input(
                f"  [{CYAN}]?[/{CYAN}]  {prompt} "
                f"[{PURPLE}][1-{len(devices)}][/{PURPLE}] "
                f"[dim](r=rescan, q=quit)[/dim]: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if choice.lower() == "q":
            return None

        if choice.lower() == "r":
            devices = _scan_devices(scan_duration, hci)
            if not devices:
                return None
            console.print(device_table(devices))
            console.print()
            continue

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                selected = devices[idx]
                addr = selected.get("address", "")
                name = selected.get("name", "Unknown")
                success(f"Selected: {name} ({addr})")
                return addr
            else:
                error(f"Enter a number between 1 and {len(devices)}")
        except ValueError:
            error("Enter a valid number, 'r' to rescan, or 'q' to quit")


def pick_two_devices(
    prompt1: str = "Select TARGET (IVI/Car)",
    prompt2: str = "Select VICTIM (Phone/Driver)",
    scan_duration: int = 10,
    hci: str = "hci0",
) -> tuple[str, str] | None:
    """Scan for devices and let the user pick two: target IVI and victim phone.

    Returns (ivi_address, phone_address) or None if cancelled.
    """
    devices = _scan_devices(scan_duration, hci)

    if not devices:
        return None

    if len(devices) < 2:
        warning("Need at least 2 devices for target + victim selection")
        warning("Only 1 device found — you can still select it as target")

    # Show table
    console.print(device_table(devices))
    console.print()

    # Pick first device (IVI)
    ivi_addr = _pick_from_list(devices, prompt1)
    if not ivi_addr:
        return None

    # Pick second device (Phone) — show remaining
    remaining = [d for d in devices if d.get("address") != ivi_addr]
    if not remaining:
        error("No other devices to select as victim")
        console.print()
        manual = console.input(
            f"  [{CYAN}]?[/{CYAN}]  Enter victim MAC manually "
            f"[dim](or q to quit)[/dim]: "
        ).strip()
        if manual.lower() == "q" or not manual:
            return None
        from bt_tap.utils.bt_helpers import validate_mac
        cleaned = manual.replace("-", ":").upper()
        if not validate_mac(cleaned):
            error(f"Invalid MAC address: {manual}")
            return None
        return (ivi_addr, cleaned)

    console.print()
    info("Remaining devices:")
    console.print(device_table(remaining))
    console.print()

    phone_addr = _pick_from_list(remaining, prompt2)
    if not phone_addr:
        return None

    return (ivi_addr, phone_addr)


def _pick_from_list(devices: list[dict], prompt: str) -> str | None:
    """Pick a device from an already-displayed list."""
    while True:
        try:
            choice = console.input(
                f"  [{CYAN}]?[/{CYAN}]  {prompt} "
                f"[{PURPLE}][1-{len(devices)}][/{PURPLE}] "
                f"[dim](q=quit)[/dim]: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if choice.lower() == "q":
            return None

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                selected = devices[idx]
                addr = selected.get("address", "")
                name = selected.get("name", "Unknown")
                success(f"Selected: {name} ({addr})")
                return addr
            else:
                error(f"Enter a number between 1 and {len(devices)}")
        except ValueError:
            error("Enter a valid number or 'q' to quit")


def resolve_address(
    address: str | None,
    prompt: str = "Select device",
    scan_duration: int = 8,
    hci: str = "hci0",
) -> str | None:
    """Return address if provided, otherwise launch interactive picker.

    Validates MAC format when provided. Returns None on invalid input.

    Usage in CLI commands:
        address = resolve_address(address)
        if not address:
            return
    """
    if address:
        from bt_tap.utils.bt_helpers import validate_mac
        # Normalize common separators before validation
        cleaned = address.replace("-", ":").upper()
        if not validate_mac(cleaned):
            from bt_tap.utils.output import error
            error(f"Invalid MAC address: {address}")
            return None
        return cleaned
    return pick_device(prompt=prompt, scan_duration=scan_duration, hci=hci)

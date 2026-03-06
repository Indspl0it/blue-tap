#!/usr/bin/env python3
import subprocess
import os

SCAN_RESULTS_FILE = "bluetooth_devices_scan_results.txt"

def read_scan_results(file_path):
    """Read and parse the scan results from the file."""
    devices = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split("\t")
                if len(parts) == 2:
                    address, name = parts
                    devices.append((address.strip(), name.strip()))
        return devices
    except FileNotFoundError:
        print(f"[ERROR] Scan results file not found: {file_path}")
        return []
    except Exception as e:
        print(f"[ERROR] Failed to read scan results: {e}")
        return []

def check_ssp_support(address):
    """Checks if Secure Simple Pairing (SSP) is supported by the target device."""
    try:
        print(f"\n[INFO] Scanning services on the target device: {address}...")
        result = subprocess.run(
            ["sdptool", "browse", address],
            capture_output=True,
            text=True,
            errors="replace"
        )

        if result.returncode != 0:
            print(f"[ERROR] Failed to connect to device {address}. Error: {result.stderr.strip()}")
            return None  # Return None to indicate an error occurred

        output = result.stdout

        # Save the output to a file with "bluetooth_" prefix
        file_name = f"bluetooth_{address.replace(':', '_')}.txt"
        with open(file_name, "w", encoding="utf-8", errors="replace") as file:
            file.write(output)

        print(f"[INFO] SDP information saved to file: {file_name}")

        # Check if SSP is mentioned in the SDP records
        if "Simple Pairing" in output or "Secure Simple Pairing" in output:
            print(f"\n[RESULT] Target device {address} may support SSP based on service descriptions.")
            return True  # SSP is supported
        else:
            print(f"\n[RESULT] Target device {address} unable to confirm SSP support from service records. Check device specifications or pairing behavior.")
            return False  # SSP is not supported
    except Exception as e:
        print(f"[ERROR] An error occurred while checking SSP support for {address}: {e}")
        return None  # Return None to indicate an error occurred

def main():
    print("=" * 50)
    print("          Bluetooth SSP Support Checker")
    print("=" * 50)

    # Read scan results
    devices = read_scan_results(SCAN_RESULTS_FILE)

    if not devices:
        print("[ERROR] No devices found in scan results. Please run the scan script first.")
        return

    print("\nAvailable Bluetooth devices:")
    for idx, (address, name) in enumerate(devices, 1):
        print(f"{idx}. {address} - {name}")

    # Prompt user to select a device
    while True:
        try:
            choice = int(input("\nEnter the number of the device to check SSP support: "))
            if 1 <= choice <= len(devices):
                target_address = devices[choice - 1][0]
                break
            else:
                print("[ERROR] Invalid choice. Please select a valid device number.")
        except ValueError:
            print("[ERROR] Invalid input. Please enter a number.")

    print(f"\n[INFO] Target device address: {target_address}")

    # Check SSP support and handle connection errors
    try:
        is_ssp_supported = check_ssp_support(target_address)

        if is_ssp_supported is True:
            print("\n[INFO] The device is more secure due to SSP support.")
        elif is_ssp_supported is False:
            print("\n[WARNING] The device may be vulnerable need further investigation.")
        else:
            print("\n[ERROR] Unable to determine SSP support due to an error or connection issue.")

    except Exception as e:
        print(f"[ERROR] Script failed to run: {e}")

    print("=" * 50)
    print("                 Scan Complete")
    print("=" * 50)

if __name__ == "__main__":
    main()

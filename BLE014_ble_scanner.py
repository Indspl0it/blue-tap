#!/usr/bin/env python3
import asyncio
import sys
from bleak import BleakScanner

def get_scan_time():
    """Prompt the user for scan time if not provided via command-line."""
    while True:
        try:
            scan_time = int(input("Enter scan time in seconds: "))
            if scan_time > 0:
                return scan_time
            else:
                print("Please enter a positive integer.")
        except ValueError:
            print("Invalid input. Please enter a positive integer.")

async def scan(timeout):
    """Perform a Bluetooth scan for the given timeout."""
    return await BleakScanner.discover(timeout=timeout)

def save_to_file(devices, filename="ble_service_scan_results.txt"):
    """Save the scan results to a text file."""
    try:
        with open(filename, "w") as file:
            for d in devices:
                file.write(f"Address: {d.address}\n")
                file.write(f"\tName: {d.name}\n")
                file.write(f"\tRSSI: {d.rssi}\n\n")
        print(f"Scan results saved to {filename}")
    except Exception as e:
        print(f"Error saving to file: {e}")

if __name__ == "__main__":
    # Check if scan time is provided via command-line arguments
    if len(sys.argv) > 1:
        try:
            timeout = int(sys.argv[1])
            if timeout <= 0:
                raise ValueError
        except ValueError:
            print("Invalid scan time. Please provide a positive integer.")
            sys.exit(1)
    else:
        # Prompt user for scan time
        timeout = get_scan_time()

    # Perform the scan
    print(f"Scanning for {timeout} seconds...")
    devices = asyncio.run(scan(timeout))

    # Sort devices by RSSI in descending order
    devices = sorted(devices, key=lambda k: k.rssi, reverse=True)

    # Display scan results
    for d in devices:
        print(f"Address: {d.address}")
        print(f"\tName: {d.name}")
        print(f"\tRSSI: {d.rssi}")

    # Save scan results to a file
    save_to_file(devices)

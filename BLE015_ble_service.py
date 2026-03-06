#!/usr/bin/env python3
import re
import os
import asyncio
from bleak import BleakClient, BleakScanner

def load_devices_from_file(filename="ble_service_scan_results.txt"):
    """Load devices (address and name) from the scan results file."""
    devices = []
    try:
        with open(filename, "r") as file:
            content = file.read()
            
            # Match device blocks with Address, Name, and RSSI
            device_blocks = re.findall(r"Address: ([0-9A-Fa-f:]+)\n\s*Name: (.+?)\n\s*RSSI: -?\d+", content)
            
            for address, name in device_blocks:
                devices.append((address.strip(), name.strip()))
    except FileNotFoundError:
        print(f"File {filename} not found.")
    return devices

async def get_services(address):
    """Fetch the services of the BLE device."""
    async with BleakClient(address) as client:
        services = await client.get_services()
        return services

def save_to_file(filename, address, name, content):
    """Save the output to a file, including the address and name on the first line."""
    with open(filename, "w") as file:
        file.write(f"Address: {address}\n")
        file.write(f"Name: {name}\n")
        file.write("\n")  # Adds an extra line after the address and name
        file.write(content)

def select_device(devices):
    """Prompt the user to select a device from the list."""
    print("\nAvailable Devices:")
    for index, (address, name) in enumerate(devices, start=1):
        print(f"{index}. Address: {address}, Name: {name}")

    while True:
        try:
            choice = int(input("\nSelect the device number: "))
            if 1 <= choice <= len(devices):
                return devices[choice - 1]
            else:
                print(f"Invalid choice. Please select a number between 1 and {len(devices)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def main():
    # Load devices from the scan results file
    devices = load_devices_from_file()

    if not devices:
        print("No devices found in the file.")
        return

    # Let the user select a device
    selected_address, selected_name = select_device(devices)

    # Run the asyncio function to get services
    print(f"Fetching services for device {selected_name} ({selected_address})...")
    services = asyncio.run(get_services(selected_address))

    # Check if services were found
    if not services:
        print("Device not found or unable to connect.")
        return

    # Prepare the output content
    output = []
    for service in services:
        output.append(str(service))
        for char in service.characteristics:
            output.append(str(char))
            output.append(str(char.properties))

    # Save to a file named after the MAC address
    filename = f"{selected_address.replace(':', '_')}_services.txt"
    save_to_file(filename, selected_address, selected_name, "\n".join(output))

    print(f"Service details saved to {filename}")

if __name__ == "__main__":
    main()

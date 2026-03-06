#!/usr/bin/env python3

import os
import subprocess
import re

def list_hci_adapters():
    """List all available HCI Bluetooth adapters on the system."""
    try:
        result = subprocess.run(["hciconfig"], capture_output=True, text=True)
        output = result.stdout
        # Parse HCI adapters from the output
        adapters = re.findall(r"^(hci\d+):\s", output, re.MULTILINE)
        return adapters
    except Exception as e:
        print(f"Error listing HCI adapters: {e}")
        return []

def spoof_bluetooth_address(hci_adapter, new_address):
    """Spoof the Bluetooth address using the bdaddr tool and reset the adapter."""
    try:
        # Spoof the Bluetooth address
        subprocess.run(["sudo", "bdaddr", "-i", hci_adapter, new_address], check=True)

        # Reset and bring the HCI adapter down and up
        subprocess.run(["sudo", "hciconfig", hci_adapter, "reset"], check=True)
        subprocess.run(["sudo", "hciconfig", hci_adapter, "down"], check=True)
        subprocess.run(["sudo", "hciconfig", hci_adapter, "up"], check=True)

        print(f"Successfully spoofed {hci_adapter} to {new_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error spoofing Bluetooth address: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def load_addresses_from_bluetooth_file(file_path):
    """Load addresses and names from the Bluetooth Classic file."""
    entries = []
    try:
        with open(file_path, "r") as file:
            content = file.readlines()
            for line in content:
                # Extract address and name
                match = re.match(r"^([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
                if match:
                    address = match.group(1)
                    name = match.group(2).strip()
                    entries.append((address, name))
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    return entries

def load_addresses_from_ble_file(file_path):
    """Load addresses and names from the BLE file."""
    entries = []
    try:
        with open(file_path, "r") as file:
            content = file.read()
            # Extract blocks of BLE addresses
            matches = re.findall(r"Address:\s([0-9A-Fa-f:]{17})\n\s*Name:\s(.*?)\n", content, re.DOTALL)
            for match in matches:
                address, name = match
                entries.append((address.strip(), name.strip()))
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    return entries

def select_address(entries):
    """Prompt the user to select an address from the available list."""
    print("\nAvailable addresses:")
    for idx, (address, name) in enumerate(entries, start=1):
        print(f"{idx}. {address} - {name}")

    while True:
        try:
            choice = int(input("\nSelect an address to spoof by number: "))
            if 1 <= choice <= len(entries):
                return entries[choice - 1][0]  # Return only the address
            else:
                print(f"Invalid choice. Please select a number between 1 and {len(entries)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def main():
    # Ask user to select Bluetooth type or manual input
    print("Select Bluetooth type or input MAC address manually:")
    print("1. Bluetooth (Classic)") 
    print("2. Bluetooth Low Energy (BLE)")
    print("3. Enter MAC address manually")

    while True:
        try:
            choice = int(input("Enter your choice (1, 2, or 3): "))
            if choice == 1:
                file_path = "bluetooth_devices_scan_results.txt"
                break
            elif choice == 2:
                file_path = "ble_service_scan_results.txt"
                break
            elif choice == 3:
                file_path = None  # Manual address input, no file needed
                break
            else:
                print("Invalid choice. Please select 1, 2, or 3.")
        except ValueError:
            print("Invalid input. Please enter 1, 2, or 3.")

    # If the user chose to manually input the MAC address
    if file_path is None:
        while True:
            selected_address = input("Enter the MAC address to spoof (e.g., 00:11:22:33:44:55): ").strip()
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", selected_address):
                break
            else:
                print("Invalid Bluetooth address format. Please try again.")
    else:
        # Load addresses based on the file type
        if choice == 1:
            entries = load_addresses_from_bluetooth_file(file_path)
        else:
            entries = load_addresses_from_ble_file(file_path)

        if not entries:
            print(f"No addresses found in {file_path}. Make sure the file is present and contains addresses.")
            return

        # Prompt user to select an address from the loaded file
        selected_address = select_address(entries)

    # List available HCI adapters
    adapters = list_hci_adapters()

    if not adapters:
        print("No HCI adapters found. Make sure Bluetooth is enabled.")
        return

    # Display available adapters
    print("Available HCI adapters:")
    for idx, adapter in enumerate(adapters, start=1):
        print(f"{idx}. {adapter}")

    # Prompt user to select an adapter
    while True:
        try:
            choice = int(input("Select an HCI adapter by number: "))
            if 1 <= choice <= len(adapters):
                hci_adapter = adapters[choice - 1]
                break
            else:
                print("Invalid choice. Please select a valid adapter number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Now, use the selected address as the new address to spoof
    print(f"Selected address for spoofing: {selected_address}")

    # Attempt to spoof the Bluetooth address
    spoof_bluetooth_address(hci_adapter, selected_address)

if __name__ == "__main__":
    main()

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
        print(output)  # Display the hciconfig output
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

def main():
    # Hardcoded Bluetooth address to spoof
    new_address = "6C:F6:DA:3F:09:CA" 
    # List all available HCI adapters
    adapters = list_hci_adapters()

    if not adapters:
        print("No HCI adapters found. Make sure Bluetooth is enabled.")
        return

    # Display available adapters
    print("Available HCI adapters:")
    for idx, adapter in enumerate(adapters):
        print(f"{idx + 1}. {adapter}")

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

    # Display the address being spoofed
    print(f"Spoofing the Bluetooth address to: {new_address}")

    # Attempt to spoof the Bluetooth address
    spoof_bluetooth_address(hci_adapter, new_address)

if __name__ == "__main__":
    main()

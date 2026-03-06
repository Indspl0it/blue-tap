#!/usr/bin/env python3
import re
import asyncio
import os
from bleak import BleakClient

def list_available_files(directory="."):
    """List all files in the given directory."""
    try:
        files = [f for f in os.listdir(directory) if f.endswith('_services.txt')]
        return files
    except FileNotFoundError:
        print(f"Directory {directory} not found.")
        return []

def load_address_and_uuids_from_file(filename):
    """Load the MAC address, name, and UUIDs from the output file."""
    address = None
    name = None
    uuids = []
    try:
        with open(filename, "r") as file:
            content = file.read()
            # Extract the MAC address and name
            address_match = re.search(r"Address: ([0-9A-Fa-f:]+)", content)
            name_match = re.search(r"Name: ([0-9A-Fa-f-]+)", content)
            
            if address_match and name_match:
                address = address_match.group(1)
                name = name_match.group(1)
            
            # Extract UUIDs with additional information
            uuid_entries = re.findall(r"([0-9a-fA-F-]{36}) \(Handle: \d+\): (\w+)", content)
            for uuid, description in uuid_entries:
                uuids.append((uuid, description))
    except FileNotFoundError:
        print(f"File {filename} not found.")
    return address, name, uuids

async def read(address, uuid):
    """Read the GATT characteristic from the BLE device."""
    client = BleakClient(address)
    data = False
    try:
        await client.connect()
        data = await client.read_gatt_char(uuid)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.disconnect()
    return data

def select_file(files):
    """Prompt the user to select an output file."""
    print("\nAvailable output files:")
    for index, file in enumerate(files, start=1):
        print(f"{index}. {file}")

    while True:
        try:
            choice = int(input("\nSelect the file number: "))
            if 1 <= choice <= len(files):
                return files[choice - 1]
            else:
                print(f"Invalid choice. Please select a number between 1 and {len(files)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def select_uuid(uuids):
    """Prompt the user to select a UUID from the list."""
    print("\nAvailable UUIDs:")
    for index, (uuid, description) in enumerate(uuids, start=1):
        print(f"{index}. {uuid} - {description}")

    while True:
        try:
            choice = int(input("\nSelect the UUID number: "))
            if 1 <= choice <= len(uuids):
                return uuids[choice - 1][0]  # Return only the UUID
            else:
                print(f"Invalid choice. Please select a number between 1 and {len(uuids)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def main():
    # List available files
    files = list_available_files()

    if not files:
        print("No output files found.")
        return

    # Let the user select a file
    selected_file = select_file(files)

    # Load the MAC address, name, and UUIDs from the selected file
    address, name, uuids = load_address_and_uuids_from_file(selected_file)

    if not address or not name:
        print("MAC address or Name not found in the file. Exiting.")
        return

    # Display the selected address and name
    print(f"\nSelected MAC Address: {address}")
    print(f"Selected Name: {name}")

    if not uuids:
        print("No UUIDs found in the file.")
        return

    # Let the user select a UUID from the list
    selected_uuid = select_uuid(uuids)

    # Read the selected UUID
    print(f"Reading characteristic with UUID: {selected_uuid}...")
    data = asyncio.run(read(address, selected_uuid))

    if not data:
        print("Data not found or failed to read.")
    else:
        # Format the output
        hex_data = ''.join(format(x, '02x') for x in data)
        string_data = ''.join(chr(b) if 32 <= b <= 127 else '.' for b in data)

        # Print the results
        print("HEX: " + hex_data)
        print("STRING: " + string_data)

if __name__ == "__main__":
    main()

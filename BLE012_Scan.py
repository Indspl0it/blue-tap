import subprocess

def scan_bluetooth(output_file="bluetooth_devices_scan_results.txt"):
    try:
        print("Scanning for Bluetooth devices...")
        # Run the hcitool scan command
        result = subprocess.run(["hcitool", "scan"], capture_output=True, text=True)

        # Check if the scan was successful
        if result.returncode != 0:
            print("Error scanning Bluetooth devices. Make sure Bluetooth is enabled.")
            return

        # Print the scan results to the console
        print("\nScan Results:")
        print(result.stdout)

        # Write the scan results to a file
        with open(output_file, "w") as file:
            file.write(result.stdout)

        print(f"\nScan completed. Results saved in {output_file}.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    scan_bluetooth()

"""Rich console output helpers."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


def banner():
    """Print the BT-Tap banner."""
    text = Text()
    text.append("BT-Tap", style="bold cyan")
    text.append(" v0.1.0\n", style="dim")
    text.append("Bluetooth/BLE Penetration Testing Toolkit\n", style="white")
    text.append("Automotive IVI Attack Framework", style="dim yellow")
    console.print(Panel(text, border_style="cyan", padding=(1, 2)))


def info(msg: str):
    console.print(f"[cyan][*][/cyan] {msg}")


def success(msg: str):
    console.print(f"[green][+][/green] {msg}")


def warning(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")


def error(msg: str):
    console.print(f"[red][-][/red] {msg}")


def device_table(devices: list[dict], title: str = "Discovered Devices") -> Table:
    """Create a rich table of discovered devices."""
    table = Table(title=title, show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Address", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("RSSI", style="yellow", justify="right")
    table.add_column("Type", style="magenta")
    for i, dev in enumerate(devices, 1):
        table.add_row(
            str(i),
            dev.get("address", "N/A"),
            dev.get("name", "Unknown"),
            str(dev.get("rssi", "N/A")),
            dev.get("type", "Classic"),
        )
    return table


def service_table(services: list[dict], title: str = "Services") -> Table:
    """Create a rich table of discovered services."""
    table = Table(title=title, show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Name", style="green")
    table.add_column("Protocol", style="cyan")
    table.add_column("Channel/PSM", style="yellow", justify="right")
    table.add_column("Profile", style="magenta")
    for i, svc in enumerate(services, 1):
        table.add_row(
            str(i),
            svc.get("name", "Unknown"),
            svc.get("protocol", "N/A"),
            str(svc.get("channel", "N/A")),
            svc.get("profile", ""),
        )
    return table

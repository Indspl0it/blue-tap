"""Bundled playbooks for common Bluetooth pentest workflows."""

from importlib import resources


def list_playbooks() -> list[str]:
    """List available bundled playbook names."""
    return sorted(
        f.name for f in resources.files(__package__).iterdir()
        if f.name.endswith('.yaml')
    )


def get_playbook_path(name: str) -> str:
    """Get path to a bundled playbook file."""
    if not name.endswith('.yaml'):
        name += '.yaml'
    return str(resources.files(__package__).joinpath(name))

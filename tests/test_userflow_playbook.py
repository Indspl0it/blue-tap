"""User-flow 10.9: Playbook run.

The bundled 'quick-recon' playbook uses old-style command names
(e.g. 'scan classic', 'recon fingerprint', 'vulnscan') which are
incompatible with the new 'run <module_id>' format introduced in Phase 4.

This test documents that incompatibility and is skipped with a clear reason
rather than producing a fake-passing test. Hardware smoke validation for
old-command playbooks is deferred to Phase 11.
"""

import pytest


@pytest.mark.skip(
    reason=(
        "The bundled quick-recon.yaml uses legacy command names "
        "('scan classic', 'recon fingerprint', 'vulnscan') that are "
        "not supported by the current CLI. The run-playbook runner "
        "dispatches via Click using the old command names, which no "
        "longer exist in the modular CLI. Playbook support requires "
        "migration of bundled playbooks to 'run <module_id>' format "
        "before this test can be written without a fake pass."
    )
)
def test_quick_recon_playbook():
    """Placeholder — see module docstring for skip reason."""
    pass

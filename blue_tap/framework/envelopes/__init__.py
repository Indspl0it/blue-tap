"""Family-specific envelope builders that produce RunEnvelope instances for each module type."""

from blue_tap.framework.envelopes.attack import build_attack_result, artifact_if_file as attack_artifact_if_file
from blue_tap.framework.envelopes.audio import build_audio_result, artifact_if_file as audio_artifact_if_file
from blue_tap.framework.envelopes.data import build_data_result, artifact_if_path as data_artifact_if_path
from blue_tap.framework.envelopes.firmware import (
    make_firmware_run_id,
    build_firmware_status_result,
    build_firmware_dump_result,
    build_connection_inspect_result,
    build_firmware_operation_result,
)
from blue_tap.framework.envelopes.fuzz import (
    make_fuzz_run_id,
    build_fuzz_result,
    build_fuzz_protocol_execution,
    build_fuzz_campaign_result,
    build_fuzz_operation_result,
    campaign_started_at_from_stats,
)
from blue_tap.framework.envelopes.recon import (
    summarize_recon_entries,
    build_recon_result,
    build_recon_execution,
)
from blue_tap.framework.envelopes.scan import (
    summarize_devices,
    build_scan_result,
)
from blue_tap.framework.envelopes.spoof import (
    make_spoof_run_id,
    build_spoof_result,
)

__all__ = [
    # attack
    "build_attack_result",
    "attack_artifact_if_file",
    # audio
    "build_audio_result",
    "audio_artifact_if_file",
    # data
    "build_data_result",
    "data_artifact_if_path",
    # firmware
    "make_firmware_run_id",
    "build_firmware_status_result",
    "build_firmware_dump_result",
    "build_connection_inspect_result",
    "build_firmware_operation_result",
    # fuzz
    "make_fuzz_run_id",
    "build_fuzz_result",
    "build_fuzz_protocol_execution",
    "build_fuzz_campaign_result",
    "build_fuzz_operation_result",
    "campaign_started_at_from_stats",
    # recon
    "summarize_recon_entries",
    "build_recon_result",
    "build_recon_execution",
    # scan
    "summarize_devices",
    "build_scan_result",
    # spoof
    "make_spoof_run_id",
    "build_spoof_result",
]

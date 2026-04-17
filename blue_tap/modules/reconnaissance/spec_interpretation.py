"""Spec-driven interpretation helpers for recon protocol evidence.

Owns ``interpret_rfcomm_probe``, ``interpret_l2cap_probe``,
``interpret_lmp_capture``, ``interpret_ble_capture``,
``evaluate_smp_transcript``, and ``normalize_smp_message`` — all consumed
by correlation — plus the native internal ``SpecInterpretationModule``.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptChoice, OptPath
from blue_tap.framework.registry import ModuleFamily
from blue_tap.modules.fuzzing.protocols.smp import (
    AUTH_MITM,
    AUTH_SC,
    FAILURE_REASON_NAMES,
    IO_CAPABILITY_NAMES,
    IO_DISPLAY_YESNO,
    IO_KEYBOARD_DISPLAY,
    IO_KEYBOARD_ONLY,
    IO_NO_INPUT_OUTPUT,
    OOB_PRESENT,
    SMP_PAIRING_FAILED,
    SMP_PAIRING_REQUEST,
    SMP_PAIRING_RESPONSE,
)

logger = logging.getLogger(__name__)


def interpret_rfcomm_probe(result: dict[str, Any], *, advertised: bool = False) -> dict[str, Any]:
    response_type = str(result.get("response_type", "unknown"))
    status = str(result.get("status", "unknown"))
    protocol_hints = [str(item) for item in result.get("protocol_hints", []) or []]

    interpretation = {
        "service_family": "unknown",
        "expected_profiles": [],
        "exposure": "advertised_surface" if advertised else "unadvertised_surface",
        "posture": "indeterminate",
        "notes": [],
    }

    if status != "open":
        interpretation["posture"] = {
            "auth_required": "gated_or_authenticated_surface",
            "timeout": "filtered_or_slow_surface",
            "host_unreachable": "transport_unreachable",
            "closed": "refused_surface",
        }.get(status, "indeterminate")
        interpretation["notes"].append(f"rfcomm_status={status}")
        return interpretation

    interpretation["posture"] = "preauth_reachable_surface"
    if response_type == "at_modem":
        interpretation["service_family"] = "telephony_control"
        interpretation["expected_profiles"] = ["HFP", "HSP", "vendor_modem_control"]
        interpretation["notes"].append("AT-style exchange is typical of telephony control over RFCOMM")
    elif response_type == "obex":
        interpretation["service_family"] = "object_exchange"
        interpretation["expected_profiles"] = ["OPP", "PBAP", "MAP", "FTP"]
        interpretation["notes"].append("OBEX framing is typical of object transfer over RFCOMM")
    elif response_type == "text_banner":
        interpretation["service_family"] = "textual_application"
        interpretation["expected_profiles"] = ["vendor_console", "diagnostic_shell", "application_banner"]
        interpretation["notes"].append("Text banner suggests an application-layer RFCOMM service")
    elif response_type == "silent_open":
        interpretation["service_family"] = "deferred_session"
        interpretation["expected_profiles"] = ["interactive_protocol", "binary_application"]
        interpretation["notes"].append("RFCOMM opened cleanly but did not send an immediate banner")
    elif response_type == "raw_binary":
        interpretation["service_family"] = "binary_application"
        interpretation["expected_profiles"] = ["vendor_binary_protocol", "stream_or_tunnel"]
        interpretation["notes"].append("Binary reply suggests a non-AT application protocol")

    if "at_command_surface" in protocol_hints:
        interpretation["notes"].append("Spec-compatible AT command surface observed")
    if "object_transfer" in protocol_hints:
        interpretation["notes"].append("Spec-compatible OBEX object transfer surface observed")

    return interpretation


def interpret_l2cap_probe(result: dict[str, Any], *, advertised: bool = False) -> dict[str, Any]:
    psm = int(result.get("psm", 0) or 0)
    status = str(result.get("status", "unknown"))
    protocol_family = str(result.get("protocol_family", "unknown"))
    behavior_hint = str(result.get("behavior_hint", ""))

    interpretation = {
        "service_family": protocol_family or "unknown",
        "exposure": "advertised_surface" if advertised else "unadvertised_surface",
        "posture": "indeterminate",
        "spec_role": "",
        "notes": [],
    }

    if status == "open":
        interpretation["posture"] = "reachable_surface"
    elif status == "auth_required":
        interpretation["posture"] = "gated_or_authenticated_surface"
    elif status == "timeout":
        interpretation["posture"] = "filtered_or_slow_surface"
    elif status == "host_unreachable":
        interpretation["posture"] = "transport_unreachable"
    else:
        interpretation["posture"] = "refused_surface"

    if psm == 1:
        interpretation["spec_role"] = "sdp_signaling"
        interpretation["notes"].append("PSM 0x0001 is the standard SDP signaling endpoint")
    elif psm == 3:
        interpretation["spec_role"] = "rfcomm_multiplexer"
        interpretation["notes"].append("PSM 0x0003 is the RFCOMM multiplexer bearer")
    elif psm in {15, 17}:
        interpretation["spec_role"] = "hid_channel"
        interpretation["notes"].append("PSM is within the HID control/interrupt pair")
    elif psm in {23, 25, 27}:
        interpretation["spec_role"] = "av_control_or_media"
        interpretation["notes"].append("PSM aligns with AVCTP/AVDTP media-control roles")
    elif psm == 31:
        interpretation["spec_role"] = "att_bearer"
        interpretation["notes"].append("PSM 0x001f is the ATT bearer used by BLE GATT")
    elif psm >= 4097:
        interpretation["spec_role"] = "dynamic_or_vendor_assigned"
        interpretation["notes"].append("Dynamic PSMs are commonly vendor-defined or session-assigned")

    if behavior_hint:
        interpretation["notes"].append(f"behavior_hint={behavior_hint}")
    return interpretation


def interpret_lmp_capture(analysis: dict[str, Any], *, pairing_mode: dict[str, Any] | None = None) -> dict[str, Any]:
    findings: list[str] = []
    posture = "limited_visibility"
    min_key_size = None
    observed_key_sizes = [int(size) for size in analysis.get("observed_key_sizes", []) if str(size).isdigit()]

    if analysis.get("feature_packets", 0):
        findings.append("classic_feature_exchange_visible")
    if analysis.get("auth_packets", 0):
        findings.append("classic_auth_exchange_visible")
    if analysis.get("encryption_packets", 0):
        findings.append("classic_encryption_negotiation_visible")
        posture = "security_negotiation_observed"
    if observed_key_sizes:
        min_key_size = min(observed_key_sizes)
        findings.append(f"min_observed_key_size={min_key_size}")
        if min_key_size < 7:
            findings.append("classic_key_size_below_recommended_minimum")
            posture = "weak_key_negotiation_observed"
    if analysis.get("bt_versions"):
        findings.append("classic_version_exchange_visible")

    if isinstance(pairing_mode, dict) and pairing_mode.get("ssp_supported") is False:
        findings.append("classic_legacy_pairing_possible")
    if isinstance(pairing_mode, dict):
        method = str(pairing_mode.get("pairing_method", "") or "")
        if method in {"Just Works", "Passkey Entry", "Numeric Comparison", "Out of Band (OOB)"}:
            findings.append(f"classic_pairing_method={method}")

    return {
        "layer": "lmp",
        "posture": posture,
        "findings": findings,
        "min_observed_key_size": min_key_size,
    }


def interpret_ble_capture(analysis: dict[str, Any], *, pairing_mode: dict[str, Any] | None = None) -> dict[str, Any]:
    findings: list[str] = []
    posture = "limited_visibility"
    source_counts = analysis.get("source_counts", {}) or {}
    signal_counts = analysis.get("signal_counts", {}) or {}

    if source_counts.get("ble", 0):
        findings.append("ble_link_activity_visible")
        posture = "ble_activity_observed"
    if signal_counts.get("pairing_or_auth_activity", 0):
        findings.append("ble_pairing_or_auth_activity_visible")
        posture = "ble_pairing_observed"
    if signal_counts.get("encryption_activity", 0):
        findings.append("ble_encryption_activity_visible")
    if signal_counts.get("feature_exchange_activity", 0):
        findings.append("ble_feature_activity_visible")
    if isinstance(pairing_mode, dict):
        method = str(pairing_mode.get("pairing_method", "") or "")
        if method == "Just Works":
            findings.append("ble_unauthenticated_association_model_possible")
        elif method:
            findings.append(f"ble_pairing_method={method}")

    return {
        "layer": "ble",
        "posture": posture,
        "findings": findings,
    }


def evaluate_smp_transcript(messages: list[dict[str, Any]]) -> dict[str, Any]:
    request = next((msg for msg in messages if msg.get("opcode") == SMP_PAIRING_REQUEST), None)
    response = next((msg for msg in messages if msg.get("opcode") == SMP_PAIRING_RESPONSE), None)
    failure = next((msg for msg in messages if msg.get("opcode") == SMP_PAIRING_FAILED), None)

    findings: list[str] = []
    posture = "ble_pairing_observed" if messages else "limited_visibility"
    negotiated_key_size = None
    secure_connections = None
    association_model = "unknown"
    crackability = "unknown"

    if request and response:
        req_auth = int(request.get("authreq", 0) or 0)
        rsp_auth = int(response.get("authreq", 0) or 0)
        secure_connections = bool((req_auth | rsp_auth) & AUTH_SC)
        req_key_size = int(request.get("max_enc_key_size", 0) or 0)
        rsp_key_size = int(response.get("max_enc_key_size", 0) or 0)
        if req_key_size and rsp_key_size:
            negotiated_key_size = min(req_key_size, rsp_key_size)
            findings.append(f"ble_negotiated_key_size={negotiated_key_size}")
            if negotiated_key_size < 7:
                findings.append("ble_key_size_below_recommended_minimum")
                posture = "ble_weak_pairing_parameters_observed"
        association_model = _infer_ble_association_model(request, response)
        findings.append(f"ble_association_model={association_model}")
        findings.append("ble_secure_connections=yes" if secure_connections else "ble_secure_connections=no")
        crackability = _infer_ble_crackability(secure_connections, association_model)
        findings.append(f"ble_crackability={crackability}")

    if failure:
        reason = int(failure.get("reason", 0) or 0)
        reason_name = FAILURE_REASON_NAMES.get(reason, f"0x{reason:02X}")
        findings.append(f"ble_pairing_failed_reason={reason_name}")

    return {
        "layer": "ble_smp",
        "posture": posture,
        "association_model": association_model,
        "secure_connections": secure_connections,
        "negotiated_key_size": negotiated_key_size,
        "crackability": crackability,
        "findings": findings,
    }


def _infer_ble_association_model(request: dict[str, Any], response: dict[str, Any]) -> str:
    req_oob = int(request.get("oob_data_flags", 0) or 0)
    rsp_oob = int(response.get("oob_data_flags", 0) or 0)
    if req_oob == OOB_PRESENT or rsp_oob == OOB_PRESENT:
        return "out_of_band"

    req_auth = int(request.get("authreq", 0) or 0)
    rsp_auth = int(response.get("authreq", 0) or 0)
    if not ((req_auth | rsp_auth) & AUTH_MITM):
        return "just_works"

    req_io = int(request.get("io_capability", 0) or 0)
    rsp_io = int(response.get("io_capability", 0) or 0)
    if req_io == IO_DISPLAY_YESNO and rsp_io == IO_DISPLAY_YESNO and ((req_auth | rsp_auth) & AUTH_SC):
        return "numeric_comparison"
    if req_io in {IO_KEYBOARD_ONLY, IO_KEYBOARD_DISPLAY} or rsp_io in {IO_KEYBOARD_ONLY, IO_KEYBOARD_DISPLAY}:
        return "passkey_entry"
    if req_io == IO_NO_INPUT_OUTPUT or rsp_io == IO_NO_INPUT_OUTPUT:
        return "just_works"
    return "mitm_capable_pairing"


def _infer_ble_crackability(secure_connections: bool | None, association_model: str) -> str:
    if secure_connections is None:
        return "unknown"
    if not secure_connections:
        if association_model == "just_works":
            return "legacy_justworks_trivially_crackable"
        if association_model == "passkey_entry":
            return "legacy_passkey_feasible"
        return "legacy_pairing_potentially_crackable"
    if association_model == "out_of_band":
        return "oob_material_required"
    if association_model == "numeric_comparison":
        return "secure_connections_not_crackle_crackable"
    return "secure_connections_stronger_than_legacy"


def normalize_smp_message(message: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(message)
    if "io_capability" in normalized:
        io_cap = int(normalized.get("io_capability", 0) or 0)
        normalized["io_capability_name"] = IO_CAPABILITY_NAMES.get(io_cap, f"0x{io_cap:02X}")
    return normalized


# ── Native Module class ─────────────────────────────────────────────────────

class SpecInterpretationModule(Module):
    """Spec Interpretation (internal).

    Apply spec-driven interpretation to a pre-analyzed capture artifact.
    The operator supplies the path to a capture-analysis JSON and the
    TARGET_TYPE discriminator; the Module dispatches to the right
    ``interpret_*`` helper from this file and returns the interpretation
    dict.
    """

    module_id = "reconnaissance.spec_interpretation"
    family = ModuleFamily.RECONNAISSANCE
    name = "Spec Interpretation"
    description = "Interpret LMP/BLE/RFCOMM/L2CAP probe/capture analyses"
    protocols = ("Classic", "BLE", "LMP", "SMP")
    requires = ()
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.recon.result"
    has_report_adapter = False
    internal = True
    references = ()
    options = (
        OptChoice(
            "TARGET_TYPE",
            choices=("lmp", "ble", "rfcomm", "l2cap", "smp"),
            default="lmp",
            description="Which interpreter to apply",
        ),
        OptPath("ANALYSIS_JSON", required=True, description="Path to capture-analysis JSON artifact"),
        OptPath("PAIRING_JSON", required=False, description="Optional pairing-mode JSON for cross-reference"),
    )

    def run(self, ctx: RunContext) -> dict:
        target_type = str(ctx.options.get("TARGET_TYPE", "lmp")).lower()
        analysis_path = str(ctx.options.get("ANALYSIS_JSON", ""))
        pairing_path = str(ctx.options.get("PAIRING_JSON", "") or "")
        started_at = ctx.started_at

        error_msg: str | None = None
        interpretation: dict = {}
        try:
            if not analysis_path or not os.path.exists(analysis_path):
                raise FileNotFoundError(f"analysis artifact not found: {analysis_path}")
            with open(analysis_path, encoding="utf-8") as fh:
                payload = json.load(fh)
            if isinstance(payload, dict) and "module_data" in payload:
                payload = payload.get("module_data") or {}
            if not isinstance(payload, dict):
                raise ValueError(f"analysis JSON at {analysis_path} is not a dict")

            pairing_mode: dict | None = None
            if pairing_path:
                if not os.path.exists(pairing_path):
                    raise FileNotFoundError(f"pairing JSON not found: {pairing_path}")
                with open(pairing_path, encoding="utf-8") as fh:
                    pm_payload = json.load(fh)
                if isinstance(pm_payload, dict) and "module_data" in pm_payload:
                    pm_payload = pm_payload.get("module_data") or {}
                if isinstance(pm_payload, dict):
                    pairing_mode = pm_payload

            if target_type == "lmp":
                interpretation = interpret_lmp_capture(payload, pairing_mode=pairing_mode)
            elif target_type == "ble":
                interpretation = interpret_ble_capture(payload, pairing_mode=pairing_mode)
            elif target_type == "rfcomm":
                interpretation = interpret_rfcomm_probe(payload)
            elif target_type == "l2cap":
                interpretation = interpret_l2cap_probe(payload)
            elif target_type == "smp":
                messages = payload.get("smp_messages") or payload.get("messages") or []
                if not isinstance(messages, list):
                    raise ValueError("SMP interpretation requires a 'smp_messages' list in the payload")
                interpretation = evaluate_smp_transcript(messages)
            else:
                raise ValueError(f"unknown TARGET_TYPE: {target_type}")
        except Exception as exc:
            logger.exception("Spec interpretation failed (type=%s)", target_type)
            error_msg = str(exc)

        findings = interpretation.get("findings", []) if isinstance(interpretation, dict) else []

        if error_msg:
            execution_status = "failed"
            outcome = "not_applicable"
        elif findings:
            execution_status = "completed"
            outcome = "observed"
        else:
            execution_status = "completed"
            outcome = "partial"

        summary_text = (
            f"Interpretation error: {error_msg}"
            if error_msg
            else f"{target_type}: {len(findings)} finding(s)"
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            target="",
            adapter="",
            started_at=started_at,
            executions=[
                make_execution(
                    execution_id="spec_interpret",
                    kind="collector",
                    id="spec_interpret",
                    title=f"Spec Interpretation ({target_type})",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "target_type": target_type,
                            "finding_count": len(findings),
                            "error": error_msg,
                        },
                        summary=summary_text,
                    ),
                    destructive=False,
                    requires_pairing=False,
                )
            ],
            summary={
                "outcome": outcome,
                "target_type": target_type,
                "finding_count": len(findings),
                "error": error_msg,
            },
            module_data=interpretation if isinstance(interpretation, dict) else {"raw": interpretation},
            run_id=ctx.run_id,
        )

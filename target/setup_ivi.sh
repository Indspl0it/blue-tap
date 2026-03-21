#!/bin/bash
# ============================================================================
# Vulnerable IVI Simulator — BlueZ Adapter Setup
#
# Configures a Bluetooth adapter to behave like an intentionally vulnerable
# car infotainment system. Works on any Linux (x86_64/arm64) with BlueZ.
#
# Usage:
#   sudo ./setup_ivi.sh                          # auto-detect profile
#   sudo ./setup_ivi.sh legacy                   # force legacy PIN mode
#   sudo ./setup_ivi.sh ssp                      # force SSP/Just Works
#   sudo ./setup_ivi.sh detect                   # dry-run diagnostics
#   sudo ./setup_ivi.sh reset                    # undo all changes
#   sudo ./setup_ivi.sh auto AA:BB:CC:DD:EE:FF   # custom phone MAC
#   sudo ./setup_ivi.sh auto AA:BB:CC:DD:EE:FF hci1  # custom adapter
# ============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-auto}"
PHONE_MAC="${2:-AA:BB:CC:DD:EE:FF}"
PHONE_NAME="Galaxy S24"
HCI="${3:-hci0}"
IVI_NAME="SYNC"
IVI_CLASS="0x200408"

# Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[+]${RESET} $1"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $1"; }
err()  { echo -e "  ${RED}[x]${RESET} $1"; }
info() { echo -e "  ${CYAN}[*]${RESET} $1"; }

# ── Root check ─────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    err "Must run as root (sudo ./setup_ivi.sh)"
    exit 1
fi

# ── Prerequisite tool checks ──────────────────────────────────────────────

MISSING=""
for tool in hciconfig hcitool sdptool btmgmt bluetoothctl; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        MISSING="$MISSING $tool"
    fi
done

if [ -n "$MISSING" ]; then
    err "Missing required tools:$MISSING"
    echo ""
    echo "  Install on Debian/Ubuntu/Kali:"
    echo "    sudo apt install bluez bluez-tools"
    echo ""
    echo "  Install on Raspberry Pi OS:"
    echo "    sudo apt install bluez"
    echo ""
    exit 1
fi

# ── Adapter detection ─────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}  Vulnerable IVI Simulator — Setup${RESET}"
echo -e "${DIM}  ──────────────────────────────────${RESET}"
echo ""

if ! hciconfig "$HCI" > /dev/null 2>&1; then
    err "No adapter found at $HCI"
    echo ""
    info "Available adapters:"
    if hciconfig -a 2>/dev/null | grep -q "^hci"; then
        hciconfig -a | grep "^hci" | sed 's/^/    /'
    else
        echo "    (none found)"
    fi
    echo ""
    echo "  If using USB dongle, check: lsusb | grep -i bluetooth"
    echo "  If internal adapter: rfkill list bluetooth"
    exit 1
fi

# Extract adapter info
# Ensure adapter is UP before extracting address
hciconfig "$HCI" up 2>/dev/null || true
sleep 0.5

ADAPTER_ADDR=$(hciconfig "$HCI" 2>/dev/null | grep -oP '(?<=BD Address: )[0-9A-Fa-f:]+' | head -1)
CHIPSET=$(cat "/sys/class/bluetooth/$HCI/device/modalias" 2>/dev/null || echo "unknown")
IDX=$(echo "$HCI" | grep -oP '\d+')

BTMGMT_INFO=$(btmgmt --index "$IDX" info 2>/dev/null || true)

if [ -z "$ADAPTER_ADDR" ]; then
    err "Could not read BD Address from $HCI"
    exit 1
fi

info "Adapter: $HCI ($ADAPTER_ADDR)"
info "Chipset: $CHIPSET"

# ── Helper: apply adapter identity ────────────────────────────────────────

apply_identity() {
    hciconfig "$HCI" up 2>/dev/null || true
    sleep 0.5
    hciconfig "$HCI" name "$IVI_NAME" 2>/dev/null || warn "Failed to set name"
    hciconfig "$HCI" class "$IVI_CLASS" 2>/dev/null || warn "Failed to set class"
    hciconfig "$HCI" piscan 2>/dev/null || warn "Failed to set piscan"
}

# ── Helper: register SDP services ─────────────────────────────────────────

register_sdp() {
    # Ensure bluetoothd compatibility mode for sdptool
    # Some systems need --compat flag on bluetoothd, but we try anyway
    local count=0

    sdptool add --channel=1  SP   2>/dev/null && count=$((count+1)) || warn "SDP: SP failed"
    sdptool add --channel=3  DUN  2>/dev/null && count=$((count+1)) || warn "SDP: DUN failed"
    sdptool add --channel=9  OPP  2>/dev/null && count=$((count+1)) || warn "SDP: OPP failed"
    sdptool add --channel=10 HFP  2>/dev/null && count=$((count+1)) || warn "SDP: HFP failed"
    sdptool add --channel=11 NAP  2>/dev/null && count=$((count+1)) || warn "SDP: NAP failed"
    sdptool add --channel=12 PANU 2>/dev/null && count=$((count+1)) || warn "SDP: PANU failed"
    sdptool add --channel=15 PBAP 2>/dev/null && count=$((count+1)) || warn "SDP: PBAP failed"
    sdptool add --channel=16 MAP  2>/dev/null && count=$((count+1)) || warn "SDP: MAP failed"

    ok "SDP: $count/8 services registered"
}

# ── Helper: apply SSP profile ─────────────────────────────────────────────

apply_ssp_profile() {
    local prof="$1"
    if [ "$prof" = "legacy" ]; then
        btmgmt --index "$IDX" ssp off 2>/dev/null || true
        btmgmt --index "$IDX" bondable on 2>/dev/null || true
    elif [ "$prof" = "ssp" ]; then
        btmgmt --index "$IDX" ssp on 2>/dev/null || true
        # NoInputNoOutput forces Just Works pairing (no PIN, no confirmation)
        btmgmt --index "$IDX" io-cap 0x03 2>/dev/null || \
            btmgmt --index "$IDX" io-cap NoInputNoOutput 2>/dev/null || \
            warn "Could not set IO capability"
        btmgmt --index "$IDX" bondable on 2>/dev/null || true
    fi
}

# ── Helper: enable BLE ────────────────────────────────────────────────────

enable_ble() {
    if btmgmt --index "$IDX" le on 2>/dev/null; then
        ok "BLE: enabled"
    else
        warn "BLE: could not enable (single-mode adapter?)"
    fi
}

# ── DETECT MODE ───────────────────────────────────────────────────────────

if [ "$PROFILE" = "detect" ]; then
    echo ""
    info "=== Detect Mode (read-only) ==="
    echo ""

    # Test SSP disable (non-destructive: try off, check, restore)
    SSP_CAN_DISABLE="no"
    # Save current state
    CURRENT_SETTINGS=$(btmgmt --index "$IDX" info 2>/dev/null | grep 'current settings:' | head -1)
    ORIGINAL_HAS_SSP="no"
    if echo "$CURRENT_SETTINGS" | grep -qw 'ssp'; then
        ORIGINAL_HAS_SSP="yes"
    fi
    # Try disabling
    btmgmt --index "$IDX" ssp off 2>/dev/null || true
    sleep 0.5
    NEW_SETTINGS=$(btmgmt --index "$IDX" info 2>/dev/null | grep 'current settings:' | head -1)
    if ! echo "$NEW_SETTINGS" | grep -qw 'ssp'; then
        SSP_CAN_DISABLE="yes"
    fi
    # Restore
    if [ "$ORIGINAL_HAS_SSP" = "yes" ]; then
        btmgmt --index "$IDX" ssp on 2>/dev/null || true
    fi

    # Test LE
    LE_SUPPORT="no"
    if echo "$BTMGMT_INFO" | grep -q 'le'; then
        LE_SUPPORT="yes"
    fi

    # Determine auto profile
    if [ "$SSP_CAN_DISABLE" = "yes" ]; then
        AUTO_PROFILE="legacy"
    else
        AUTO_PROFILE="ssp"
    fi

    info "Adapter:      $HCI ($ADAPTER_ADDR)"
    info "Chipset:      $CHIPSET"
    info "SSP disable:  $SSP_CAN_DISABLE"
    info "BLE support:  $LE_SUPPORT"
    info "Auto profile: $AUTO_PROFILE"
    echo ""

    info "Expected vuln-scan findings:"
    if [ "$AUTO_PROFILE" = "legacy" ]; then
        ok "  PIN Pairing Bypass (CVE-2020-26555) — HIGH"
        ok "  PIN brute-force testable"
    else
        ok "  Just Works pairing — HIGH"
        ok "  BIAS (CVE-2020-10135) — INFO"
    fi
    ok "  Unauthenticated OBEX — CRITICAL"
    ok "  Hidden RFCOMM — MEDIUM"
    ok "  Service Exposure — MEDIUM+"
    ok "  No PIN lockout — MEDIUM"
    echo ""
    info "(Adapter-dependent checks like KNOB/BLURtooth/BrakTooth depend on LMP version"
    info " and chipset — run bt-tap vuln-scan to see actual results)"
    echo ""
    exit 0
fi

# ── RESET MODE ────────────────────────────────────────────────────────────

if [ "$PROFILE" = "reset" ]; then
    echo ""
    info "=== Resetting adapter to defaults ==="
    echo ""

    hciconfig "$HCI" noscan 2>/dev/null || true
    btmgmt --index "$IDX" ssp on 2>/dev/null || true
    btmgmt --index "$IDX" bondable on 2>/dev/null || true

    # Remove pre-paired phone bond
    if [ -n "$ADAPTER_ADDR" ] && [ -n "$PHONE_MAC" ]; then
        BOND_DIR="/var/lib/bluetooth/$ADAPTER_ADDR/$PHONE_MAC"
        if [ -d "$BOND_DIR" ]; then
            rm -rf "$BOND_DIR"
            ok "Removed bond: $PHONE_MAC"
        fi
    fi

    # Clean persistence files
    rm -f "$SCRIPT_DIR/.ivi_profile" "$SCRIPT_DIR/.ivi_adapter" "$SCRIPT_DIR/.ivi_phone"
    ok "Removed persistence files"

    # Restart bluetooth
    systemctl restart bluetooth 2>/dev/null || service bluetooth restart 2>/dev/null || true
    sleep 2
    hciconfig "$HCI" up 2>/dev/null || true

    ok "Adapter reset to defaults"
    echo ""
    exit 0
fi

# ── SETUP MODE (auto / legacy / ssp) ─────────────────────────────────────

echo ""

# Step 1: Adapter identity
info "Step 1: Adapter identity"
apply_identity

# Verify
ACTUAL_NAME=$(hciconfig "$HCI" name 2>/dev/null | grep -oP "(?<=Name: ').*(?=')" || true)
if echo "$ACTUAL_NAME" | grep -qi "$IVI_NAME"; then
    ok "Name: $IVI_NAME"
else
    warn "Name may not have been set (got: $ACTUAL_NAME)"
fi
ok "Class: $IVI_CLASS (Audio/Video: Car Audio)"
ok "Discoverable + Connectable (piscan)"

# Step 2: SSP profile
echo ""
info "Step 2: SSP configuration"

if [ "$PROFILE" = "auto" ]; then
    # Try to disable SSP
    btmgmt --index "$IDX" ssp off 2>/dev/null || true
    sleep 0.5
    SSP_CHECK=$(btmgmt --index "$IDX" info 2>/dev/null | grep 'current settings:' | head -1)
    if ! echo "$SSP_CHECK" | grep -qw 'ssp'; then
        PROFILE="legacy"
        ok "SSP disabled — Legacy PIN mode"
    else
        PROFILE="ssp"
        warn "Adapter enforces SSP (common on Intel) — Just Works mode"
    fi
fi

apply_ssp_profile "$PROFILE"

if [ "$PROFILE" = "legacy" ]; then
    ok "Profile: LEGACY — PIN pairing (1234), CVE-2020-26555 testable"
else
    ok "Profile: SSP — Just Works, BIAS/Invalid Curve testable"
fi

# Step 3: SDP services
echo ""
info "Step 3: SDP service registration"
register_sdp

# Step 4: BLE
echo ""
info "Step 4: BLE configuration"
enable_ble

# Step 5: Pre-paired phone bond
echo ""
info "Step 5: Pre-paired phone bond ($PHONE_MAC)"

BOND_DIR="/var/lib/bluetooth/$ADAPTER_ADDR/$PHONE_MAC"
mkdir -p "$BOND_DIR"
cat > "$BOND_DIR/info" << BONDEOF
[General]
Name=$PHONE_NAME
Trusted=true
Blocked=false
Services=

[LinkKey]
Key=1234567890ABCDEF1234567890ABCDEF
Type=4
PINLength=0
BONDEOF

ok "Bond file written: $BOND_DIR/info"

# Restart bluetooth to pick up the new bond
info "Restarting bluetooth service..."
systemctl restart bluetooth 2>/dev/null || service bluetooth restart 2>/dev/null || true
sleep 2

# Re-apply everything (bluetooth restart resets adapter state)
apply_identity
apply_ssp_profile "$PROFILE"
register_sdp > /dev/null  # quiet stdout on re-register, keep stderr visible
enable_ble > /dev/null 2>&1

# Verify bond
if bluetoothctl paired-devices 2>/dev/null | grep -qi "$PHONE_MAC"; then
    ok "Bond verified: $PHONE_MAC ($PHONE_NAME)"
else
    warn "Bond may not show in bluetoothctl yet (BlueZ may need a connection attempt)"
    ok "Bond file exists at $BOND_DIR/info — hijack should still work"
fi

# Step 6: Persist config
echo ""
info "Step 6: Saving configuration"
echo "$PROFILE" > "$SCRIPT_DIR/.ivi_profile"
echo "$ADAPTER_ADDR" > "$SCRIPT_DIR/.ivi_adapter"
echo "$PHONE_MAC" > "$SCRIPT_DIR/.ivi_phone"
ok "Profile: $SCRIPT_DIR/.ivi_profile → $PROFILE"
ok "Adapter: $SCRIPT_DIR/.ivi_adapter → $ADAPTER_ADDR"
ok "Phone:   $SCRIPT_DIR/.ivi_phone → $PHONE_MAC"

# ── Final summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}  ╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}  ║   IVI SIMULATOR READY                    ║${RESET}"
echo -e "${BOLD}${GREEN}  ╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}Name:${RESET}       $IVI_NAME"
echo -e "  ${CYAN}MAC:${RESET}        $ADAPTER_ADDR"
echo -e "  ${CYAN}Class:${RESET}      $IVI_CLASS (Car Audio)"
echo -e "  ${CYAN}Profile:${RESET}    $PROFILE"
echo -e "  ${CYAN}Phone:${RESET}      $PHONE_MAC ($PHONE_NAME)"
echo -e "  ${CYAN}SDP:${RESET}        8 services (SP, DUN, OPP, HFP, NAP, PANU, PBAP, MAP)"
echo ""
echo -e "  ${YELLOW}Next steps:${RESET}"
echo -e "    1. Start pairing agent:  ${DIM}sudo python3 $SCRIPT_DIR/pin_agent.py${RESET}"
echo -e "    2. Start IVI daemon:     ${DIM}sudo python3 $SCRIPT_DIR/ivi_daemon.py${RESET}"
echo -e "    3. (Optional) BLE GATT:  ${DIM}sudo python3 $SCRIPT_DIR/ble_gatt.py${RESET}"
echo ""

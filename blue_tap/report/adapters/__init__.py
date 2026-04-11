"""Registry of report adapters for standardized module envelopes."""

from blue_tap.report.adapters.attack import AttackReportAdapter
from blue_tap.report.adapters.audio import AudioReportAdapter
from blue_tap.report.adapters.auto import AutoReportAdapter
from blue_tap.report.adapters.data import DataReportAdapter
from blue_tap.report.adapters.discovery import DiscoveryReportAdapter
from blue_tap.report.adapters.dos import DosReportAdapter
from blue_tap.report.adapters.firmware import FirmwareReportAdapter
from blue_tap.report.adapters.fuzz import FuzzReportAdapter
from blue_tap.report.adapters.lmp_capture import LmpCaptureReportAdapter
from blue_tap.report.adapters.recon import ReconReportAdapter
from blue_tap.report.adapters.spoof import SpoofReportAdapter
from blue_tap.report.adapters.vulnscan import VulnscanReportAdapter


REPORT_ADAPTERS = (
    DiscoveryReportAdapter(),
    VulnscanReportAdapter(),
    AttackReportAdapter(),
    AutoReportAdapter(),
    DataReportAdapter(),
    AudioReportAdapter(),
    DosReportAdapter(),
    FirmwareReportAdapter(),
    FuzzReportAdapter(),
    LmpCaptureReportAdapter(),
    ReconReportAdapter(),
    SpoofReportAdapter(),
)

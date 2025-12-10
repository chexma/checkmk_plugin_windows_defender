#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Windows Defender Plugin for CheckMK 2.4
# Migrated to Check API V2
#
# Original author: Andre Eckstein, Andre.Eckstein@Bechtle.com
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation in version 2. This file is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.

"""
Agent output format (<<<windows_defender:sep(58)>>>):

AMEngineVersion                 : 1.1.17800.5
AMProductVersion                : 4.18.2101.9
AMRunningMode                   : EDR Block Mode
AMServiceEnabled                : True
AMServiceVersion                : 4.18.2101.9
AntispywareEnabled              : True
AntispywareSignatureAge         : 0
AntispywareSignatureLastUpdated : 25.02.2021 22:37:07
AntispywareSignatureVersion     : 1.331.1839.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 0
AntivirusSignatureLastUpdated   : 25.02.2021 22:37:08
AntivirusSignatureVersion       : 1.331.1839.0
BehaviorMonitorEnabled          : True
...
"""

import time
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    check_levels,
    Metric,
    render,
    Result,
    Service,
    State,
    StringTable,
)


# Type definitions for check parameters
LevelsType = tuple[Literal["fixed"], tuple[float, float]] | tuple[Literal["no_levels"], None] | None
ServiceStateType = Literal["enabled", "disabled"]


class WindowsDefenderParams(TypedDict, total=False):
    """Type-safe check parameters for Windows Defender."""

    date_format: Literal["eu", "us", "iso"]
    # Signature age levels
    AntispywareSignatureLastUpdated: LevelsType
    AntivirusSignatureLastUpdated: LevelsType
    NISSignatureLastUpdated: LevelsType
    # Scan age levels
    FullScanEndTime: LevelsType
    QuickScanEndTime: LevelsType
    # Service states
    AMServiceEnabled: ServiceStateType
    BehaviorMonitorEnabled: ServiceStateType
    AntispywareEnabled: ServiceStateType
    AntivirusEnabled: ServiceStateType
    NISEnabled: ServiceStateType
    RealTimeProtectionEnabled: ServiceStateType
    OnAccessProtectionEnabled: ServiceStateType


@dataclass(frozen=True)
class WindowsDefenderSection:
    """Parsed Windows Defender data with type safety."""

    # Version information
    am_engine_version: str | None
    am_product_version: str | None
    am_service_version: str | None
    nis_engine_version: str | None
    antispyware_signature_version: str | None
    antivirus_signature_version: str | None
    nis_signature_version: str | None

    # Signature timestamps (raw strings for later parsing with date_format param)
    antispyware_signature_last_updated: str | None
    antivirus_signature_last_updated: str | None
    nis_signature_last_updated: str | None

    # Scan timestamps (raw strings)
    full_scan_end_time: str | None
    quick_scan_end_time: str | None

    # Service states (True/False/None if unknown)
    am_service_enabled: bool | None
    behavior_monitor_enabled: bool | None
    antispyware_enabled: bool | None
    antivirus_enabled: bool | None
    nis_enabled: bool | None
    realtime_protection_enabled: bool | None
    onaccess_protection_enabled: bool | None

    # Additional info
    am_running_mode: str | None
    computer_state: str | None
    is_tamper_protected: bool | None
    is_virtual_machine: bool | None


# Default check parameters
WINDOWS_DEFENDER_DEFAULT_LEVELS: dict[str, Any] = {
    # Date format: "auto", "us" (MM/DD/YYYY), "eu" (DD/MM/YYYY or DD.MM.YYYY), "iso" (YYYY-MM-DD)
    "date_format": "eu",  # Default to European format (German)
    # Signature ages (warn, crit) in seconds
    "AntispywareSignatureLastUpdated": ("fixed", (3 * 86400, 7 * 86400)),
    "AntivirusSignatureLastUpdated": ("fixed", (2 * 86400, 7 * 86400)),
    "NISSignatureLastUpdated": ("fixed", (5 * 86400, 7 * 86400)),
    # Service states - expected values (enabled/disabled)
    "AMServiceEnabled": "enabled",
    "BehaviorMonitorEnabled": "enabled",
    "AntispywareEnabled": "enabled",
    "AntivirusEnabled": "enabled",
    "NISEnabled": "enabled",
    "RealTimeProtectionEnabled": "enabled",
    "OnAccessProtectionEnabled": "enabled",
}

# Date format configurations
# Note: EU config also includes US AM/PM format since Windows can output mixed formats on same host
DATE_FORMAT_CONFIGS: dict[str, list[str]] = {
    "us": [
        "%m/%d/%Y %I:%M:%S %p",   # US with AM/PM: 11/18/2021 10:38:19 PM
        "%m/%d/%Y %H:%M:%S",      # US 24h: 11/18/2021 22:38:19
    ],
    "eu": [
        "%d.%m.%Y %H:%M:%S",      # European with dots: 25.02.2021 22:37:07
        "%m/%d/%Y %I:%M:%S %p",   # US AM/PM (unambiguous, include for mixed-format hosts)
        "%d/%m/%Y %H:%M:%S",      # European with slashes: 25/02/2021 22:37:07
        "%d/%m/%Y %I:%M:%S %p",   # European with AM/PM
    ],
    "iso": [
        "%Y-%m-%d %H:%M:%S",      # ISO: 2021-02-25 22:37:07
        "%Y-%m-%dT%H:%M:%S",      # ISO with T separator
    ],
}


def _parse_timestamp(timestamp_str: str, now: float, date_format: str = "eu") -> float | None:
    """Parse a timestamp string and return the age in seconds.

    Args:
        timestamp_str: The timestamp string to parse
        now: Current time as Unix timestamp
        date_format: One of "us", "eu", "iso"

    Returns None if parsing fails.
    """
    if not timestamp_str:
        return None

    timestamp_str = timestamp_str.strip()

    # Get formats to try based on configuration
    formats_to_try = DATE_FORMAT_CONFIGS.get(date_format, DATE_FORMAT_CONFIGS["eu"])

    # Try each format
    for fmt in formats_to_try:
        try:
            update_date = time.mktime(time.strptime(timestamp_str, fmt))
            age = now - update_date
            # Sanity check: signature shouldn't be from the future (allow 1 day tolerance for TZ issues)
            if age >= -86400:
                return age
        except ValueError:
            continue

    return None


def _parse_bool(value: str) -> bool | None:
    """Parse a boolean string value."""
    if value == "True":
        return True
    if value == "False":
        return False
    return None


def _extract_levels_tuple(levels: Any) -> tuple[float, float] | None:
    """Extract (warn, crit) tuple from ruleset level format for display purposes.

    Ruleset SimpleLevels format: ("fixed", (warn, crit)) or ("no_levels", None)
    Returns just the (warn, crit) tuple for display in messages.
    """
    if levels is None:
        return None
    if isinstance(levels, tuple) and len(levels) == 2:
        level_type, level_values = levels
        if level_type == "fixed" and isinstance(level_values, tuple):
            return level_values
        if level_type == "no_levels":
            return None
    return None


def parse_windows_defender(string_table: StringTable) -> WindowsDefenderSection | None:
    """Parse the Windows Defender agent output into a typed dataclass."""
    if not string_table:
        return None

    # Build dictionary from key:value pairs
    raw: dict[str, str] = {}
    for line in string_table:
        if len(line) >= 2:
            key = line[0].strip()
            value = ":".join(line[1:]).strip()
            raw[key] = value

    if not raw:
        return None

    return WindowsDefenderSection(
        # Version information
        am_engine_version=raw.get("AMEngineVersion"),
        am_product_version=raw.get("AMProductVersion"),
        am_service_version=raw.get("AMServiceVersion"),
        nis_engine_version=raw.get("NISEngineVersion"),
        antispyware_signature_version=raw.get("AntispywareSignatureVersion"),
        antivirus_signature_version=raw.get("AntivirusSignatureVersion"),
        nis_signature_version=raw.get("NISSignatureVersion"),
        # Signature timestamps (raw strings - parsed later with date_format param)
        antispyware_signature_last_updated=raw.get("AntispywareSignatureLastUpdated"),
        antivirus_signature_last_updated=raw.get("AntivirusSignatureLastUpdated"),
        nis_signature_last_updated=raw.get("NISSignatureLastUpdated"),
        # Scan timestamps (raw strings)
        full_scan_end_time=raw.get("FullScanEndTime"),
        quick_scan_end_time=raw.get("QuickScanEndTime"),
        # Service states
        am_service_enabled=_parse_bool(raw.get("AMServiceEnabled", "")),
        behavior_monitor_enabled=_parse_bool(raw.get("BehaviorMonitorEnabled", "")),
        antispyware_enabled=_parse_bool(raw.get("AntispywareEnabled", "")),
        antivirus_enabled=_parse_bool(raw.get("AntivirusEnabled", "")),
        nis_enabled=_parse_bool(raw.get("NISEnabled", "")),
        realtime_protection_enabled=_parse_bool(raw.get("RealTimeProtectionEnabled", "")),
        onaccess_protection_enabled=_parse_bool(raw.get("OnAccessProtectionEnabled", "")),
        # Additional info
        am_running_mode=raw.get("AMRunningMode"),
        computer_state=raw.get("ComputerState"),
        is_tamper_protected=_parse_bool(raw.get("IsTamperProtected", "")),
        is_virtual_machine=_parse_bool(raw.get("IsVirtualMachine", "")),
    )


def discover_windows_defender(section: WindowsDefenderSection) -> DiscoveryResult:
    """Discover the Windows Defender service."""
    yield Service()


def _check_signature_ages(
    params: WindowsDefenderParams, section: WindowsDefenderSection, now: float
) -> CheckResult:
    """Check signature ages using check_levels for proper integration."""

    date_format = params.get("date_format", "eu")  # Default to European format

    signatures = [
        (
            "AntispywareSignatureLastUpdated",
            "antispyware_sig_age",
            "AntiSpyware signature",
            section.antispyware_signature_last_updated,
        ),
        (
            "AntivirusSignatureLastUpdated",
            "antivirus_sig_age",
            "AntiVirus signature",
            section.antivirus_signature_last_updated,
        ),
        (
            "NISSignatureLastUpdated",
            "nis_sig_age",
            "NIS signature",
            section.nis_signature_last_updated,
        ),
    ]

    for param_key, metric_name, label, timestamp_str in signatures:
        age = _parse_timestamp(timestamp_str, now, date_format) if timestamp_str else None

        if age is None:
            yield Result(
                state=State.UNKNOWN,
                summary=f"Age of {label} is unknown",
            )
            continue

        levels = params.get(param_key)

        yield from check_levels(
            age,
            levels_upper=levels,
            metric_name=metric_name,
            label=f"{label} age",
            render_func=render.timespan,
        )


def _check_service_states(
    params: WindowsDefenderParams, section: WindowsDefenderSection
) -> CheckResult:
    """Check service states against expected values."""

    services = [
        ("AMServiceEnabled", "AM Service", section.am_service_enabled),
        ("BehaviorMonitorEnabled", "Behavior Monitor", section.behavior_monitor_enabled),
        ("AntispywareEnabled", "Antispyware", section.antispyware_enabled),
        ("AntivirusEnabled", "Antivirus", section.antivirus_enabled),
        ("NISEnabled", "NIS", section.nis_enabled),
        ("RealTimeProtectionEnabled", "RealTimeProtection", section.realtime_protection_enabled),
        ("OnAccessProtectionEnabled", "OnAccessProtection", section.onaccess_protection_enabled),
    ]

    issues = 0
    ok_services = []

    for param_key, description, current_value in services:
        expected = params.get(param_key, "enabled")

        # Handle None (unknown state from agent)
        if current_value is None:
            yield Result(
                state=State.UNKNOWN,
                summary=f'service "{description}" state is unknown',
            )
            issues += 1
            continue

        # Convert bool to string for comparison with params
        current_str = "enabled" if current_value else "disabled"

        if current_str != expected:
            yield Result(
                state=State.WARN,
                summary=f'service "{description}" is {current_str} (expected {expected})',
            )
            issues += 1
        else:
            ok_services.append(description)

    if issues == 0:
        yield Result(
            state=State.OK,
            summary=f"All {len(ok_services)} services in expected state",
        )


def _check_scan_ages(
    params: WindowsDefenderParams, section: WindowsDefenderSection, now: float
) -> CheckResult:
    """Check scan ages if configured."""

    date_format = params.get("date_format", "eu")  # Default to European format

    scans = [
        ("FullScanEndTime", "full_scan_age", "Full Scan", section.full_scan_end_time),
        ("QuickScanEndTime", "quick_scan_age", "Quick Scan", section.quick_scan_end_time),
    ]

    for param_key, metric_name, label, timestamp_str in scans:
        levels = params.get(param_key)

        # Skip if not configured
        if levels is None:
            continue

        age = _parse_timestamp(timestamp_str, now, date_format) if timestamp_str else None

        if age is None:
            # Scan has never been executed - extract thresholds for message
            levels_tuple = _extract_levels_tuple(levels)
            if levels_tuple:
                warn, crit = levels_tuple
            else:
                warn, crit = (7 * 86400, 14 * 86400)

            thresholds = f"(warn/crit at {render.timespan(warn)}/{render.timespan(crit)})"
            yield Result(
                state=State.CRIT,
                summary=f"{label} has never been executed {thresholds}",
            )
            # Emit metric with value 0 to indicate never run
            yield Metric(metric_name, 0)
            continue

        yield from check_levels(
            age,
            levels_upper=levels,
            metric_name=metric_name,
            label=f"Last {label}",
            render_func=render.timespan,
        )


def _yield_version_info(section: WindowsDefenderSection) -> CheckResult:
    """Yield version information as notice (details only)."""

    versions = []
    if section.am_engine_version:
        versions.append(f"AM Engine: {section.am_engine_version}")
    if section.am_product_version:
        versions.append(f"AM Product: {section.am_product_version}")
    if section.nis_signature_version:
        versions.append(f"NIS Sig: {section.nis_signature_version}")
    if section.antivirus_signature_version:
        versions.append(f"AV Sig: {section.antivirus_signature_version}")
    if section.antispyware_signature_version:
        versions.append(f"AS Sig: {section.antispyware_signature_version}")

    if versions:
        yield Result(state=State.OK, notice=f"Versions - {', '.join(versions)}")

    # Additional info
    details = []
    if section.am_running_mode:
        details.append(f"Running Mode: {section.am_running_mode}")
    if section.is_tamper_protected is not None:
        details.append(f"Tamper Protected: {'Yes' if section.is_tamper_protected else 'No'}")
    if section.is_virtual_machine is not None:
        details.append(f"Virtual Machine: {'Yes' if section.is_virtual_machine else 'No'}")

    if details:
        yield Result(state=State.OK, notice=" | ".join(details))


def check_windows_defender(
    params: WindowsDefenderParams, section: WindowsDefenderSection
) -> CheckResult:
    """Check Windows Defender status."""

    now = time.time()

    # Check signature ages with metrics
    yield from _check_signature_ages(params, section, now)

    # Check service states
    yield from _check_service_states(params, section)

    # Check scan ages (if configured) with metrics
    yield from _check_scan_ages(params, section, now)

    # Output version info as notice
    yield from _yield_version_info(section)


# Register the agent section
agent_section_windows_defender = AgentSection(
    name="windows_defender",
    parse_function=parse_windows_defender,
)

# Register the check plugin
check_plugin_windows_defender = CheckPlugin(
    name="windows_defender",
    service_name="Windows Defender",
    sections=["windows_defender"],
    discovery_function=discover_windows_defender,
    check_function=check_windows_defender,
    check_default_parameters=WINDOWS_DEFENDER_DEFAULT_LEVELS,
    check_ruleset_name="windows_defender",
)

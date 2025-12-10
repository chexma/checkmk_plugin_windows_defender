#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Windows Defender Ruleset for CheckMK 2.4
# Migrated to Rulesets API V1
#
# Original author: Andre Eckstein, Andre.Eckstein@Bechtle.com

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    LevelDirection,
    SimpleLevels,
    SingleChoice,
    SingleChoiceElement,
    TimeSpan,
    TimeMagnitude,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _age_levels(
    title: str,
    help_text: str,
    default_warn_days: float,
    default_crit_days: float,
) -> SimpleLevels:
    """Factory function for age-based SimpleLevels with TimeSpan."""
    return SimpleLevels(
        title=Title(title),
        help_text=Help(help_text),
        form_spec_template=TimeSpan(
            displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR],
        ),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue(
            value=(default_warn_days * 86400.0, default_crit_days * 86400.0)
        ),
    )


def _service_state_choice(title: str, help_text: str = "Default state is enabled") -> SingleChoice:
    """Factory function for service state SingleChoice elements."""
    return SingleChoice(
        title=Title(title),
        help_text=Help(help_text),
        elements=[
            SingleChoiceElement(name="enabled", title=Title("enabled")),
            SingleChoiceElement(name="disabled", title=Title("disabled")),
        ],
        prefill=DefaultValue("enabled"),
    )


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("Windows Defender signature age and state"),
        help_text=Help(
            "Configure thresholds for Windows Defender signature ages and expected service states"
        ),
        elements={
            # Date format configuration
            "date_format": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Date format from Windows agent"),
                    help_text=Help(
                        "Select the date format used by the Windows host. "
                        "This depends on the Windows locale settings."
                    ),
                    elements=[
                        SingleChoiceElement(
                            name="eu", title=Title("European format (DD.MM.YYYY or DD/MM/YYYY)")
                        ),
                        SingleChoiceElement(name="us", title=Title("US format (MM/DD/YYYY)")),
                        SingleChoiceElement(name="iso", title=Title("ISO format (YYYY-MM-DD)")),
                    ],
                    prefill=DefaultValue("eu"),
                ),
            ),
            # Signature age levels
            "AntispywareSignatureLastUpdated": DictElement(
                required=False,
                parameter_form=_age_levels(
                    "Age of Anti-Spyware Signature",
                    "Maximum age of the Anti-Spyware signature before alerting",
                    default_warn_days=3,
                    default_crit_days=7,
                ),
            ),
            "AntivirusSignatureLastUpdated": DictElement(
                required=False,
                parameter_form=_age_levels(
                    "Age of Anti-Virus Signature",
                    "Maximum age of the Anti-Virus signature before alerting",
                    default_warn_days=2,
                    default_crit_days=7,
                ),
            ),
            "NISSignatureLastUpdated": DictElement(
                required=False,
                parameter_form=_age_levels(
                    "Age of NIS Signature",
                    "Maximum age of the NIS (Network Inspection System) signature before alerting",
                    default_warn_days=5,
                    default_crit_days=7,
                ),
            ),
            # Scan age levels
            "FullScanEndTime": DictElement(
                required=False,
                parameter_form=_age_levels(
                    "Age of last full scan",
                    "Maximum time since the last full scan before alerting. "
                    "Leave unconfigured to not check.",
                    default_warn_days=7,
                    default_crit_days=14,
                ),
            ),
            "QuickScanEndTime": DictElement(
                required=False,
                parameter_form=_age_levels(
                    "Age of last quick scan",
                    "Maximum time since the last quick scan before alerting. "
                    "Leave unconfigured to not check.",
                    default_warn_days=2,
                    default_crit_days=7,
                ),
            ),
            # Service state expectations
            "AMServiceEnabled": DictElement(
                required=False,
                parameter_form=_service_state_choice("Expected state of AM Service"),
            ),
            "BehaviorMonitorEnabled": DictElement(
                required=False,
                parameter_form=_service_state_choice("Expected state of Behavior Monitor"),
            ),
            "AntispywareEnabled": DictElement(
                required=False,
                parameter_form=_service_state_choice("Expected state of Antispyware"),
            ),
            "AntivirusEnabled": DictElement(
                required=False,
                parameter_form=_service_state_choice("Expected state of Antivirus"),
            ),
            "NISEnabled": DictElement(
                required=False,
                parameter_form=_service_state_choice(
                    "Expected state of NIS",
                    "Default state is enabled. Note: NIS may be disabled on some systems.",
                ),
            ),
            "RealTimeProtectionEnabled": DictElement(
                required=False,
                parameter_form=_service_state_choice("Expected state of Real Time Protection"),
            ),
            "OnAccessProtectionEnabled": DictElement(
                required=False,
                parameter_form=_service_state_choice(
                    "Expected state of OnAccess Protection",
                    "Default state is enabled. Note: May be disabled in some environments.",
                ),
            ),
        },
    )


rule_spec_windows_defender = CheckParameters(
    name="windows_defender",
    title=Title("Windows Defender signature age and state"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
    condition=HostCondition(),
)

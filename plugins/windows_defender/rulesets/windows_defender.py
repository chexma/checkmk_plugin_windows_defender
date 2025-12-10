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


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("Windows Defender signature age and state"),
        help_text=Help("Configure thresholds for Windows Defender signature ages and expected service states"),
        elements={
            "date_format": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Date format from Windows agent"),
                    help_text=Help(
                        "Select the date format used by the Windows host. This depends on the Windows locale settings."
                    ),
                    elements=[
                        SingleChoiceElement(name="eu", title=Title("European format (DD.MM.YYYY or DD/MM/YYYY)")),
                        SingleChoiceElement(name="us", title=Title("US format (MM/DD/YYYY)")),
                        SingleChoiceElement(name="iso", title=Title("ISO format (YYYY-MM-DD)")),
                    ],
                    prefill=DefaultValue("eu"),
                ),
            ),
            "AntispywareSignatureLastUpdated": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Age of Anti-Spyware Signature"),
                    help_text=Help("Maximum age of the Anti-Spyware signature before alerting"),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                        ],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(3 * 86400.0, 7 * 86400.0)),
                ),
            ),
            "AntivirusSignatureLastUpdated": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Age of Anti-Virus Signature"),
                    help_text=Help("Maximum age of the Anti-Virus signature before alerting"),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                        ],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(2 * 86400.0, 7 * 86400.0)),
                ),
            ),
            "NISSignatureLastUpdated": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Age of NIS Signature"),
                    help_text=Help("Maximum age of the NIS (Network Inspection System) signature before alerting"),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                        ],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(5 * 86400.0, 7 * 86400.0)),
                ),
            ),
            "FullScanEndTime": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Age of last full scan"),
                    help_text=Help("Maximum time since the last full scan before alerting. Leave unconfigured to not check."),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                        ],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(7 * 86400.0, 14 * 86400.0)),
                ),
            ),
            "QuickScanEndTime": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Age of last quick scan"),
                    help_text=Help("Maximum time since the last quick scan before alerting. Leave unconfigured to not check."),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                        ],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(2 * 86400.0, 7 * 86400.0)),
                ),
            ),
            "AMServiceEnabled": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Expected state of AM Service"),
                    help_text=Help("Default state is enabled"),
                    elements=[
                        SingleChoiceElement(name="enabled", title=Title("enabled")),
                        SingleChoiceElement(name="disabled", title=Title("disabled")),
                    ],
                    prefill=DefaultValue("enabled"),
                ),
            ),
            "BehaviorMonitorEnabled": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Expected state of Behavior Monitor"),
                    help_text=Help("Default state is enabled"),
                    elements=[
                        SingleChoiceElement(name="enabled", title=Title("enabled")),
                        SingleChoiceElement(name="disabled", title=Title("disabled")),
                    ],
                    prefill=DefaultValue("enabled"),
                ),
            ),
            "AntispywareEnabled": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Expected state of Antispyware"),
                    help_text=Help("Default state is enabled"),
                    elements=[
                        SingleChoiceElement(name="enabled", title=Title("enabled")),
                        SingleChoiceElement(name="disabled", title=Title("disabled")),
                    ],
                    prefill=DefaultValue("enabled"),
                ),
            ),
            "AntivirusEnabled": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Expected state of Antivirus"),
                    help_text=Help("Default state is enabled"),
                    elements=[
                        SingleChoiceElement(name="enabled", title=Title("enabled")),
                        SingleChoiceElement(name="disabled", title=Title("disabled")),
                    ],
                    prefill=DefaultValue("enabled"),
                ),
            ),
            "NISEnabled": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Expected state of NIS"),
                    help_text=Help("Default state is enabled. Note: NIS may be disabled on some systems."),
                    elements=[
                        SingleChoiceElement(name="enabled", title=Title("enabled")),
                        SingleChoiceElement(name="disabled", title=Title("disabled")),
                    ],
                    prefill=DefaultValue("enabled"),
                ),
            ),
            "RealTimeProtectionEnabled": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Expected state of Real Time Protection"),
                    help_text=Help("Default state is enabled"),
                    elements=[
                        SingleChoiceElement(name="enabled", title=Title("enabled")),
                        SingleChoiceElement(name="disabled", title=Title("disabled")),
                    ],
                    prefill=DefaultValue("enabled"),
                ),
            ),
            "OnAccessProtectionEnabled": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Expected state of OnAccess Protection"),
                    help_text=Help("Default state is enabled. Note: May be disabled in some environments."),
                    elements=[
                        SingleChoiceElement(name="enabled", title=Title("enabled")),
                        SingleChoiceElement(name="disabled", title=Title("disabled")),
                    ],
                    prefill=DefaultValue("enabled"),
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

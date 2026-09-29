#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Windows Defender Agent Bakery Configuration for CheckMK 2.5
# Migrated to Rulesets API V1 (AgentConfig)
#
# Original author: Andre Eckstein, Andre.Eckstein@Bechtle.com

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("Windows Defender Plugin"),
        help_text=Help("Deploy the Windows Defender monitoring plugin to Windows hosts"),
        elements={
            "deployment": DictElement(
                required=True,
                parameter_form=CascadingSingleChoice(
                    title=Title("Deployment type"),
                    elements=[
                        CascadingSingleChoiceElement(
                            name="sync",
                            title=Title("Deploy the plugin and run it synchronously"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="cached",
                            title=Title("Deploy the plugin and run it asynchronously"),
                            parameter_form=TimeSpan(
                                title=Title("Execution interval"),
                                displayed_magnitudes=[TimeMagnitude.HOUR, TimeMagnitude.MINUTE],
                                prefill=DefaultValue(3600.0),
                            ),
                        ),
                        CascadingSingleChoiceElement(
                            name="do_not_deploy",
                            title=Title("Do not deploy the plugin"),
                            parameter_form=FixedValue(value=None),
                        ),
                    ],
                    prefill=DefaultValue("sync"),
                ),
            ),
        },
    )


rule_spec_windows_defender_bakery = AgentConfig(
    name="windows_defender",
    title=Title("Windows Defender"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
)

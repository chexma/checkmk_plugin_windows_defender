#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Windows Defender Agent Bakery Configuration for CheckMK 2.4
# Migrated to Rulesets API V1 (AgentConfig)
#
# Original author: Andre Eckstein, Andre.Eckstein@Bechtle.com

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    Dictionary,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("Windows Defender Plugin"),
        help_text=Help("Deploy the Windows Defender monitoring plugin to Windows hosts"),
        elements={},
    )


rule_spec_windows_defender_bakery = AgentConfig(
    name="windows_defender",
    title=Title("Windows Defender"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
)

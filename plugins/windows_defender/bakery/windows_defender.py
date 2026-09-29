#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Windows Defender Bakery Plugin for CheckMK 2.5
# Migrated to Bakery API V2 (cmk.bakery.v2_unstable)
#
# Original author: Andre Eckstein, Andre.Eckstein@Bechtle.com
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation in version 2. This file is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.

from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from cmk.bakery.v2_unstable import BakeryPlugin, FileGenerator, OS, Plugin


class WindowsDefenderBakeryConfig(BaseModel):
    deployment: tuple[Literal["sync"], None] | tuple[Literal["cached"], float] | tuple[Literal["do_not_deploy"], None]


def get_windows_defender_files(conf: WindowsDefenderBakeryConfig) -> FileGenerator:
    mode, interval = conf.deployment
    if mode == "do_not_deploy":
        return
    # Source path is relative to cmk_addons/plugins/windows_defender/agents/
    yield Plugin(
        base_os=OS.WINDOWS,
        source=Path("windows_defender.ps1"),
        interval=int(interval) if mode == "cached" and interval else None,
    )


bakery_plugin_windows_defender = BakeryPlugin(
    name="windows_defender",
    parameter_parser=WindowsDefenderBakeryConfig.model_validate,
    default_parameters=None,  # only deploy if an "Agent rules" rule is configured
    files_function=get_windows_defender_files,
)

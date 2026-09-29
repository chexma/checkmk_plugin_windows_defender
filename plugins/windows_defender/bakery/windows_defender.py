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

from collections.abc import Mapping
from pathlib import Path

from cmk.bakery.v2_unstable import BakeryPlugin, FileGenerator, OS, Plugin, no_op_parser


def get_windows_defender_files(conf: Mapping[str, object]) -> FileGenerator:
    # Source path is relative to cmk_addons/plugins/windows_defender/agents/
    yield Plugin(base_os=OS.WINDOWS, source=Path("windows_defender.ps1"))


bakery_plugin_windows_defender = BakeryPlugin(
    name="windows_defender",
    parameter_parser=no_op_parser,
    default_parameters=None,  # only deploy if an "Agent rules" rule is configured
    files_function=get_windows_defender_files,
)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Windows Defender Graphing Definitions for CheckMK 2.4
# Metrics, Graphs, and Perfometers
#
# Original author: Andre Eckstein, Andre.Eckstein@Bechtle.com

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph, MinimalRange
from cmk.graphing.v1.metrics import (
    Color,
    Metric,
    TimeNotation,
    Unit,
)
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer


# Unit for time/age in seconds
UNIT_TIME = Unit(TimeNotation())

# Signature age metrics
metric_antispyware_sig_age = Metric(
    name="antispyware_sig_age",
    title=Title("AntiSpyware signature age"),
    unit=UNIT_TIME,
    color=Color.BLUE,
)

metric_antivirus_sig_age = Metric(
    name="antivirus_sig_age",
    title=Title("AntiVirus signature age"),
    unit=UNIT_TIME,
    color=Color.GREEN,
)

metric_nis_sig_age = Metric(
    name="nis_sig_age",
    title=Title("NIS signature age"),
    unit=UNIT_TIME,
    color=Color.PURPLE,
)

# Scan age metrics
metric_full_scan_age = Metric(
    name="full_scan_age",
    title=Title("Full scan age"),
    unit=UNIT_TIME,
    color=Color.ORANGE,
)

metric_quick_scan_age = Metric(
    name="quick_scan_age",
    title=Title("Quick scan age"),
    unit=UNIT_TIME,
    color=Color.CYAN,
)

# Perfometer for antivirus signature age (most commonly monitored)
perfometer_antivirus_sig_age = Perfometer(
    name="antivirus_sig_age",
    focus_range=FocusRange(Closed(0), Open(7 * 86400)),  # 0 to 7 days
    segments=["antivirus_sig_age"],
)

# Graph for signature ages (combined view)
graph_signature_ages = Graph(
    name="windows_defender_signature_ages",
    title=Title("Windows Defender Signature Ages"),
    minimal_range=MinimalRange(0, 7 * 86400),  # 0 to 7 days
    simple_lines=[
        "antispyware_sig_age",
        "antivirus_sig_age",
        "nis_sig_age",
    ],
)

# Graph for scan ages (combined view)
graph_scan_ages = Graph(
    name="windows_defender_scan_ages",
    title=Title("Windows Defender Scan Ages"),
    minimal_range=MinimalRange(0, 14 * 86400),  # 0 to 14 days
    simple_lines=[
        "full_scan_age",
        "quick_scan_age",
    ],
)

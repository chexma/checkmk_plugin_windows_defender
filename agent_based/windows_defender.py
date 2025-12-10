#!/usr/bin/python

# Andre Eckstein, Andre.Eckstein@Bechtle.com

# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  This file is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.


# Output of the agent plugin:
"""
<<<windows_defender:sep(58)>>>
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
ComputerID                      : xyz
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 :
FullScanStartTime               :
IoavProtectionEnabled           : False
IsTamperProtected               : False
IsVirtualMachine                : True
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : False
NISEngineVersion                : 1.1.17800.5
NISSignatureAge                 : 0
NISSignatureLastUpdated         : 25.02.2021 22:37:08
NISSignatureVersion             : 1.331.1839.0
OnAccessProtectionEnabled       : False
QuickScanAge                    : 701
QuickScanEndTime                : 28.03.2019 12:13:06
QuickScanStartTime              : 28.03.2019 12:04:24
RealTimeProtectionEnabled       : True
RealTimeScanDirection           : 0
PSComputerName                  :
"""

#from .agent_based_api.v1 import *
from .agent_based_api.v1 import register, render, Result, State, Service

import time

windows_defender_default_levels = {
    # Signature ages
    "AntispywareSignatureLastUpdated": (3 * 86400, 7 * 86400),
    "AntivirusSignatureLastUpdated": (2 * 86400, 7 * 86400),
    "NISSignatureLastUpdated": (5 * 86400, 7 * 86400),
    # Service states
    "AMServiceEnabled": "True",
    "BehaviorMonitorEnabled": "True",
    "AntispywareEnabled": "True",
    "AntivirusEnabled": "True",
    "NISEnabled": "True",
    "RealTimeProtectionEnabled": "True",
    "OnAccessProtectionEnabled": "True",
}


def parse_windows_defender(string_table):

    parsed = {}
    now = time.time()
    parsed = dict([(x[0].strip(), ":".join(x[1:]).strip()) for x in string_table])

    signatures_with_timestamps = ["AntispywareSignatureLastUpdated", "AntivirusSignatureLastUpdated", "NISSignatureLastUpdated", "QuickScanEndTime", "FullScanEndTime"]

    for signature in signatures_with_timestamps:
        """ Convert Timestamps to epoch and calculate age in seconds"""
        try:
            if parsed[signature].endswith("AM") or parsed[signature].endswith("PM"):
                update_date = time.mktime(time.strptime(parsed[signature], '%m/%d/%Y %I:%M:%S %p'))
            else:
                update_date = time.mktime(time.strptime(parsed[signature], '%d.%m.%Y %H:%M:%S'))
            signature_age_in_seconds = now - update_date
        except ValueError:
            signature_age_in_seconds = None
        parsed[signature] = signature_age_in_seconds

    return parsed


register.agent_section(
    name="windows_defender",
    parse_function=parse_windows_defender,
)


def discover_windows_defender(section):
    yield Service()


def check_windows_defender(params, section):

    ###########################
    # check age of signatures #
    ###########################

    signature_names = {
        "AntispywareSignatureLastUpdated": "AntiSpyware signature",
        "AntivirusSignatureLastUpdated": "AntiVirus signature",
        "NISSignatureLastUpdated": "NIS signature",
    }

    for signature_name, signature_description in signature_names.items():
        s = State.OK
        signature_age = section.get(signature_name, None)

        warn = params[signature_name][0]
        crit = params[signature_name][1]

        if signature_age is None:
            yield Result(state=State.UNKNOWN, summary = "Age of last %s is unknown" % (signature_description))

        else:
            infotext = "%s age: %s" % (signature_description, render.timespan(signature_age))
            thresholds = " (warn/crit at %s/%s)" % (render.timespan(warn), render.timespan(crit))

            if signature_age >= crit:
                infotext += thresholds
                s = State.CRIT

            elif signature_age >= warn:
                infotext += thresholds
                s = State.WARN

            yield Result(
                state=s,
                summary=infotext)

    ############################
    # check status of services #
    ############################

    service_names = {
    "AMServiceEnabled": "AM Service",
    "BehaviorMonitorEnabled": "Behavior Monitor",
    "AntispywareEnabled": "Antispyware",
    "AntivirusEnabled": "Antivirus",
    "NISEnabled": "NIS",
    "RealTimeProtectionEnabled": "RealTimeProtection",
    "OnAccessProtectionEnabled": "OnAccessProtection",
    }

    service_states = {
        "True": "enabled",
        "False": "disabled",
    }

    service_state_status = 0
    for service_name in service_names:

        if section[service_name] != params[service_name]:
            yield Result(state = State.WARN, summary = "service \"%s\" is %s" % (service_names[service_name], service_states[section[service_name]]))
            service_state_status += 1

    if service_state_status == 0:
        yield Result(state = State.OK, notice = "All services are started correctly")

    ############################
    # check age of last scans  #
    ############################

    scan_ages = {
        "FullScanEndTime": "Full Scan",
        "QuickScanEndTime": "Quick Scan"
    }

    for scan_type in scan_ages:
        if scan_type in params:
            warn = params[scan_type][0]
            crit = params[scan_type][1]

            thresholds = "(warn/crit at %s/%s)" % (render.timespan(warn), render.timespan(crit))

            if section[scan_type] is None:
                yield Result(state = State.CRIT, summary = "%s has never been executed %s" % (scan_ages[scan_type], thresholds))
            else:
                age = render.timespan(section[scan_type])
                if section[scan_type] >= crit:
                    yield Result(state = State.CRIT, summary = "last %s is %s ago %s" % (scan_ages[scan_type], age, thresholds))
                elif section[scan_type] >= warn:
                    yield Result(state = State.WARN, summary = "last %s is %s ago %s" % (scan_ages[scan_type], age, thresholds))
                else:
                    yield Result(state = State.OK, summary = "last %s is %s ago" % (scan_type, age))

    ##################
    # print versions #
    ##################

    versions = "Versions - AM Engine: %s, AM Product: %s, NIS Signature: %s, Antivirus Signature: %s, Antispyware Signature: %s" % (
        section["AMEngineVersion"],
        section["AMProductVersion"],
        section["NISSignatureVersion"],
        section["AntivirusSignatureVersion"],
        section["AntispywareSignatureVersion"],
        )
    yield Result(state = State.OK, notice = versions)


register.check_plugin(
    name = "windows_defender",
    service_name = "Windows Defender",
    sections=["windows_defender"],
    discovery_function = discover_windows_defender,
    check_function = check_windows_defender,
    check_default_parameters=windows_defender_default_levels,
    check_ruleset_name="windows_defender",
)

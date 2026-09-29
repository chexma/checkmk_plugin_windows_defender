# Windows Defender Plugin for Checkmk 2.5

A comprehensive Checkmk plugin for monitoring Windows Defender status, signature ages, scan ages, and service states on Windows hosts.

## Features

- **Signature Age Monitoring**: Track the age of AntiSpyware, AntiVirus, and NIS (Network Inspection System) signatures with configurable thresholds
- **Service State Monitoring**: Monitor 7 different Windows Defender services (AM Service, Behavior Monitor, Antispyware, Antivirus, NIS, Real-Time Protection, OnAccess Protection)
- **Scan Age Monitoring**: Track when the last Full Scan and Quick Scan were executed
- **Version Information**: Display AM Engine, AM Product, and signature versions in service details
- **Graphing**: Built-in metrics and graphs for signature ages and scan ages
- **Perfometer**: Visual indicator for antivirus signature age
- **Agent Bakery Support**: Deploy the Windows agent plugin via the Checkmk Agent Bakery (commercial editions: Pro, Ultimate, Cloud)
- **Configurable Date Formats**: Support for European (DD.MM.YYYY), US (MM/DD/YYYY), and ISO (YYYY-MM-DD) date formats

## Requirements

- Checkmk 2.5.0 or later (for Checkmk 2.4 use the 2.4.x releases of this plugin)
- Windows hosts with Windows Defender enabled
- Checkmk Agent for Windows installed on monitored hosts

## Installation

### From MKP File

```bash
# Upload and install
mkp add windows_defender-2.5.0.mkp

# Enable the package
mkp enable windows_defender 2.5.0

# Restart Apache for ruleset changes (if needed)
omd restart apache
```

### Manual Installation

Copy the plugin files to your Checkmk site:

```bash
# Agent plugin (Windows) - for manual deployment / agent download page
cp plugins_legacy/agents/windows/plugins/windows_defender.ps1 \
   ~/local/share/check_mk/agents/windows/plugins/

# Check plugin
cp plugins/windows_defender/agent_based/windows_defender.py \
   ~/local/lib/python3/cmk_addons/plugins/windows_defender/agent_based/

# Rulesets
cp plugins/windows_defender/rulesets/*.py \
   ~/local/lib/python3/cmk_addons/plugins/windows_defender/rulesets/

# Graphing
cp plugins/windows_defender/graphing/windows_defender.py \
   ~/local/lib/python3/cmk_addons/plugins/windows_defender/graphing/

# Bakery plugin (commercial editions only, Bakery API v2)
cp plugins/windows_defender/bakery/windows_defender.py \
   ~/local/lib/python3/cmk_addons/plugins/windows_defender/bakery/

# Agent plugin source used by the bakery
cp plugins/windows_defender/agents/windows_defender.ps1 \
   ~/local/lib/python3/cmk_addons/plugins/windows_defender/agents/
```

## Configuration

### Check Parameters

Configure thresholds via **Setup > Services > Service monitoring rules > Windows Defender signature age and state**:

| Parameter | Description | Default (Warn/Crit) |
|-----------|-------------|---------------------|
| Date format | Date format from Windows agent | European (DD.MM.YYYY) |
| Anti-Spyware Signature Age | Maximum age before alerting | 3 days / 7 days |
| Anti-Virus Signature Age | Maximum age before alerting | 2 days / 7 days |
| NIS Signature Age | Maximum age before alerting | 5 days / 7 days |
| Full Scan Age | Time since last full scan | 7 days / 14 days |
| Quick Scan Age | Time since last quick scan | 2 days / 7 days |
| Service States | Expected state (enabled/disabled) | All enabled |

### Agent Bakery (commercial editions: Pro, Ultimate, Cloud)

Deploy the agent plugin via **Setup > Agents > Windows, Linux, Solaris, AIX > Agent rules > Windows Defender**

The rule offers the following deployment types:

- **Deploy the plugin and run it synchronously** (default) - executed on every agent run
- **Deploy the plugin and run it asynchronously** - executed in the configured interval (default: 1 hour)
- **Do not deploy the plugin** - use this to exclude hosts or folders from a more general rule

> **Note:** The bakery plugin uses the Bakery API v2 (`cmk.bakery.v2_unstable`), which is marked *unstable* in Checkmk 2.5
> and may change with Checkmk updates until it becomes stable in 3.0.0. Please re-test agent baking after updating Checkmk.

## Agent Output Format

The Windows agent plugin outputs data in the `<<<windows_defender:sep(58)>>>` section format (colon-separated):

```
<<<windows_defender:sep(58)>>>
AMEngineVersion                 : 1.1.18500.10
AMProductVersion                : 4.18.2109.6
AMServiceEnabled                : True
AntispywareSignatureLastUpdated : 07.10.2021 10:38:18
AntivirusSignatureLastUpdated   : 07.10.2021 10:38:19
BehaviorMonitorEnabled          : True
RealTimeProtectionEnabled       : True
...
```

## Monitored Items

### Signature Ages (always checked)
- AntiSpyware signature age
- AntiVirus signature age
- NIS signature age

### Service States (configurable)
- AM Service
- Behavior Monitor
- Antispyware
- Antivirus
- NIS (Network Inspection System)
- Real-Time Protection
- OnAccess Protection

### Scan Ages (optional)
- Full Scan age
- Quick Scan age

### Version Information (displayed in details)
- AM Engine Version
- AM Product Version
- Signature Versions
- Running Mode
- Tamper Protection status
- Virtual Machine detection

## Metrics and Graphs

The plugin provides the following metrics:

| Metric | Description |
|--------|-------------|
| `antispyware_sig_age` | AntiSpyware signature age in seconds |
| `antivirus_sig_age` | AntiVirus signature age in seconds |
| `nis_sig_age` | NIS signature age in seconds |
| `full_scan_age` | Time since last full scan in seconds |
| `quick_scan_age` | Time since last quick scan in seconds |

Two combined graphs are available:
- **Windows Defender Signature Ages**: Shows all three signature ages
- **Windows Defender Scan Ages**: Shows full scan and quick scan ages

## Troubleshooting

### Date Format Issues

If signature ages show as "unknown", the date format might not match. Configure the correct format in the check parameters:

- **European**: `07.10.2021 10:38:18` or `07/10/2021 10:38:18`
- **US**: `10/07/2021 10:38:18 AM`
- **ISO**: `2021-10-07 10:38:18`

### Testing the Check

```bash
# Get raw agent output
cmk -d <hostname> | grep -A 50 "<<<windows_defender"

# Test check execution
cmk -v --detect-plugins=windows_defender <hostname>

# Debug with more verbosity
cmk -vv --debug --detect-plugins=windows_defender <hostname>

# Rediscover services
cmk -vI --detect-plugins=windows_defender <hostname>
```

## Version History

### 2.5.2
- Agent Bakery rule now has a "Deployment type" option: deploy synchronously, deploy asynchronously
  with an execution interval, or do not deploy (previously the rule had no parameters)
- Bakery plugin validates the rule with a pydantic model instead of `no_op_parser`

### 2.5.1
- Fixed: scan age set to "No levels" no longer raises CRIT when a scan has never been executed
- A scan that has never been executed no longer emits a misleading age metric of 0
- Documentation: Bakery API v2 is unstable in 2.5, edition names updated (Pro, Ultimate, Cloud)

### 2.5.0
- Ported to Checkmk 2.5 (requires 2.5.0 or later)
- Bakery plugin migrated from Bakery API v1 to Bakery API v2 (`cmk.bakery.v2_unstable`, unstable in 2.5)
  in the plugin family layout (`cmk_addons/plugins/windows_defender/bakery/`, agent source in `.../agents/`)
- Check API v2, Rulesets API v1 and Graphing API v1 are unchanged in 2.5 - no functional changes to the check

### 2.4.9
- Code refactoring for better maintainability
- Added TypedDict for type-safe check parameters
- Factory functions in ruleset to reduce code duplication
- Added combined graphs for signature and scan ages
- Removed unused code and imports

### 2.4.8
- Fixed `check_levels()` parameter format for Checkmk 2.4 API v2

### 2.4.6
- Removed auto-detect date format option
- Simplified date parsing logic

### 2.4.5
- Added configurable date format parameter (eu/us/iso)
- European date format as default

### 2.4.3
- Added graphing support (metrics, perfometer)

### 2.4.2
- Migrated to Checkmk 2.4 Check API v2
- Migrated to Rulesets API v1
- Added scan age monitoring
- Enhanced service state output

## License

GNU General Public License v2 (GPLv2)

## Author

Andre Eckstein

## Links

- [Checkmk Exchange](https://exchange.checkmk.com/)
- [GitHub Repository](https://github.com/chexma/checkmk_plugin_windows_defender)

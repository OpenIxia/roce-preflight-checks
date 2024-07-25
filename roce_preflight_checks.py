"""Keysight Collective Communication Benchmarks

Copyright (C) Keysight Technologies, Inc - All Rights Reserved.

THE CONTENTS OF THIS PROJECT ARE PROPRIETARY AND CONFIDENTIAL.
UNAUTHORIZED COPYING, TRANSFERRING OR REPRODUCTION OF THE CONTENTS OF THIS
PROJECT, VIA ANY MEDIUM IS STRICTLY PROHIBITED.

The receipt or possession of the source code and/or any parts thereof does not
convey or imply any right to use them for any purpose other than the purpose
for which they were provided to you.

The software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and non infringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in the
software.

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

USAGES:
   - python3.10 kccb.py --config ../demo/8ports_ipv4.yml --ixnetwork-host <ip>

   # To emulate RoCEv2 traffic using Traffic Item. User must set port_mode to nrz
   # in yml config file. This will automatically use Traffic Item.
   # chassis:
   #     port_mode: 4x100-nrz

"""
import json
import yaml
import jsonschema
from types import SimpleNamespace
import logging
import time
from typing import List
import pandas
import statistics
import argparse
import os
import ixnetwork_restpy
from requests.adapters import HTTPAdapter
import pluggy
import random
import signal
import sys
import traceback
from datetime import datetime
import paramiko
import re
from tabulate import tabulate
import io

try:
    import benchmark_spec
    import benchmark_plugin
except:
    pass

# Release notes:
#    - Fixed bug: Make script to run prechecks with and without rocev2 stack
#    - Check typeOfTest.  If it's all_to_all and pfc_incast precheck is enabled, abort the script with error.
#    - Close the test session if passed
VERSION="1.0.6"


class ConnectSSH:
    """
    SSH to the chassis CLI
    """
    def __init__(self, mainObj, host, username, password, pkeyFile=None, port=22, timeout=10):
        self.host = host
        self.username = username
        self.password = password
        self.pkey = None
        self.port = port
        self.timeout = timeout
        self.mainObj = mainObj

        if pkeyFile:
            # Convert the pkey file into a string
            pkeyFileOpen = open(pkeyFile)
            pkeyContents = pkeyFileOpen.read()
            pkeyFileOpen.close()
            pkeyString = io.StringIO.StringIO(pkeyContents)
            self.pkey = paramiko.RSAKey.from_private_key(pkeyString)

        try:
            self.sshClient = paramiko.SSHClient()
            self.sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.sshClient.connect(hostname=self.host,
                                   username=self.username,
                                   password=self.password,
                                   port=self.port, pkey=self.pkey,
                                   timeout=self.timeout)

            self.mainObj._logger.info(f'\nSuccessfully connected to chassis: {host}')
        except paramiko.SSHException:
            raise Exception(f'\nSSH Failed to connect to the chassis: {host} username:{self.username} password:{self.password}')
        except TimeoutError as errMsg:
            self.mainObj._precheckSetupTasks['License Check'].update({'result': 'Failed',
                                                                      'errorMsg': self.mainObj.wrapText(f'Connecting to chassis CLI: {host}', width=300)})
            raise Exception(f'License check: Connecting to chassis: {host}: {errMsg}')

    def enterCommand(self, command, commandInput=None):
        stdin, stdout, stderr = self.sshClient.exec_command(command)
        while not stdout.channel.exit_status_ready() and not stdout.channel.recv_ready():
            time.sleep(1)

        stdoutString = stdout.readlines()
        stderrString = stderr.readlines()
        return stdoutString, stderrString

    def close(self):
        self.sshClient.close()


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, logger):
        self._logger = logger
        super().__init__()

    def send(self, *args, **kwargs):
        import requests

        # If initial request fails, retry up to three times
        saved = None
        for attempt in range(4):
            if saved is not None:
                self._logger.info(f"Retry {attempt} of {saved.request.url}")
            try:
                return super().send(*args, **kwargs)
            except requests.exceptions.ConnectionError as e:
                self._logger.info(f"Requests connection error: {e}")
                saved = e
                continue
        raise saved


class KCCB:
    def __init__(self, optional_args: List[str] = None):
        self._session_assistant = None
        self._ixnetwork = None
        self._dest_macs = {}
        self._iterations = 1
        self._ip_type = None
        self._frame_overhead = None
        self._link_speed = None
        self._show_burst_timing = True
        # v1 is for ports in NRZ mode and using regular Traffic Item to
        # emulate RoCEv2 traffic
        self._v1 = False
        self._setup_prechecks()
        self._setup_logger()
        self._parse_args(optional_args)
        self._setYamlConfigDefaults()
        self._validate_config()
        self._register_plugin()

        self._includeRoceV2NgpfStack = False
        self._expiredLicenses = []
        self._isRocev2LicenseExists = False
        self._typeOfChassis = None
        # SPEED_100G, SPEED_200G, SPEED_400G, SPEED_800G
        self._linkSpeed = self._config.layer1_profiles[0].link_speed

        if self._args.validate is True:
            exit(0)

    def _setYamlConfigDefaults(self):
        """
        Set default Yaml config parameter values.
        Read user Yaml config file input and overwrite parameter values
        """
        self._all_hosts = []
        with open(self._args.config) as fileObj:
            ymlConfigs = yaml.safe_load(fileObj)

        for host in ymlConfigs['hosts']:
            self._all_hosts.append(host['name'])

        self._precheckSelectionsDict = {'prechecks': {'license_check': True,
                                                      'check_connectivity': False,
                                                      'setup_ports': False,
                                                      'setup_layer1': False,
                                                      'check_link_state': False,
                                                      'configure_interfaces': False,
                                                      'arp_gateways': False,
                                                      'ping_mesh': False,
                                                      'apply_rocev2_traffic': False,
                                                      'pfc_incast': False
                                                     }}

        self._yamlTestNames = {'tests': [{'profile_name': 'RoCEv2-Preflight-Checks'}]}
        self._yamlChassis = {'chassis': {'chassis_chain': '', 'primary_chassis_ip': ''}}

        self._yamlTestProfileDefaults = {'test_profiles': [{'name': 'RoCEv2-Preflight-Checks',
                                                            'typeOfTest': 'all_to_all',
                                                            'enableDcqcn': True,
                                                            'start': 1073741824,
                                                            'end': 1073741824,
                                                            'queue_pairs_per_flow': 0,
                                                            'bufferSize': 131072,
                                                            'hosts': [],
                                                            'skip_flows': [[]],
                                                            'step': 2,
                                                            'tos': 225,
                                                            'hosts': self._all_hosts}]}

        self._yamlLayer1ProfileDefaults = {'layer1_profiles': [{'name': 'layer1',
                                                                'auto_negotiate': False,
                                                                'ieee_defaults': False,
                                                                'link_speed': 'SPEED_400G',
                                                                'link_training': False,
                                                                'rs_fec': True,
                                                                'hosts': self._all_hosts,
                                                                'flow_control': {'ieee_802_1qbb': {'pfc_class_1': 2}}
                                                                }]}

    def _setup_prechecks(self):
        self._prechecks = False
        self._precheckSetupTasks = {'License Check':                        {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Check connectivity to traffic agents': {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Setup Ports':                          {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Setup L1 Configs':                     {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Check Link State':                     {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Configure Interfaces':                 {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Start Protocols':                      {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'ARP Gateways':                         {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Ping Mesh':                            {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'Apply RoCEv2 Traffic':                 {'result': 'Enabled: Skipped', 'errorMsg': None},
                                    'PFC Incast':                           {'result': 'Enabled: Skipped', 'errorMsg': None}}

    def _precheckSetupReport(self):
        """
        Generate a tabulated report
        """
        if self._prechecks is False:
            return

        self._precheckSetupHeaders = ['Tasks', 'Results', 'Messages']
        self._precheckSetupFile = 'precheck_setup_result.txt'
        finalResult = 'passed'

        precheckTaskList = []
        for task, result in self._precheckSetupTasks.items():
            if result['result'] == 'Failed':
                finalResult = 'failed'

            precheckTaskList.append((task, result['result'], result['errorMsg']))

        table = tabulate(precheckTaskList, headers=self._precheckSetupHeaders, tablefmt='fancy_grid')
        with io.open(self._precheckSetupFile, 'w', encoding="utf-8") as outFile:
            outFile.write(table)

        print(table)
        if finalResult == 'passed':
            self.cleanup()

    def _verifyLicenses(self):
        """
        SSH into the chassis, enter "show licenses" and verify if any license are about to expire in
        less than 15 days and if any license has expired.
        """
        if self._prechecks and self._config.prechecks.license_check is False:
            self._precheckSetupTasks['License Check'].update({'result': 'Disabled: Skippped'})
            raise Exception('License check is disabled. Skipping.')

        # S400GD-16P-QDD+FAN+NRZ+ROCEV2: Parse out the first letter for S or M type of AresOne
        chassisCardDescription = self._ixnetwork.AvailableHardware.find()[0].Chassis.find()[0].Card.find()[0].Description
        self._logger.info(f'Type of chassis: {chassisCardDescription}')
        self._typeOfChassis = chassisCardDescription[0]

        if hasattr(self._config, 'chassis') and hasattr(self._config.chassis, 'chassis_chain'):
            if self._config.chassis.chassis_chain:
                primaryChassisIp = self._config.chassis.primary_chassis_ip
        else:
            sys.exit(f'\nError: The Yaml config file requires key chassis.chassis_chain and primary_chassis_ip. Please update the Yaml config file')

        sshClient = ConnectSSH(mainObj=self, host=primaryChassisIp, username=self._args.ixnetwork_uid, password=self._args.ixnetwork_pwd)
        output = sshClient.enterCommand('show licenses')

        licenseDateFormat = '%d-%b-%Y'
        today = datetime.now()
        # Format: 25-Jun-2024
        todayObj = today.strftime(licenseDateFormat)
        licensesInChassis = []
        licenseWarnings = ''

        for line in output[0]:
            if 'IxNetwork RoCEv2' in line:
                #8706-639B-1D6F-DA22 | Keysight IxNetwork RoCEv2 Lossless Ethernet Test Package for AresONE-S 400GE and AresONE-M 800GE fixed chassis models | IxNetwork | 1        | 930-2208-01 | 27-Jul-2024 | 27-Jul-2024
                #regexMatch = re.search('.+\\| +Keysight IxNetwork RoCEv2.+\\| +IxNetwork +\\| +[0-9]+ +\\| +[^ ]+ +\\| +([^ ]+) +\\| +.+', line.strip())
                self._isRocev2LicenseExists = True

            regexMatch = re.search('.+\\|\s+(.+)\\| +([^ ]+) +\\| +[0-9]+ +\\| +([^ ]+) +\\| +([^ ]+) +\\| +.+', line.strip())
            if regexMatch:
                # 27-Jul-2024
                productDescription = regexMatch.group(1).strip()
                product = regexMatch.group(2).strip()
                partNumber = regexMatch.group(3).strip()
                expireDate = regexMatch.group(4)

                # 2024-07-27
                licenseDateObj = datetime.strptime(expireDate, licenseDateFormat).date()

                # 70 days, 0:00:00
                dateDelta = (licenseDateObj - today.date()).days

                print(f'\nProduct: {product}  ProductNumber: {partNumber}')
                print(f'\tDescr: {productDescription}')

                if dateDelta < 0:
                    print(f'\tExpired: {dateDelta} days ago')
                    self._expiredLicenses.append((product, partNumber, dateDelta))
                else:
                    # Duplicate licensess could exists. 1 could be expired and 1 could be valid.
                    for index, expiredLicense in enumerate(self._expiredLicenses):
                        expiredProductDescription = expiredLicense[0]
                        if productDescription == expiredProductDescription:
                            self._expiredLicenses.pop(index)
                            break

                    if dateDelta < 15:
                        print(f'\tWARNING!! {dateDelta} more days until expiration date')
                        licenseWarnings += f'{product}:{partNumber}: Expires in {dateDelta} days\n'
                    else:
                        print(f'\tLicense is valid: {dateDelta} more days until expiration date')

        if len(self._expiredLicenses) > 0:
            errorMsg = ''
            for expiredLicense in self._expiredLicenses:
                errorMsg += f'{expiredLicense[0]}:{expiredLicense[1]}: Expired {expiredLicense[2]} days ago\n\n'

            errorMsg += 'Scroll up for more details'
            self._precheckSetupTasks['License Check'].update({'result': 'Expired Licenses', 'errorMsg': self.wrapText(errorMsg, width=300)})
            raise Exception('License verification failed')
        else:
            if licenseWarnings:
                self._precheckSetupTasks['License Check'].update({'result': 'Passed', 'errorMsg': self.wrapText(licenseWarnings, width=300)})
            else:
                self._precheckSetupTasks['License Check'].update({'result': 'Passed'})

        print()

    def wrapText(self, text: str, width: int=50):
        """
        Wrap long text in a tabulated table cell
        """
        newText = ''
        start = 0
        maxWords = width

        while True:
            getText = text[start:maxWords].strip()
            if not getText:
                break

            newText += f'{getText}\n'
            maxWords += width
            start += width

        return newText

    def run(self):
        try:
            self.portUpDeltaTime = 0
            self.startTime = time.perf_counter()
            self.portSetupStartTime = time.perf_counter()

            self._connect()
            self._verifyLicenses()
            if self._args.no_reset_ports is False:
                self._setup_ports()

            self._setup_layer1()
            self._wait_for_linkup()
            self.portUpDeltaTime = time.perf_counter() - self.portSetupStartTime

            if self._v1:
                self._setup_control_plane()
                self._start_control_plane_v1()
                self._run_test_v1()
                self.cleanup()
            else:
                self._run_test()

            self.overallTestTime = time.perf_counter() - self.startTime
            self.showTimeMeasurements()

        except Exception as e:
            self._logger.error(traceback.format_exc(None, e))
            self._precheckSetupReport()
            #self._logger.info(self._config)
            #raise e

    def showTimeMeasurements(self):
        '''
        Use cmd line arg --show_time to show time measurements at the end of the test
        '''
        if self._args.show_time:
            print(f'\n\nPort setup time: {self.portUpDeltaTime}')
            if  hasattr(self._config.chassis, 'port_mode'):
                print(f'Change port mode time: {self.changePortModeTime}')

            if self._v1 is False:
                print(f'RoCEv2 NGPF setup time: {self.createRocev2NgpfDeltaTime}')
                print(f'RoCEv2 NGPF endpoints setup time: {self.configRocev2EndpointsDelta}')
                print(f'Start All Protocols UP time: {self.startAllProtocolTime}')
                print(f'Create RoCEv2 traffic time: {self.createRocev2Traffic}')
                print(f'Apply Traffic time: {self.applyTrafficTime}')
                print(f'Getting stats time: {self.getStats}')

            print(f'Overall Test time: {self.overallTestTime}\n\n')

    def cleanup(self):
        # Windows IxNetwork
        if '-useAPIServer' not in self._ixnetwork.Globals.CommandArgs:
            return

        # IxNetwork Web Edition
        if '-useAPIServer' in self._ixnetwork.Globals.CommandArgs and self._args.noCloseSession:
            return

        try:
            self._ixnetwork.NewConfig()
        except Exception as e:
            self._logger.error(e)
            self._logger.info(self._config)
            raise e
        if self._session_assistant is not None:
            self._session_assistant.Session.remove()

    def _register_plugin(self):
        try:
            self._plugin_manager = pluggy.PluginManager("benchmark")
            self._plugin_manager.add_hookspecs(benchmark_spec)
            self._plugin_manager.register(benchmark_plugin.Plugin())
        except:
            pass

    def _setup_logger(self):
        self._logger = logging.getLogger("kccb")
        self._logger.setLevel(logging.INFO)
        if (
            len(
                [
                    handler
                    for handler in self._logger.handlers
                    if handler.name == "console"
                ]
            )
            == 0
        ):
            sh = logging.StreamHandler()
            sh.name = "console"
            sh.setLevel(logging.INFO)
            formatter = logging.Formatter(
                "%(asctime)s [%(name)s] [%(levelname)s] %(message)s"
            )
            sh.setFormatter(formatter)
            self._logger.addHandler(sh)
            self._logger.info(f"Version = {VERSION}")

    def _parse_args(self, optional_args):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument(
            "--ixnetwork-host",
            help="Address of the host running IxNetwork (default is first chassis)",
            required=False,
        )
        parser.add_argument(
            "--ixnetwork-uid",
            help="User name for the IxNetwork host",
            default="admin",
        )
        parser.add_argument(
            "--ixnetwork-pwd",
            help="Password for the IxNetwork host",
            default="admin",
        )
        parser.add_argument(
            "--ixnetwork-debug",
            help="Flag to enable debug level tracing on the IxNetwork host (default is info)",
            action="store_true",
        )
        parser.add_argument(
            "--ixnetwork-session-name",
            help="Name for the IxNetwork session (e.g. your username, default is KCCB)",
            required=False,
        )
        parser.add_argument(
            "--output-dir",
            help="Directory that will hold all result artifacts",
            default="./results",
        )
        parser.add_argument(
            "--validate",
            help="Flag to only validate the configuration and exit",
            action="store_true",
        )
        parser.add_argument(
            "--ixnetwork-rest-port",
            help="IxNetwork Rest API listening port",
            required=False,
            default=None
        )
        parser.add_argument(
            "--show-time",
            help="Show at the end of the test how long each IxNetwork setup/action took",
            action="store_true",
            required=False,
        )
        parser.add_argument(
            "--no-reset-ports",
            help="Don't reset ports.",
            required=False,
            action="store_true"
        )
        parser.add_argument(
            "--noCloseSession",
            help="Don't close the IxNetwork test session",
            action="store_true",
            required=False,
        )
        parser.add_argument(
            "--config",
            help="Test configuration file in yaml format (required)\n\n"
            + "Example Configuration\n"
            + "---------------------\n"
            + "chain: [10.36.67.37]         # list of chassis, first chassis will be the primary chassis if more than one chassis in the chain\n"
            + "hosts:                       # list of hosts in the test\n"
            + "- name: Host1.1              # logical name of the host\n"
            + "  address: 32.0.1.2          # emulated address of the host (v4/v6)\n"
            + "  prefix: 24                 # prefix of emulated address host\n"
            + "  gateway: 32.0.1.1          # gateway address (v4/v6)\n"
            + "  additional_addresses: 0    # number of additional emulated addresses (min=0 max=32)\n"
            + "  location: 10.36.67.37;1;1  # physical chassis;card;port of the hardware test port \n"
            + "layer1_profiles:             # list of layer1 profiles\n"
            + "- name: layer1               # logical name of the layer1 profile\n"
            + "  hosts: [Host1.1]           # list of hosts in the layer1 profile\n"
            + "  link_speed: SPEED_100G     # the speed of the port (SPEED_100G | SPEED_200G | SPEED_400G)\n"
            + "  auto_negotiate: true       # enable/disable auto negotiation\n"
            + "  ieee_defaults: false       # true overrides auto_negotiate, link_training, rs_fec values for gigabit ethernet interfaces\n"
            + "  link_training: false       # enable/disable gigabit ethernet link training\n"
            + "  rs_fec: true               # enable/disable gigabit ethernet reed solomon forward error correction\n"
            + "  tx_clock_adjust_ppm: 0     # adjust transmit line clock (-100 to 100 parts per million, default 0)\n"
            + "  flow_control:              # flow control settings\n"
            + "    ieee_802_1qbb:           # priority based flow control settings\n"
            + "      pfc_class_1: 0         # pause traffic when receiving PFC pause frames with this class\n"
            + "test_profiles:               # list of AI/ML tests\n"
            + "- name: all_to_all           # logical name of the test\n"
            + "  hosts: [Host1.1]           # list of hosts in the test\n"
            + "  start: 32                  # the data size at which the test will start\n"
            + "  step: 2                    # the factor at which the data size will be increased\n"
            + "  end: 134217728             # the data size after which the test will end\n"
            + "  ethernet_mtu: 1500         # the system will derive the infiniband mtu based on the ethernet mtu\n"
            + "  skip_flows:                # skip flows within each list of hosts\n"
            + "    - [Host1.1 Host1.2]      # list of hosts (can have more than one list), skip flows between these hosts\n"
            + "  burst:                     # make each flow bursty (optional)\n"
            + "    packets_per_burst: 32    # number of packets per burst\n"
            + "    burst_rate_percent: 99   # frame rate during burst, as a percentage of line rate\n"
            + "    total_rate_percent: 70.0 # total frame rate across flows, as a percentage of line rate\n"
            + "    burst_offset_percent: 100 # offset between bursts for different flows from the same tx host, as a percentage of burst tx time (default 100)\n"
            + "    host_offset_percent: 0   # offset between tx start times for each host, as a percentage of burst tx time (default 0)\n"
            + "    host_offset_ns: 0        # offset between tx start times for each host, in nanoseconds (default 0)\n"
            + "    delayed_start: false     # wait for destination to start before sending flow (default false)\n"
            + "  send_pfc:                  # send PFC pause/resume frames with pfc_class_1 (optional)\n"
            + "    hosts: [Host1.1]         # list of hosts which send PFC frames\n"
            + "    interval_us: 10          # interval between PFC frames sent by each host\n"
            + "    pause_count: 1           # number of PFC pause frames sent on each cycle\n"
            + "    resume_count: 2          # number of PFC resume frames sent on each cycle\n"
            + "  ecn_capable: true          # set ECN-Capable Transport(0) in IP header, default true\n"
            + "tests:                       # list of test profiles that will be run\n"
            + "  profile_name: all_to_all   # name of a test profile\n",
            required=True,
        )
        if optional_args is None:
            self._args = parser.parse_args()
        else:
            self._args = parser.parse_args(optional_args)

    def _validate_config(self):
        schema = {
            "type": "object",
            "required": [
                "hosts",
                "layer1_profiles",
                "test_profiles",
                "tests",
            ],
            "properties": {
                "hosts": {
                    "type": "array",
                    "minItems": 2,
                    "items": {
                        "type": "object",
                        "required": [
                            "name",
                            "location",
                            "address",
                            "prefix",
                        ],
                        "properties": {
                            "name": {"type": "string"},
                            "location": {"type": "string"},
                            "address": {"type": "string"},
                            "gateway": {"type": "string"},
                            "prefix": {"type": "integer"},
                            "additional_addresses": {
                                "type": "integer",
                                "default": 0,
                            },
                        },
                    },
                },
                "layer1_profiles": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "name",
                            "hosts",
                            "link_speed",
                            "rs_fec",
                            "auto_negotiate",
                            "link_training",
                            "flow_control",
                        ],
                        "properties": {
                            "name": {"type": "string"},
                            "hosts": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "link_speed": {
                                "type": "string",
                                "enum": ["SPEED_100G", "SPEED_200G", "SPEED_400G", "SPEED_800G"],
                            },
                            "rs_fec": {"type": "boolean"},
                            "auto_negotiate": {"type": "boolean"},
                            "ieee_defaults": {"type": "boolean"},
                            "link_training": {"type": "boolean"},
                            "tx_clock_adjust_ppm": {
                                "type": "integer",
                                "minimum": -100,
                                "maximum": 100
                            },
                            "flow_control": {
                                "type": "object",
                                "required": ["ieee_802_1qbb"],
                                "properties": {
                                    "ieee_802_1qbb": {
                                        "type": "object",
                                        "required": ["pfc_class_1"],
                                        "properties": {
                                            "pfc_class_1": {
                                                "type": "integer",
                                                "minimum": 0,
                                                "maximum": 7,
                                            }
                                        },
                                    }
                                },
                            },
                        },
                    },
                },
                "test_profiles": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "name",
                            "hosts",
                            "start",
                            "end",
                            "step",
                            "ethernet_mtu",
                            "queue_pairs_per_flow",
                            "typeOfTest"
                        ],
                        "properties": {
                            "name": {"type": "string"},
                            "hosts": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "start": {"type": "integer"},
                            "end": {"type": "integer"},
                            "step": {"type": "integer"},
                            "ethernet_mtu": {"type": "integer"},
                            "tos": {"type": "integer", "default": "0"},
                            "queue_pairs_per_flow": {"type": "integer", "default": 0},
                            "typeOfTest": {"type": "string", "default": "all_to_all"},
                            "skip_flows": {
                                "type": "array",
                                "items": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "restrict_flows": {
                                "type": "array",
                                "items": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "burst": {
                                "type": "object",
                                "required": [
                                    "packets_per_burst",
                                    "burst_rate_percent",
                                    "total_rate_percent",
                                ],
                                "packets_per_burst": {"type": "integer"},
                                "burst_rate_percent": {"type": "number"},
                                "total_rate_percent": {"type": "number"},
                                "burst_offset_percent": {"type": "integer"},
                                "host_offset_percent": {"type": "integer"},
                                "host_offset_ns": {"type": "integer"},
                                "delayed_start": {"type": "boolean"},
                            },
                            "send_pfc": {
                                "type": "object",
                                "required": [
                                    "hosts",
                                    "interval_us",
                                    "pause_count",
                                    "resume_count",
                                ],
                                "hosts": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "interval_us": {"type": "integer"},
                                "pause_count": {"type": "integer"},
                                "resume_count": {"type": "integer"},
                            },
                            "ecn_capable": {"type": "boolean"},
                        },
                    },
                },
                "tests": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["profile_name"],
                        "properties": {
                            "profile_name": {"type": "string"},
                        },
                    },
                },
            },
        }

        with open(self._args.config) as fp:
            yamlConfigs = yaml.safe_load(fp)
            config_dict = self._precheckSelectionsDict
            config_dict.update(self._yamlChassis)
            config_dict.update(self._yamlTestNames)
            config_dict.update(self._yamlTestProfileDefaults)
            config_dict.update(self._yamlLayer1ProfileDefaults)

            if 'prechecks' in yamlConfigs:
                self._prechecks = True
                for key, value in yamlConfigs['prechecks'].items():
                    if key in config_dict['prechecks']:
                        if config_dict['prechecks'][key] != value:
                            config_dict['prechecks'][key] = value
                        else:
                            config_dict['prechecks'][key] = value

            if 'chassis' in yamlConfigs:
                config_dict['chassis'] = yamlConfigs['chassis']

            if 'hosts' in yamlConfigs:
                config_dict['hosts'] = yamlConfigs['hosts']

            if 'tests' in yamlConfigs:
                for index, runTestProfileNamesDict in enumerate(yamlConfigs['tests']):
                    defaultRunTestProfileNamesDict = {}
                    for key, value in runTestProfileNamesDict.items():
                        if 0 <= index < len(config_dict['tests']):
                            defaultRunTestProfileNamesDict = config_dict['tests'][index]

                        defaultRunTestProfileNamesDict[key] = value

                    if 0 <= index < len(config_dict['tests']):
                        config_dict['tests'].pop(index)

                    config_dict['tests'].insert(index, defaultRunTestProfileNamesDict)

            if 'test_profiles' in yamlConfigs:
                for index, testProfileDict in enumerate(yamlConfigs['test_profiles']):
                    defaultTestProfileDict = {}
                    for key, value in testProfileDict.items():
                        if 0 <= index < len(config_dict['test_profiles']):
                            defaultTestProfileDict = config_dict['test_profiles'][index]

                        defaultTestProfileDict[key] = value

                    if 0 <= index < len(config_dict['test_profiles']):
                        config_dict['test_profiles'].pop(index)

                    config_dict['test_profiles'].insert(index, defaultTestProfileDict)

            if 'layer1_profiles' in yamlConfigs:
                for index, layer1ProfileDict in enumerate(yamlConfigs['layer1_profiles']):
                    defaultLayer1ProfileDict = {}
                    for key, value in layer1ProfileDict.items():
                        if 0 <= index < len(config_dict['layer1_profiles']):
                            defaultLayer1ProfileDict = config_dict['layer1_profiles'][index]

                        defaultLayer1ProfileDict[key] = value

                    if 0 <= index < len(config_dict['layer1_profiles']):
                        config_dict['layer1_profiles'].pop(index)

                    config_dict['layer1_profiles'].insert(index, defaultLayer1ProfileDict)

            jsonschema.validate(config_dict, schema)

            for layer1_profile in config_dict["layer1_profiles"]:
                self._validate_foreign_keys(
                    "hosts", config_dict["hosts"], layer1_profile["hosts"]
                )

            for test_profile in config_dict["test_profiles"]:
                self._validate_foreign_keys(
                    "hosts", config_dict["hosts"], test_profile["hosts"]
                )
                if "skip_flows" in test_profile:
                    for host_list in test_profile["skip_flows"]:
                        self._validate_foreign_keys(
                            "hosts", config_dict["hosts"], host_list
                        )
                if "restrict_flows" in test_profile:
                    for host_list in test_profile["restrict_flows"]:
                        self._validate_foreign_keys(
                            "hosts", config_dict["hosts"], host_list
                        )
                if "send_pfc" in test_profile:
                    self._validate_foreign_keys(
                        "hosts", config_dict["hosts"], test_profile["send_pfc"]["hosts"]
                    )

            self._validate_foreign_keys(
                "test_profiles",
                config_dict["test_profiles"],
                [test["profile_name"] for test in config_dict["tests"]],
            )
            self._config = json.loads(
                json.dumps(config_dict),
                object_hook=lambda d: SimpleNamespace(**d),
            )

        # If ixnetwork-host was not passed as an argument, use chassis address
        if self._args.ixnetwork_host is None:
            self._args.ixnetwork_host = self._config.hosts[0].location.split(";")[0]

        self._logger.info(f"Validated {self._args.config} configuration")

    def _validate_foreign_keys(self, node_name, nodes, foreign_key_values):
        for foreign_key_value in foreign_key_values:
            if foreign_key_value not in [node["name"] for node in nodes]:
                raise ValueError(
                    f"{foreign_key_value} not present in {node_name}[:].name"
                )

    def _run_test_v1(self):
        '''
        This is the original function that uses Traffic Item to create RoCEv2 traffic
        '''
        for test in self._config.tests:
            self._summary_data = []
            self._application_data = []
            self._host_data = []
            self._test_profile = self._get_test_profile(test.profile_name)
            self._setup_flows_v1(self._test_profile)
            self._setup_pfc_flows(self._test_profile)
            self._logger.info(
                f"Begin {self._test_profile.name} test: {len(self._test_profile.hosts)} hosts,"
                + f" datasize {self._test_profile.start}B to {self._test_profile.end}B, step factor {self._test_profile.step},"
                + f" infiniband mtu {self._infiniband_mtu}"
                + f" tos {self._test_profile.tos}"
            )
            traffic_items = self._traffic.TrafficItem.find()
            traffic_items.Generate()
            data_size = self._test_profile.start
            while data_size <= self._test_profile.end:
                self._size = data_size
                self._logger.info(f"Sending {self._size} bytes...")
                self._set_data_size_properties_v1(self._test_profile)
                self._traffic.Apply()
                self._start_hw_flows_v1()
                self._get_hw_statistics_v1()
                self._logger.info(
                    "Run results:\n" + self.get_summary_data().to_string()
                )
                data_size = data_size * self._test_profile.step
            self._write_artifacts()
            self._logger.info(f"End {self._test_profile.name} test")

    def _run_test(self):
        '''
        This function uses the new IxNetwork RoCEv2 implementation
        '''
        self._summary_data = []
        self._application_data = []
        self._host_data = []

        for test in self._config.tests:
            self._logger.info(f'Running test name: {test.profile_name}')
            self._test_profile = [test_profile for test_profile in self._config.test_profiles if test_profile.name == test.profile_name][0]
            data_size = self._test_profile.start
            self._ethernet_mtu = self._test_profile.ethernet_mtu
            if self._test_profile.queue_pairs_per_flow > 0:
                # This value will get replaced in setup_control if test_profile.queue_pairs_per_flow == 0
                self._total_queue_pairs_per_flow  = self._test_profile.queue_pairs_per_flow

            if self._prechecks and self._config.prechecks.pfc_incast and self._test_profile.typeOfTest == 'all_to_all':
                errMsg = f'Precheck pfc_incast=True and test_profiles.typeOfTest="all_to_all".\ntypeOfTest needs to be "incast" if pfc_incast=True\nif pfc_incast=False, typeOfTest could be incast or all_to_all.\nNot sure what test to run.'
                self._precheckSetupTasks['PFC Incast'].update({'result': 'Failed', 'errorMsg': self.wrapText(errMsg, width=300)})
                raise Exception(errMsg)

            while data_size <= self._test_profile.end:
                # Variables inside this while loop are used in _setup_control_plane.
                # So calling _setup_control_plane() must come after these variable settings.
                #
                # If the required size is a multiple of 128MB, use 128MB as the buffer length.
                # If not, check whether it's a multiple of 64MB, 32MB, and so on.
                self._size = data_size
                sizePerDestination = self._size / len(self._config.hosts)
                # 134,217,728: max buffer size is around 220MB (less than 256MB, the next power of 2)
                #              So using 128MB that fits our max buffer size
                #              1024*1024=1MB, 1024*1024*1024=1GB
                #              threshold = 134,217,728
                threshold = 128 * (1024 * 1024)

                if self._test_profile.queue_pairs_per_flow == 0:
                    # Automatically calculate bufferSize for users
                    while True:
                        if sizePerDestination >= threshold and sizePerDestination % threshold == 0:
                            self._bufferSize = threshold / (1024 * 1024)
                            self._bufferSizeUnit = 'mb'
                            self._burstCount = sizePerDestination / threshold
                            break
                        else:
                            threshold = threshold / 2
                            if threshold < (1024 * 1024):
                                self._bufferSize = sizePerDestination
                                self._bufferSizeUnit = 'byte'
                                self._burstCount = 1
                                break
                else:
                    self._bufferSize = self._test_profile.bufferSize

                    if len(str(self._bufferSize)) > 6:
                        self._bufferSizeUnit = 'mb'
                    elif len(str(self._bufferSize)) < 7 and len(str(self._bufferSize)) > 2:
                        self._bufferSizeUnit = 'kb'
                    elif len(str(self._bufferSize)) > 3:
                        self._bufferSizeUnit = 'byte'

                    self._burstCount = 1

                self._setup_control_plane()
                self._setup_rocev2_flows()
                self._start_control_plane()
                self._pingEndpoints()

                if self._prechecks and self._config.prechecks.apply_rocev2_traffic:
                    if self._config.prechecks.license_check and self._isRocev2LicenseExists is False:
                        self._precheckSetupTasks['Apply RoCEv2 Traffic'].update({'result': 'Enabled: Skipped',
                                                                                 'errorMsg': 'License check enabled. RoCEv2 license does not exists.'})
                        raise Exception('RoCEv2 license does not exists. Skipping apply RoCEv2 traffic')

                if self._prechecks and self._includeRoceV2NgpfStack is False:
                    self._precheckSetupTasks['Apply RoCEv2 Traffic'].update({'result': 'Enabled: Skipped',
                                                                             'errorMsg': 'RoCEv2 protocol stack was not included'})
                    self._logger.info('Stopping all protocols')
                    self._ixnetwork.StopAllProtocols(Arg1='sync')
                    self._precheckSetupReport()
                    return

                if self._prechecks and self._config.prechecks.apply_rocev2_traffic is False:
                    self._precheckSetupTasks['Apply RoCEv2 Traffic'].update({'result': 'Disabled: Skipped'})
                    raise Exception('Apply RoCEv2 Traffic is disabled. Skipping')

                # This sets self._infiniband_mtu: if self._frame_overhead + ib_mtu <- ethernet_mtu
                self._get_test_profile(test.profile_name)

                host_count = len(self._test_profile.hosts)
                payload_size = self._size / host_count
                self._frame_size = (
                    self._frame_overhead + self._infiniband_mtu
                    if payload_size >= self._frame_overhead + self._infiniband_mtu
                    else self._frame_overhead + payload_size
                )

                self._frame_count = (
                    1
                    if payload_size <= self._infiniband_mtu
                    else payload_size / self._infiniband_mtu
                )

                self._logger.info(f'Type of test: {self._test_profile.typeOfTest}')
                self._logger.info(f'Begin {self._test_profile.name} test: {len(self._test_profile.hosts)} hosts:  linkSpeed:{int(self._link_speed)}GE dataSize:{self._size}  ethernetMTU:{self._test_profile.ethernet_mtu}  ibMTU:{self._infiniband_mtu}  dataSizePerDest:{sizePerDestination}  bufferSize:{self._bufferSize}{self._bufferSizeUnit.upper()}  burstCount:{self._burstCount}')

                # Creates RoCEv2 traffic. Sets flow.type and flow.burstCount
                self._setup_flows(self._test_profile)

                try:
                    self._logger.info('Applying Traffic')
                    applyTrafficStart = time.perf_counter()
                    self._ixnetwork.Traffic.Apply()
                    self._precheckSetupTasks['Apply RoCEv2 Traffic'].update({'result': 'Passed'})
                except Exception as errMsg:
                    self._precheckSetupTasks['Apply RoCEv2 Traffic'].update({'result': 'Failed', 'errorMsg': self.wrapText(errMsg)})
                    raise Exception(errMsg)

                if self._prechecks:
                    if hasattr(self._config.prechecks, 'pfc_incast') and self._config.prechecks.pfc_incast is False:
                        self._precheckSetupTasks['PFC Incast'].update({'result': 'Disabled: Skipped'})

                    # Could only run either all-to-all test or incast. If pfc_incast=True, then run unicast,
                    # call precheckSetupResport() and return.  Don't run RoCEv2 traffic again.
                    if hasattr(self._config.prechecks, 'pfc_incast') and self._config.prechecks.pfc_incast is True:
                        self._start_hw_flows()
                        self._get_hw_statistics()
                        self._getPFCStatistics()
                        self._logger.info('Stopping all protocols')
                        self._ixnetwork.StopAllProtocols(Arg1='sync')
                        self._precheckSetupReport()
                        return

                self._precheckSetupReport()
                self.applyTrafficTime = time.perf_counter() - applyTrafficStart

                self._start_hw_flows()
                self._get_hw_statistics()
                self._logger.info(f"RoCEv2 Statistics:\n{self.get_summary_data().to_string()}\n")
                data_size = data_size * self._test_profile.step

                self._logger.info('Stopping all protocols')
                self._ixnetwork.StopAllProtocols(Arg1='sync')
                time.sleep(15)

            start = time.perf_counter()
            self.cleanup()
            self._write_artifacts()
            self.writeArtifactsDeltaTime = time.perf_counter() - start
            self._logger.info(f"End {self._test_profile.name} test")

    def _write_artifacts(self):
        formatted_time = time.strftime("%Y-%m-%d_%H-%M-%S", time.gmtime())
        for output, name in [
            (self.get_summary_data(), "summary"),
            (self.get_application_data(), "application"),
            (self.get_host_data(), "host"),
        ]:
            filepath = os.path.join(
                self._args.output_dir,
                f"config-{os.path.splitext(os.path.basename(self._args.config))[0]}",
                f"test-{self._test_profile.name}_{name}_{formatted_time}.txt",
            )
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            # Originally, the filepath was passed in for the buf arg, but this doesn't work
            # in gitlab pipeline running python3.6 because this python version limits pandas
            # version to 1.1.5, which to_markdown fails to call attribute writelines.
            # So just get the returned string and write it after
            stringOutput = output.to_markdown()
            with open(filepath, 'w') as fileObj:
                fileObj.write(stringOutput)

            # Show result summary and Job Completion Time
            # ./results/config-demo_newRocev2Api_2ports/test-all_to_all_application_*

    def _import(self, imports):
        errors = self._ixnetwork.ResourceManager.ImportConfig(
            json.dumps(imports), False
        )
        if len(errors) > 0:
            raise Exception(errors)

    def _select(self, payload: dict) -> dict:
        response = self._ixnetwork.Select(selects=[payload])
        return json.loads(
            json.dumps(response[0]),
            object_hook=lambda d: SimpleNamespace(**d),
        )

    # If an IxNetwork session exists with the specified name, delete it
    def _delete_session(self, session_name):
        testplatform = ixnetwork_restpy.TestPlatform(self._args.ixnetwork_host)
        apikey = testplatform.Authenticate(self._args.ixnetwork_uid, self._args.ixnetwork_pwd)
        testplatform.ApiKey = apikey
        sessions = testplatform.Sessions
        sessions.find(Name=session_name)
        if sessions:
            sessions.remove()

    def _connect(self):
        import warnings

        # Don't blank out the existing session
        if self._args.no_reset_ports:
            clearConfig = False
        else:
            clearConfig = True

        warnings.filterwarnings("ignore", category=ResourceWarning)
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        if self._session_assistant is None:
            if not self._args.ixnetwork_session_name:
                if self._config.prechecks.check_connectivity:
                    self._args.ixnetwork_session_name = "RoCEv2-Preflight-Checks"
                else:
                    self._args.ixnetwork_session_name = "RoCEv2"

            self._logger.info(f'Connecting to IxNetwork API server {self._args.ixnetwork_host}')
            self._delete_session(self._args.ixnetwork_session_name)
            self._session_assistant = ixnetwork_restpy.SessionAssistant(
                IpAddress=self._args.ixnetwork_host,
                UserName=self._args.ixnetwork_uid,
                Password=self._args.ixnetwork_pwd,
                SessionName=self._args.ixnetwork_session_name,
                ClearConfig=clearConfig,
                RestPort=self._args.ixnetwork_rest_port,
                LogLevel=ixnetwork_restpy.SessionAssistant.LOGLEVEL_REQUEST_RESPONSE
                if self._args.ixnetwork_debug
                else ixnetwork_restpy.SessionAssistant.LOGLEVEL_NONE,
            )

            adapter = CustomHTTPAdapter(self._logger)
            self._session_assistant.TestPlatform._connection._session.mount(
                "http://", adapter
            )
            self._session_assistant.TestPlatform._connection._session.mount(
                "https://", adapter
            )
            self._logger.info(
                f"Started IxNetwork mw session on {self._args.ixnetwork_host}: {self._args.ixnetwork_session_name}"
            )
            self._ixnetwork = self._session_assistant.Ixnetwork
            preferences = self._ixnetwork.Globals.Preferences
            url = "%s/debug/ui" % preferences.href
            payload = {
                "sendPineFlagCfgToHWM": False,
            }
            preferences._connection._update(url, payload)
            url = "%s/debug/mw" % preferences.href
            payload = {
                "traceLevel": "all" if self._args.ixnetwork_debug else "none",
                "debugLog": self._args.ixnetwork_debug,
            }
            preferences._connection._update(url, payload)
            self._traffic = self._ixnetwork.Traffic
            self._ip_template = self._traffic.ProtocolTemplate.find(
                StackTypeId="^ipv4$"
            )
            self._udp_template = self._traffic.ProtocolTemplate.find(
                StackTypeId="^udp$"
            )
            self._custom_template = self._traffic.ProtocolTemplate.find(
                StackTypeId="^custom$"
            )
            self._traffic.EnableStaggeredTransmit = False
            self._ixnetwork.Statistics.TimestampPrecision = 9
            self._port_map: ixnetwork_restpy.PortMapAssistant = (
                self._session_assistant.PortMapAssistant()
            )

            if self._addChassis() is False:
                self._precheckSetupTasks['Check connectivity to traffic agents'].update({'result': f'Failed',
                                                                                         'errorMsg': f'Add chassis failed'})
                raise Exception(f'Adding Chassis failed')
            else:
                self._logger.info(f"Connected to traffic generator. IxNetwork Version:{self._ixnetwork.Globals.BuildNumber}")
                self._precheckSetupTasks['Check connectivity to traffic agents'].update({'result': f'Passed',
                                                                                        'errorMsg': f'IxNetwork Version: {self._ixnetwork.Globals.BuildNumber}'})

    def _addChassis(self):
        # Configure chained chassis's
        if hasattr(self._config, 'chassis') and hasattr(self._config.chassis, 'chassis_chain'):
            if self._config.chassis.chassis_chain:
                imports = []
                primaryChassisIp = self._config.chassis.primary_chassis_ip

                for index, chassisIp in enumerate(self._config.chassis.chassis_chain):
                    self._logger.info(f'Adding chassis: {chassisIp}')
                    if chassisIp != primaryChassisIp:
                        imports.append({"xpath": f"/locations[{index + 1}]",
                                        "hostname": chassisIp,
                                        "primaryDevice": primaryChassisIp})
                    else:
                        imports.append({"xpath": f"/locations[{index + 1}]",
                                        "hostname": chassisIp})

                try:
                    self._import(imports)
                    return True
                except Exception as errMsg:
                    self._logger.error(f'Add chassis: Failed: {chassisIp}')
                    return False

    def _getPortMode(self, portMode=None):
        """
        - Get the port-mode based on AresOne chassis type: S or M
        - Link speed is obtained by user setting in Yaml config file under test_profiles
        - Friendly name is either nrz or pam4 set by user in the Yaml config file
        - Fanout cable type is determined by verifying the port location for a dot, in
          which a dot represents a fanout port
        """
        for host in self._config.hosts:
            # 10.36.67.37/5 or 10.36.67.37/5.2
            portLocationSample = host.location
            port = portLocationSample.split('/')[-1]
            if '.' in port:
                self._cableType = 'fanout'
            else:
                self._cableType = 'nonFanout'

        # Note:
        #    - Bug: 400G pam4 non-fanout needs to use starTwoByFourHundredGigFannedOutPAM4RoCEv2
        portModesRocev2 = {'S': {'SPEED_100G': {'nrz':  {'fanout': 'starFourByHundredGigFannedOutNRZRoCEv2'},
                                                'pam4': {'fanout': 'startEightByHundredGigFannedOutPAM4RoCEv2'}
                                               },
                                 'SPEED_200G': {'pam4': {'fanout': 'starFourByTwoHundredGigFannedOutPAMRoCEv2'}
                                               },
                                 'SPEED_400G': {'pam4': {'fanout':    'starTwoByFourHundredGigFannedOutPAM4RoCEv2',
                                                         'nonFanout': 'starTwoByFourHundredGigFannedOutPAM4RoCEv2'}
                                               },
                                },
                           'M': {'SPEED_400G': {'pam4': {'fanout':    'starTwoByFourHundredGigFannedOutPAM4RoCEv2',
                                                         'nonFanout': 'starTwoByFourHundredGigFannedOutPAM4RoCEv2'}}
                                               }
                                }

        portModesNonRocev2 = {'S': {'SPEED_100G': {'nrz':  {'fanout':   'starFourByHundredGigFannedOutNRZ'},
                                                   'pam4': {'fanout':   'starEightByHundredGigFannedOutPAM4'}
                                                  },
                                    'SPEED_400G': {'pam4': {'fanout':   'starTwoByFourHundredGigFannedOutPAM4',
                                                            'nonFanout': 'starTwoByFourHundredGigNonFannedOutPAM4'}
                                                  },
                                   },
                              'M': {'SPEED_400G': {'pam4': {'fanout': 'starTwoByFourHundredGigFannedOutPAM4'}
                                                  }
                                   }
                             }

        if self._config.prechecks.license_check is False:
            self._logger.warning(f'User set license check=False. Defaulting portMode with RoCEv2')
            return portModesRocev2[self._typeOfChassis][self._linkSpeed][portMode].get(self._cableType, None)

        if self._isRocev2LicenseExists:
            return portModesRocev2[self._typeOfChassis][self._linkSpeed][portMode].get(self._cableType, None)

        if self._isRocev2LicenseExists is False:
            return portModesNonRocev2[self._typeOfChassis][self._linkSpeed][portMode].get(self._cableType, None)

    def _setup_ports(self):
        """Setup ports and ngpf topology, determine frame overhead

        ipv4 frame overhead = eth(14) + ipv4(20) + udp(8) + bth(12) + reth(16) + ibcrc(4) + fcs(4) = 78
        ipv6 frame overhead = eth(14) + ipv4(40) + udp(8) + bth(12) + reth(16) + ibcrc(4) + fcs(4) = 98
        """
        if self._prechecks and self._config.prechecks.setup_ports is False:
            self._precheckSetupTasks['Setup Ports'].update({'result': 'Disabled: Skipped'})
            raise Exception('Setup ports is disabled. Skipping')

        # Configure port speed mode
        # To get a list of all the options, go on the api-browser: ixNetwork.AvailableHardware.Chassis.Card.Aggregation
        # starEightByHundredGigFannedOutPAM4 | starFourByHundredGigFannedOutNRZRoCEv2 | starFourByHundredGigFannedOutNRZ
        if hasattr(self._config, 'chassis') and hasattr(self._config.chassis, 'port_mode'):
            # port_mode: nrz or pam4
            portMode = self._getPortMode(portMode=self._config.chassis.port_mode)
            if portMode is None:
                self._precheckSetupTasks['Setup Ports'].update({'result': 'Failed',
                                                                'errorMsg': f'Unknown port-mode in Yaml config file: {self._config.chassis.port_mode}'})
                raise Exception(f'Unknown port-mode: {self._config.chassis.port_mode}')

            location_list = []
            port_mode_list = []
            for host in self._config.hosts:
                location_list.append(host.location)
                port_mode_list.append(portMode)
                # the last true is forcefully clear ownership

            self._logger.info(f'Setup Ports: PortSpeed:{self._linkSpeed}  CableType:{self._cableType}  PortMode:{self._config.chassis.port_mode} -> {portMode}')
            self.startChangePortModeTime = time.perf_counter()

            try:
                # Configure port-mode
                self._ixnetwork.SwitchModeLocations(Arg1=location_list, Arg2=port_mode_list, Arg3=True)
            except Exception as errMsg:
                self._precheckSetupTasks['Setup Ports'].update({'result': 'Failed',
                                                                'errorMsg': self.wrapText(f'PortMode misconfiguration: {self._config.chassis.port_mode}',
                                                                                          width=300)})
                raise Exception(f'Setup Ports failed: {errMsg}')

            self.changePortModeTime = time.perf_counter() - self.startChangePortModeTime

        # Configure vports
        imports = []
        for i in range(len(self._config.hosts)):
            host = self._config.hosts[i]
            imports.append(
                {
                    "xpath": f"/vport[{i + 1}]",
                    "name": host.name,
                    "location": host.location
                }
            )

        try:
            self._import(imports)
            self._precheckSetupTasks['Setup Ports'].update({'result': 'Passed'})
        except Exception as errMsg:
            self._precheckSetupTasks['Setup Ports'].update({'result': 'Failed',
                                                            'errorMsg': self.wrapText(str(errMsg))})
            raise Exception(errMsg)

        self._ixnetwork.Vport.find().ConnectPorts(Arg2=True)

    def _wait_for_linkup(self):
        if self._prechecks and self._config.prechecks.check_link_state is False:
            self._precheckSetupTasks['Check Link State'].update({'result': 'Disabled: Skipped'})
            raise Exception('Check Link State is disabled. Skipping.')

        self._logger.info('Wait for link up')
        payload = {
            "from": "/",
            "properties": [],
            "children": [
                {
                    "child": f"^vport$",
                    "properties": ["name", "connectionState", "type"],
                    "filters": [],
                }
            ],
            "inlines": [],
        }

        LINK_TIMEOUT = 120
        start = time.time()
        while True:
            response = self._select(payload)
            if time.time() - start > LINK_TIMEOUT:
                payload = {
                    "from": "/",
                    "properties": [],
                    "children": [
                        {
                            "child": f"^(vport|l1Config|{response.vport[0].type.strip('Fcoe')}|fcoe)$",
                            "properties": ["*"],
                            "filters": [],
                        }
                    ],
                    "inlines": [],
                }
                response = self._select(payload)

                portsDown = f'Link UP failed after {LINK_TIMEOUT}secs:\n'
                for vport in response.vport:
                    port = vport.assignedToDisplayName
                    if vport.connectionState != "connectedLinkUp":
                        self._logger.error(f"Link down on: {vport}")
                        portsDown += f'{port} is down. ConnectionStatus: {vport.connectionStatus}\n'

                self._precheckSetupTasks['Check Link State'].update({'result': 'Failed',
                                                                     'errorMsg': self.wrapText(f"{portsDown}", width=300)})
                raise Exception(portsDown)
            if len(
                [
                    vport
                    for vport in response.vport
                    if vport.connectionState == "connectedLinkUp"
                ]
            ) == len(response.vport):
                break
            time.sleep(2)

        self._logger.info("Linkup on all ports")
        self._precheckSetupTasks['Check Link State'].update({'result': 'Passed'})

    def wrapText(self, text, width=50):
        newText = ''
        start = 0
        maxWords = width

        while True:
            getText = text[start:maxWords].strip()
            if not getText:
                break

            newText += f'{getText}\n'
            maxWords += width
            start += width

        return newText

    def _setup_control_plane(self):
        if self._prechecks and self._config.prechecks.configure_interfaces is False:
            self._precheckSetupTasks['Configure Interfaces'].update({'result': 'Disabled: Skipped'})
            raise Exception('Configure Interfaces is disabled. Skipping.')

        start = time.perf_counter()
        imports = []

        for i in range(len(self._config.hosts)):
            host = self._config.hosts[i]

            if hasattr(host, "additional_addresses") is False:
                host.additional_addresses = 0

            imports.append(
                {
                    "xpath": f"/topology[{i + 1}]",
                    "name": f"{host.name} Topology",
                    "vports": [f"/vport[{i + 1}]"],
                }
            )
            imports.append(
                {
                    "xpath": f"/topology[{i + 1}]/deviceGroup[1]",
                    "name": f"{host.name} DeviceGroup",
                    "multiplier": 1 + host.additional_addresses,
                }
            )
            imports.append(
                {
                    "xpath": f"/topology[{i + 1}]/deviceGroup[1]/ethernet[1]",
                    "name": f"{host.name} Ethernet",
                }
            )
            imports.append(
                {
                    "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1] mac']/counter",
                    "start": self._get_mac(host.name),
                    "step": "00:00:00:00:00:01",
                    "direction": "increment",
                }
            )

            step = "0.0.0.1"
            if ":" in host.address:
                self._ip_type = "ipv6"
                self._rocev2_type = "roce6v2"
                self._frame_overhead = 98
                step = "::1"
            else:
                self._ip_type = "ipv4"
                self._rocev2_type = "rocev2"
                self._frame_overhead = 78
                step = "0.0.0.1"

            imports.append(
                {
                    "xpath": f"/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]",
                    "name": f"{host.name} {self._ip_type}",
                }
            )
            imports.append(
                {
                    "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1] address']/counter",
                    "start": host.address,
                    "step": step,
                    "direction": "increment",
                }
            )
            imports.append(
                {
                    "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1] prefix']/singleValue",
                    "value": str(host.prefix),
                }
            )

            if hasattr(host, 'gateway'):
                imports.append(
                    {
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1] gatewayIp']/singleValue",
                        "value": host.gateway,
                    }
                )
            else:
                imports.append(
                    {
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1] resolveGateway']/singleValue",
                        "value": "false"
                    }
                )

            if self._v1 is False:
                imports.append({
                    "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1] mtu']/singleValue",
                    "value": f"{self._test_profile.ethernet_mtu}"
                })

        self._logger.info('Configuring IPv4 NGPF')

        try:
            self._import(imports)
        except Exception as errMsg:
            self._precheckSetupTasks['Configure Interfaces'].update({'result': 'Failed', 'errorMsg': self.wrapText(errMsg)})
            raise Exception(errMsg)

        self._precheckSetupTasks['Configure Interfaces'].update({'result': 'Passed'})
        self.createRocev2NgpfDeltaTime = time.perf_counter() - start

    def _setup_rocev2_flows(self):
        # Configure RoCEv2 endpoints
        # Note: Cannot configured the RoCEv2 endpoints unless the RoCEv2 object is created/imported
        #       in _setup_control_plane

        if self._prechecks:
            if self._config.prechecks.license_check and self._isRocev2LicenseExists is False:
                self._logger.warning('Exiting _setup_rocev2_flows: prechecks.license_check=True and isRocev2LicenseExists=False.')
                return

            if self._config.prechecks.configure_interfaces is False:
                self._logger.warning('Exiting _setup_rocev2_flows: prechecks.config_interfaces=False.')
                return

            if self._precheckSetupTasks['Configure Interfaces']['result'] == 'failed':
                self._logger.warning('Exiting _setup_rocev2_flows: Config interfaces result failed.')
                return

        self._logger.info("Setup RoCEv2 flows")

        imports = []
        checkOneTimeOnly = True
        totalHostRocev2Defined = 0

        # Must import the RoCEv2 object before selecting the RoCEv2 endpoint
        for i in range(len(self._config.hosts)):
            # Calculate: Every srcHost's endpoint queuePairIds
            # Get total queue pair IDs from user data file

            if hasattr(self._config.hosts[i], 'rocev2'):
                totalHostRocev2Defined += 1
                if checkOneTimeOnly:
                    self._includeRoceV2NgpfStack = True
                    checkOneTimeOnly = False

            if self._config.prechecks.pfc_incast and hasattr(self._config.hosts[i], 'rocev2') is False:
                errorMsg = f'pfc_incast=True. Expecting host {self._config.hosts[i].name}\nwith rocev2 param with an remoteEndpoint host.'
                self._precheckSetupTasks['Configure Interfaces'].update({'result': 'Failed',
                                                                         'errorMsg': self.wrapText(errorMsg, width=300)})
                raise Exception(errorMsg)

            # Note: self._test_profile was set in setup_control_plane()
            if self._test_profile.queue_pairs_per_flow > 0:
                if self._test_profile.typeOfTest == 'all_to_all':
                    self._total_queue_pair = self._test_profile.queue_pairs_per_flow * (len(self._config.hosts)-1)
                else:
                    self._total_queue_pair = self._test_profile.queue_pairs_per_flow
            else:
                if hasattr(self._config.hosts[i], 'rocev2'):
                    if self._config.prechecks.pfc_incast:
                        if hasattr(self._config.hosts[i], 'incast') is False:
                            errorMsg = f'pfc_incast=True. Expecting host {self._config.hosts[i].name}\nwith incast parameter set to tx or rx.'
                            self._precheckSetupTasks['Configure Interfaces'].update({'result': 'Failed',
                                                                                     'errorMsg': self.wrapText(errorMsg, width=300)})
                            raise Exception(errorMsg)

                    # Calculate: Every srcHost's endpoint queuePairIds
                    # Get total queue pair IDs from user data file
                    self._total_queue_pair = 0
                    for index, endpoint in enumerate(self._config.hosts[i].rocev2):
                        if self._skip_flow(self._test_profile, self._config.hosts[i].name, endpoint.remoteEndpoint):
                            continue

                        # Add up all the queue pairs from each endpoint
                        if hasattr(endpoint, 'queuePairValues') and len(endpoint.queuePairValues) > 0:
                            self._total_queue_pair += len(endpoint.queuePairValues)
                        else:
                            self._total_queue_pair += 1

            if hasattr(self._config.hosts[i], 'rocev2'):
                imports.append({
                    "xpath": f"/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]",
                    "name": f'{self._config.hosts[i].name}',
                    "qpCount": self._total_queue_pair
                })

        if len(self._config.hosts) != totalHostRocev2Defined and self._test_profile.typeOfTest == 'all_to_all':
            self._test_profile.typeOfTest = 'incast'

        if self._test_profile.typeOfTest == 'all_to_all':
            self._total_queue_pairs_per_flow = int(self._total_queue_pair / int((len(self._config.hosts) - 1)))
        else:
            # Only supporting all-to-all or incast. For incast, just supporting 1 qp per flow.
            self._total_queue_pairs_per_flow = 1

        if self._includeRoceV2NgpfStack:
            self._import(imports)

        imports = []
        self._num_flows = 0
        start = time.perf_counter()
        starting_queue_pair_id = 100

        for i in range(len(self._config.hosts)):
            endpointList = []
            endpointOverlayIndex = 1

            if hasattr(self._config.hosts[i], 'rocev2') is False:
                continue

            for endpoint in self._config.hosts[i].rocev2:
                endpointList.append(f'{endpoint.remoteEndpoint}')

            # Expecting full-mesh: Each Topology host sends to all Topology
            for endpoint in self._config.hosts[i].rocev2:
                skip = self._skip_flow(self._test_profile, self._config.hosts[i].name, endpoint.remoteEndpoint)
                if self._skip_flow(self._test_profile, self._config.hosts[i].name, endpoint.remoteEndpoint):
                    self._logger.info(f'Skipping flows: {self._config.hosts[i].name} -> {endpoint.remoteEndpoint}')
                    continue

                imports.append({
                    "xpath": f"/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1]",
                    "peerNameList": endpointList,
                    "allPeersAdded": True
                })

                # Apply same udp source port to all QPs for this endpoint
                if hasattr(endpoint, 'udpSourcePort') and type(endpoint.udpSourcePort) is not list:
                    imports.append({
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1] udpSourcePort']/singleValue",
                        "value": endpoint.udpSourcePort
                    })

                # Apply same dscp number to all QPs for this endpoint
                if hasattr(endpoint, 'dscp') and type(endpoint.dscp) is not list:
                    imports.append({
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1] dscp']/singleValue",
                        "value": endpoint.dscp
                    })

                # self._bufferSizeUnit options: byte, mb, kb
                imports.append({
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1] messageSizeUnit']/singleValue",
                        "value": self._bufferSizeUnit
                    })

                imports.append({
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1] messageSize']/singleValue",
                        "value": self._bufferSize
                    })

                if hasattr(endpoint, 'queuePairValues') or self._test_profile.queue_pairs_per_flow > 0:
                    customizeQP = True
                else:
                    customizeQP = False

                imports.append({
                        "xpath": f"/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1]",
                        "customizeQP": customizeQP
                    })

                if self._test_profile.queue_pairs_per_flow == 0 and hasattr(endpoint, 'queuePairValues') is False:
                    self._num_flows += 1
                    continue

                if self._test_profile.queue_pairs_per_flow > 0:
                    queue_pair_id_list = []

                    for number in range(0, self._test_profile.queue_pairs_per_flow):
                        starting_queue_pair_id += 1
                        queue_pair_id_list.append(starting_queue_pair_id)

                elif hasattr(endpoint, 'queuePairValues'):
                    queue_pair_id_list = endpoint.queuePairValues

                for index, queuePairId in enumerate(queue_pair_id_list):
                    self._num_flows += 1

                    imports.append({
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1] customQP']/overlay[{endpointOverlayIndex}]",
                        "count": 1,
                        "index": endpointOverlayIndex,
                        "value": f"{queuePairId}"
                    })

                    if self._test_profile.queue_pairs_per_flow == 0 and hasattr(endpoint, 'udpSourcePort'):
                        if type(endpoint.udpSourcePort) is list:
                            try:
                                imports.append({
                                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1] udpSourcePort']/overlay[{endpointOverlayIndex}]",
                                        "count": 1,
                                        "index": endpointOverlayIndex,
                                        "value": f"{endpoint.udpSourcePort[index]}"
                                    })
                            except:
                                # The index is not found.
                                # User srcUdpPort list doesn't have enough values. Set srcUdpPort to default value.
                                pass

                    if self._test_profile.queue_pairs_per_flow == 0 and hasattr(endpoint, 'dscp'):
                        if type(endpoint.dscp) is list:
                            try:
                                imports.append({
                                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[1] dscp']/overlay[{endpointOverlayIndex}]",
                                        "count": 1,
                                        "index": endpointOverlayIndex,
                                        "value": f"{endpoint.dscp[index]}"
                                    })
                            except:
                                # The index is not found. user dscp list doesn't have enough values. Set dscp to default value.
                                pass

                    endpointOverlayIndex += 1

        if self._includeRoceV2NgpfStack:
            self._logger.info(f'Configuring RoCEv2 NGPF endpoint flows: {self._num_flows}  QPsPerFlow:{self._total_queue_pairs_per_flow}  buffer size: {self._bufferSize} {self._bufferSizeUnit}')
            self._import(imports)

        self.configRocev2EndpointsDelta = time.perf_counter() - start

    def _pingEndpoints(self):
        if self._prechecks:
            if self._config.prechecks.ping_mesh is False:
                self._precheckSetupTasks['Ping Mesh'].update({'result': 'Disabled: Skippped'})
                raise Exception (f'Ping Mesh is disabled. Skipping.')

            if self._precheckSetupTasks['Configure Interfaces']['result'] == 'failed':
                raise Exception (f'Configure interfaces failed. Skipping ping mesh.')

        # Get all endpoint host IP addresses
        self._logger.info('Pinging Endpoints to check reachability')
        endpointIPAddresses = []
        failures = []
        for i in range(len(self._config.hosts)):
            host = self._config.hosts[i]
            endpointIPAddresses.append(host.address)

        pingException = False
        pingFailures = ''

        for i in range(len(self._config.hosts)):
            host = self._config.hosts[i]
            host_name = host.name
            hostSrcIp = host.address
            if self._ip_type == 'ipv4':
                host_ipObj = self._ixnetwork.Topology.find(Name=host_name).DeviceGroup.find().Ethernet.find().Ipv4.find()
            if self._ip_type == 'ipv6':
                host_ipObj = self._ixnetwork.Topology.find(Name=host_name).DeviceGroup.find().Ethernet.find().Ipv6.find()

            for endpointIPAddress in endpointIPAddresses:
                if endpointIPAddress == hostSrcIp:
                    continue

                result = host_ipObj.SendPing(DestIP=endpointIPAddress)
                self._logger.info(f'PingEndpoints: FrameSize:64B srcHost:{host_name}  srcIp:{hostSrcIp}  destIp:{endpointIPAddress}  result:{result[0]["arg2"]}')
                if result[0]['arg2'] is False:
                    pingFailures += f'{hostSrcIp} -> {endpointIPAddress}\n'
                    pingException = True

                # else:
                #     # Ping with jumbo size frames if 64Byte ping works
                #     result = host_ipObj.SendPingWithCountAndPayload(DestIP=endpointIPAddress, PingCount=3, PingInterval=1, PayloadSize=1472)
                #     self._logger.info(f'PingEndpoints: FrameSize:1472B  srcHost:{host_name}  srcIp:{hostSrcIp}  destIp:{endpointIPAddress}  result:{result[0]["arg2"]}')
                #     if result[0]['arg2'] is False:
                #         pingFailures += f'{hostSrcIp} -> {endpointIPAddress}\n'
                #         pingException = True

        if pingException:
            self._precheckSetupTasks['Ping Mesh'].update({'result': 'Failed',
                                                          'errorMsg': self.wrapText(pingFailures, width=300)})
            raise Exception('Pinging endpoints with 64 Bytes frames failed')
        else:
            self._precheckSetupTasks['Ping Mesh'].update({'result': 'Passed'})

        '''
        # Ping with jumbo frames
        if pingException is False:
            # Ping endpoints using jumbo size frames
            pingException = False
            pingFailures = ''

            for i in range(len(self._config.hosts)):
                host = self._config.hosts[i]
                host_name = host.name
                hostSrcIp = host.address
                if self._ip_type == 'ipv4':
                    host_ipObj = self._ixnetwork.Topology.find(Name=host_name).DeviceGroup.find().Ethernet.find().Ipv4.find()
                if self._ip_type == 'ipv6':
                    host_ipObj = self._ixnetwork.Topology.find(Name=host_name).DeviceGroup.find().Ethernet.find().Ipv6.find()

                for endpointIPAddress in endpointIPAddresses:
                    if endpointIPAddress == hostSrcIp:
                        continue

                    result = host_ipObj.SendPingWithCountAndPayload(DestIP=endpointIPAddress, PingCount=3, PingInterval=1, PayloadSize=1472)
                    self._logger.info(f'PingEndpoints: FrameSize:1472  srcHost:{host_name}  srcIp:{hostSrcIp}  destIp:{endpointIPAddress}  result:{result[0]["arg2"]}')
                    if result[0]['arg2'] is False:
                        pingFailures += f'{hostSrcIp} -> {endpointIPAddress}\n'
                        pingException = True

            if pingException:
                self._precheckSetupTasks['Ping Mesh'].update({'result': 'Failed',
                                                                        'errorMsg': self.wrapText(pingFailures, width=300)})
                raise Exception('Pinging endpoints with jumbo size frames failed')
            else:
                self._precheckSetupTasks['Ping Mesh'].update({'result': 'Passed'})
        '''

    def _reconfigure_rocev2_bufferSize(self):
        '''
        Reconfigure the RoCEv2 NGPF buffer sizes
        The bufferSize and bufferSizeUnit were calculated in _run_test()
        '''
        imports = []
        self._logger.info(f'Reconfiguring RoCEv2 NGPF endpoint flow buffer size: {self._bufferSize} {self._bufferSizeUnit}')

        for i in range(len(self._config.hosts)):
            hostFlowId = 0

            # Expecting full-mesh: Each Topology host sends to all Topology
            for endpoint in self._config.hosts[i].rocev2:
                # Each endpoint has a unique flow ID.
                # Queue Pair IDs use overlays[id]
                hostFlowId += 1

                imports.append({
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[{hostFlowId}] bufferSize']/singleValue",
                        "value": self._bufferSize
                    })

                # Options: byte, mb, kb
                imports.append({
                        "xpath": f"/multivalue[@source = '/topology[{i + 1}]/deviceGroup[1]/ethernet[1]/{self._ip_type}[1]/{self._rocev2_type}[1]/flows[{hostFlowId}] bufferSizeUnit']/singleValue",
                        "value": self._bufferSizeUnit
                    })

        self._import(imports)

    def _setup_layer1(self):
        """Setup host.location layer1 characteristics

        Get the state of /vport and /locations
        For every /vport if the speed does not match what is asked for then
            Find the resource group mode that matches the speed
            Set the resource group
        Find the /vport/l1Config -currentType and set the applicable properties for the following paths
            - /vport/l1Config -currentType: "<currentType>Fcoe"
            - /vport/l1Config/<currentType>/
            - /vport/l1Config/<currentType>/fcoe
        """
        if self._prechecks and self._config.prechecks.setup_layer1 is False:
            self._precheckSetupTasks['Setup L1 Configs'].update({'result': 'Disabled: Skippped'})
            raise Exception('Setup Layer1 is disabled. Skipping.')

        self._logger.info("Setup ports layer1")

        # add parameter for port modes. resource
        speed_map = {
            "SPEED_100G": {
                "actualSpeed": 100000,
                "speed": "speed100g",
                "resourceMode": ["novusHundredGig", "OneHundredGig", "FourByHundredGig"],
            },
            "SPEED_200G": {
                "actualSpeed": 200000,
                "speed": "speed200g",
                "resourceMode": ["TwoHundredGig"],
            },
            "SPEED_400G": {
                "actualSpeed": 400000,
                "speed": "speed400g",
                "resourceMode": ["FourHundredGig"],
            },
        }
        payload = {
            "from": "/",
            "properties": [],
            "children": [
                {
                    "child": f"^(vport|availableHardware|chassis|card|aggregation)$",
                    "properties": [
                        "actualSpeed",
                        "name",
                        "connectionState",
                        "location",
                        "resourceMode",
                        "type",
                        "hostname",
                        "cardId",
                        "card",
                        "activePorts",
                        "availableModes",
                        "mode",
                        "resourcePorts",
                    ],
                    "filters": [],
                }
            ],
            "inlines": [],
        }
        response = self._select(payload)
        mode_switches = {"locations": [], "modes": []}
        for i in range(len(self._config.hosts)):
            vport = response.vport[i]
            host = self._config.hosts[i]
            layer1_profile = self._get_layer1_profile(host.name)
            mode = speed_map[layer1_profile.link_speed]
            if (
                len(
                    [
                        mode not in vport.resourceMode
                        for mode in mode["resourceMode"]
                    ]
                )
                == 0
            ):
                mode_switches["locations"].append(host.location)
                mode_switches["modes"].append(
                    self._get_mode(
                        host.location, mode["resourceMode"], response
                    )
                )
        if len(mode_switches["locations"]) > 0:
            self._ixnetwork.SwitchModeLocations(
                Arg1=mode_switches["locations"],
                Arg2=mode_switches["modes"],
                Arg3=False,
            )
            self._logger.info(
                f"Switched port modes on locations {', '.join(mode_switches['locations'])}"
            )
            response = self._select(payload)

        imports = []

        for i in range(len(response.vport)):
            vport = response.vport[i]
            port_type = vport.type.replace("Fcoe", "")
            if self._link_speed is None:
                self._link_speed = (
                    int(speed_map[layer1_profile.link_speed]["actualSpeed"])
                    / 1000
                )

            # port_type: nrz+rocev2 = starFourHundredGigLanFcoe
            imports.append(
                {
                    "xpath": f"/vport[{i + 1}]/l1Config",
                    "currentType": f"{port_type}Fcoe",
                }
            )

            if hasattr(layer1_profile, "tx_clock_adjust_ppm"):
                ppm = layer1_profile.tx_clock_adjust_ppm
            else:
                ppm = 0

            imports.append(
                {
                    "xpath": f"/vport[{i + 1}]/l1Config/{port_type}",
                    "speed": speed_map[layer1_profile.link_speed]["speed"],
                    "enableAutoNegotiation": layer1_profile.auto_negotiate,
                    "ieeeL1Defaults": layer1_profile.ieee_defaults,
                    "enableRsFec": layer1_profile.rs_fec,
                    "linkTraining": layer1_profile.link_training,
                    "enablePPM": ppm != 0,
                    "ppm": ppm,
                }
            )
            pfc_class = layer1_profile.flow_control.ieee_802_1qbb.pfc_class_1
            imports.append(
                {
                    "xpath": f"/vport[{i + 1}]/l1Config/{port_type}/fcoe",
                    "supportDataCenterMode": True,
                    "flowControlType": "ieee802.1Qbb",
                    "pfcQueueGroupSize": "pfcQueueGroupSize-4",
                    "enablePFCPauseDelay": False,
                    "pfcPauseDelay": 1,
                    "pfcQueueGroups": [
                        pfc_class,
                        0 if pfc_class == 1 else 1,
                        0 if pfc_class == 2 else 2,
                        0 if pfc_class == 3 else 3,
                    ],
                }
            )

        if self._args.no_reset_ports is False:
            try:
                self._import(imports)
            except Exception as errMsg:
                self._precheckSetupTasks['Setup L1 Configs'].update({'result': 'Failed', 'errorMsg': self.wrapText(errMsg)})
                raise Exception(errMsg)

            self._precheckSetupTasks['Setup L1 Configs'].update({'result': 'Passed'})

    def _get_mode(self, location, resource_mode, select_response):
        for chassis in select_response.availableHardware.chassis:
            for card in chassis.card:
                for aggregation in card.aggregation:
                    for mode in aggregation.availableModes:
                        if resource_mode in mode:
                            return mode
        raise Exception(
            f"Resource speed {resource_mode} not found for location {location}"
        )

    def _start_control_plane_v1(self):
        self._ixnetwork.StartAllProtocols(Arg1="async")
        payload = {
            "from": "/",
            "properties": [],
            "children": [
                {
                    "child": f"^(topology|deviceGroup|ethernet|{self._ip_type})$",
                    "properties": [
                        "ports",
                        "portsStateCount",
                        "name",
                        "sessionStatus",
                    ],
                    "filters": [],
                }
            ],
            "inlines": [
                {
                    "child": "vport",
                    "properties": ["name", "location"],
                }
            ],
        }
        MAC_RESOLUTION_TIMEOUT = 300
        start = time.time()
        while True:
            all_up = True
            response = self._select(payload)
            if time.time() - start > MAC_RESOLUTION_TIMEOUT:
                for topology in response.topology:
                    for deviceGroup in topology.deviceGroup:
                        for ethernet in deviceGroup.ethernet:
                            if (
                                all(
                                    [
                                        status == "up"
                                        for status in ethernet.sessionStatus
                                    ]
                                )
                                is False
                            ):
                                self._logger.error(
                                    f"Gateway mac resolution failed on {topology}"
                                )
                raise Exception(
                    f"Failed to resolve gateway macs after {MAC_RESOLUTION_TIMEOUT} seconds"
                )
            for topology in response.topology:
                for deviceGroup in topology.deviceGroup:
                    for ethernet in deviceGroup.ethernet:
                        for ip in getattr(ethernet, self._ip_type):
                            all_up &= all(
                                [status == "up" for status in ip.sessionStatus]
                            )

            if all_up is True:
                self._topologies = self._ixnetwork.Topology.find()
                self._logger.info(
                    f"Started control plane and resolved gateway mac addresses"
                )
                break
            time.sleep(2)

    def _start_control_plane(self):
        if self._precheckSetupTasks['Configure Interfaces']['result'] == 'failed':
            self._precheckSetupTasks['Start Protocols'].update({'result': 'Disabled: Skippped'})
            raise Exception (f'Configure interfaces failed. Skipping Start Protocol.')

        startAllProtocolStart = time.perf_counter()
        self._logger.info('Start all protocols')

        try:
            self._ixnetwork.StartAllProtocols(Arg1="async")
        except Exception as errMsg:
            self._precheckSetupTasks['Start Protocols'].update({'result': 'Failed', 'errorMsg': self.wrapText(str(errMsg))})
            raise Exception(f'Starting Protocols: Failed: {str(errMsg)}')

        payload = {
            "from": "/",
            "properties": [],
            "children": [
                {
                    "child": f"^(topology|deviceGroup|ethernet|{self._ip_type}|rocev2|roce6v2)$",
                    "properties": [
                        "ports",
                        "portsStateCount",
                        "name",
                        "sessionStatus",
                    ],
                    "filters": [],
                }
            ],
            "inlines": [
                {
                    "child": "vport",
                    "properties": ["name", "location"],
                }
            ],
        }
        MAC_RESOLUTION_TIMEOUT = 300
        start = time.time()
        while True:
            all_up = True
            response = self._select(payload)
            if time.time() - start > MAC_RESOLUTION_TIMEOUT:
                for topology in response.topology:
                    for deviceGroup in topology.deviceGroup:
                        for ethernet in deviceGroup.ethernet:
                            if (
                                all(
                                    [
                                        status == "up"
                                        for status in ethernet.sessionStatus
                                    ]
                                )
                                is False
                            ):
                                self._logger.error(
                                    f"Gateway mac resolution failed on {topology}"
                                )

                if self._config.prechecks.arp_gateways:
                    self._precheckSetupTasks['ARP Gateways'].update({'result': 'Failed',
                                                                     'errorMsg': self.wrapText(f'Failed to resolve gateway Mac after {MAC_RESOLUTION_TIMEOUT} seconds')})
                raise Exception(
                    f"Failed to resolve gateway macs after {MAC_RESOLUTION_TIMEOUT} seconds"
                )
            for topology in response.topology:
                for deviceGroup in topology.deviceGroup:
                    for ethernet in deviceGroup.ethernet:
                        for ip in getattr(ethernet, self._ip_type):
                            if self._ip_type == 'ipv4':
                                if self._includeRoceV2NgpfStack:
                                    for rocev2 in ip.rocev2:
                                        all_up &= all(
                                            [status == "up" for status in rocev2.sessionStatus]
                                        )
                                else:
                                    all_up &= all(
                                        [status == "up" for status in ip.sessionStatus]
                                    )
                            if self._ip_type == 'ipv6':
                                if self._includeRoceV2NgpfStack:
                                    for roce6v2 in ip.roce6v2:
                                        all_up &= all(
                                            [status == "up" for status in roce6v2.sessionStatus]
                                        )
                                else:
                                    all_up &= all(
                                        [status == "up" for status in ip.sessionStatus]
                                    )

            if all_up is True:
                self._precheckSetupTasks['Start Protocols'].update({'result': 'Passed'})
                self._topologies = self._ixnetwork.Topology.find()
                self._logger.info(
                    f"Started control plane and resolved protocols"
                )
                break
            time.sleep(2)

        self.startAllProtocolTime = time.perf_counter() - startAllProtocolStart

        if all_up is False:
            self._precheckSetupTasks['Start Protocols'].update({'result': 'Failed'})

            if self._config.prechecks.arp_gateways is False:
                self._precheckSetupTasks['ARP Gateways'].update({'result': 'Failed'})
            else:
                self._precheckSetupTasks['ARP Gateways'].update({'result': 'Failed',
                                                                'errorMsg': self.wrapText(f'Failed to resolve gateway Mac after {MAC_RESOLUTION_TIMEOUT} seconds')})
                raise Exception('ARP gateways failed')


        if self._config.prechecks.arp_gateways is False:
            self._precheckSetupTasks['ARP Gateways'].update({'result': 'Skipped'})
        else:
            self._precheckSetupTasks['ARP Gateways'].update({'result': 'Passed'})

    def _skip_flow(self, test, src_host_name, dst_host_name):
        if src_host_name == dst_host_name:
            return True

        if hasattr(test, "skip_flows"):
            for skip_list in test.skip_flows:
                if src_host_name in skip_list:
                    if dst_host_name in skip_list:
                        return True

        if not hasattr(test, "restrict_flows"):
            return False

        # Where skip_flows specifies that there should be no flows between
        # hosts on the same list, restrict_flows is the opposite:  there
        # should only be Ethernet flows between hosts on the same list.
        for restrict_list in test.restrict_flows:
            if src_host_name in restrict_list:
                if dst_host_name in restrict_list:
                    return False

        return True

    def _setup_flows_v1(self, test):
        if hasattr(self._test_profile, "tos") is False:
            self._test_profile.tos = 0
        # set ECN Capable(0) unless ecn_capable is set to false
        if hasattr(self._test_profile, "ecn_capable") and not test.ecn_capable:
            pass
        else:
            self._test_profile.tos = (self._test_profile.tos & 0xfc) | 0x1
        self._traffic.TrafficItem.find().remove()
        imports = [
            {
                "xpath": f"/traffic",
                "autoCorrectL4HeaderChecksums": False,
                "useTxRxSync": False,
            }
        ]

        # item for RoCEv2 traffic
        item = 1
        imports.append(
            {
                "xpath": f"/traffic/trafficItem[{item}]",
                "name": "rocev2",
                "trafficItemType": "l2L3",
                "trafficType": self._ip_type,
                "srcDestMesh": "manyToMany",
                "egressEnabled": True,
            }
        )

        i = 0
        self._map_flow_to_src_index = {}
        self._map_flow_to_dst_index = {}
        self._map_flow_to_src_num_flows = {}
        for src_host_name in test.hosts:
            src_index = self._get_host_index(src_host_name) + 1

            if hasattr(self._config.hosts[src_index - 1], 'queue_pair_ids'):
                queuePairIds = self._config.hosts[src_index -1].queue_pair_ids
                queuePairIdIndex = 0

            src_num_flows = len(
                [
                    dst_host_name
                    for dst_host_name in test.hosts
                    if not self._skip_flow(test, src_host_name, dst_host_name)
                ]
            )
            for dst_host_name in test.hosts:
                dst_index = self._get_host_index(dst_host_name) + 1
                if self._skip_flow(test, src_host_name, dst_host_name):
                    continue

                i += 1
                self._map_flow_to_src_index[i] = src_index
                self._map_flow_to_dst_index[i] = dst_index
                self._map_flow_to_src_num_flows[i] = src_num_flows

                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/endpointSet[{i}]",
                        "name": f"{src_host_name} -> {dst_host_name}",
                        "sources": [ f"/topology[{src_index}]" ],
                        "destinations": [ f"/topology[{dst_index}]" ],
                        "allowEmptyTopologySets": False,
                    }
                )

                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/framePayload",
                        "type": "custom",
                        "customPattern": "00",
                        "customRepeat": True,
                    }
                )

                if hasattr(test, "burst"):
                    rate = test.burst.burst_rate_percent
                else:
                    # Divide by number of flows from each source
                    rate = 100.0 / self._map_flow_to_src_num_flows[i]
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/frameRate",
                        "rate": rate,
                    }
                )
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/frameSize",
                        "type": "fixed",
                    }
                )
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/transmissionControl",
                        "frameCount": 1,
                        "type": "fixedFrameCount",
                    }
                )
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'ethernet-1']/field[@alias = 'ethernet.header.pfcQueue-4']",
                        "valueType": "singleValue",
                        "singleValue": 0,
                    }
                )
                if self._ip_type == "ipv4":
                    imports.append(
                        {
                            "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'ipv4-2']/field[@alias = 'ipv4.header.priority.raw-3]",
                            "activeFieldChoice": True,
                            "valueType": "singleValue",
                            "singleValue": "%x" % self._test_profile.tos,
                        }
                    )
                else:
                    imports.append(
                        {
                            "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'ipv6-2']/field[@alias = 'ipv6.header.versionTrafficClassFlowLabel.trafficClass-2]",
                            "valueType": "singleValue",
                            "singleValue": self._test_profile.tos,
                        }
                    )

                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'udp-3']/field[@alias = 'udp.header.srcPort-1']",
                        "auto": False,
                        "valueType": "singleValue",
                        "singleValue": str(6000 + i),
                    }
                )
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'udp-3']/field[@alias = 'udp.header.dstPort-2']",
                        "auto": False,
                        "valueType": "singleValue",
                        "singleValue": "4791",
                    }
                )

                if hasattr(self._config.hosts[src_index - 1], 'queue_pair_ids'):
                    if type(queuePairIds) == list and len(queuePairIds) > 0:
                        try:
                            valueList = queuePairIds[queuePairIdIndex]
                            queuePairIdIndex += 1

                            imports.append(
                                {
                                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'infiniBandBaseTransportHeader-4']/field[@alias   = 'infiniBandBaseTransportHeader.baseTransportHeader.destQp-10']",
                                    "valueList": valueList,
                                    "valueType": "valueList"
                                }
                            )
                        except IndexError:
                            # Handle a condition if user did not create enough items in the queue_pair_ids list
                            pass

                # Workaround: 100th endpoint set needs to be applied on its own
                if i + 1 == 100:
                    self._import(imports)
                    imports = []

                if i == 100:
                    self._import(imports)
                    imports = []

        self._num_flows = i

        imports.append(
            {
                "xpath": f"/traffic/trafficItem[{item}]/tracking",
                "trackBy": ["trackingenabled0", "sourceDestPortPair0"],
            }
        )

        if self._ip_type == "ipv4":
            ecnOffsetBits = 126
        else:
            ecnOffsetBits = 122
        imports.append(
            {
                "xpath": f"/traffic/trafficItem[{item}]/egressTracking",
                "offset": "Custom",
                "customOffsetBits": ecnOffsetBits,
                "encapsulation": "Any: Use Custom Settings",
                "customWidthBits": 2,
            }
        )
        self._import(imports)
        self._logger.info(f"Configured {self._num_flows} flows...")

    def _setup_flows(self, test):
        '''
        if hasattr(self._test_profile, "tos") is False:
            self._test_profile.tos = 0

        # set ECN Capable(0) unless ecn_capable is set to false
        if hasattr(self._test_profile, "ecn_capable") and not test.ecn_capable:
            pass
        else:
            self._test_profile.tos = (self._test_profile.tos & 0xfc) | 0x1
        '''
        if self._includeRoceV2NgpfStack is False:
            return

        start = time.perf_counter()
        self._logger.info('Add RoceV2 Flow Groups in Traffic ')
        self._traffic.AddRoCEv2FlowGroups()
        # self._logger.info('Generate RoCEv2 Traffic')
        # self._ixnetwork.Traffic.RoceV2Traffic.Generate()

        imports = []
        if hasattr(self._test_profile, 'enableDcqcn'):
            if self._test_profile.enableDcqcn is False:
                self._logger.info('Disable RoCEv2 DCQCN')
                for roceTrafficPortConfig in self._traffic.RoceV2Traffic.RoceV2PortConfig.find():
                    index = roceTrafficPortConfig.href.split('/')[-1]
                    imports.append({
                        "xpath": f"/traffic/roceV2Traffic/roceV2PortConfig[{index}]/roceV2DcqcnParams",
                        "enabled": False
                })

        self._logger.info("Configuring RoCEv2 traffic burst count and type")
        #for roceTrafficStream in self._traffic.RoceV2Traffic.RoceV2Stream.find():
        #    roceTrafficStream.Type = 'fixed'
        #    roceTrafficStream.BurstCount = int(self._burstCount)
        for index in range(self._num_flows):
            imports.append({
                "xpath": f"/traffic/roceV2Traffic/roceV2Stream[{index + 1}]",
                "burstCount": int(self._burstCount),
                "type": "fixed"
            })

        if hasattr(self._test_profile, 'portTransmit'):
            for host in self._test_profile.portTransmit:
                for roceTrafficPortConfig in self._traffic.RoceV2Traffic.RoceV2PortConfig.find(TxPort=host.host):
                    index = roceTrafficPortConfig.href.split('/')[-1]

                    imports.append({
                        "xpath": f"/traffic/roceV2Traffic/roceV2PortConfig[{index}]",
                        "txCtrlParam": host.txCtrlParam,
                        "targetLineRateInPercent": host.targetLineRateInPercent,
                        "interBatchPeriodValue": host.interBatchPeriodValue,
                        "interBatchPeriodUnits": host.interBatchPeriodUnits
                    })


        self._import(imports)
        self.createRocev2Traffic = time.perf_counter() - start

    def _setup_pfc_flows(self, test):
        if not hasattr(test, "send_pfc"):
            return

        # traffic item for PFC pause/resume frames
        item = 2

        src_list = [
            self._get_host_index(src_host_name) + 1
            for src_host_name in test.send_pfc.hosts
        ]

        endpoints = []
        i = 0
        for src_index in src_list:
            i = i + 1
            endpoints.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/endpointSet[{i}]",
                    "sources": [
                        f"/vport[{src_index}]/protocols"
                    ],
                }
            )

        imports = [
            {
                "xpath": f"/traffic/trafficItem[{item}]",
                "name": "PFC",
                "trafficType": "raw",
                "endpointSet": endpoints,
            }
        ]

        i = 0
        for src_host_name in test.send_pfc.hosts:
            layer1_profile = self._get_layer1_profile(src_host_name)
            pfc_class = layer1_profile.flow_control.ieee_802_1qbb.pfc_class_1

            i += 1
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/frameSize",
                    "type": "fixed",
                    "fixedSize": 64,
                }
            )
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/transmissionControl",
                    "frameCount": 1,
                    "type": "fixedFrameCount",
                }
            )

            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'ethernet-1']/field[@alias = 'ethernet.header.destinationAddress-1']",
                    "valueType": "singleValue",
                    "singleValue": f"01:80:C2:00:00:01",
                }
            )
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'ethernet-1']/field[@alias = 'ethernet.header.sourceAddress-2']",
                    "valueType": "singleValue",
                    "singleValue": self._get_mac(src_host_name),
                }
            )
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'ethernet-1']/field[@alias = 'ethernet.header.etherType-3']",
                    "valueType": "singleValue",
                    "singleValue": "8808",
                    "auto": False,
                }
            )

            # Set PFC queue to 6 (same as CNP), so any incoming PFC pause frames on other classes will be ignored
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'ethernet-1']/field[@alias = 'ethernet.header.pfcQueue-4']",
                    "valueType": "singleValue",
                    "singleValue": 6,
                }
            )

            # Set up MAC Control packet using custom 16-bit headers, allowing for variation across packets.
            # Value is specified as a hex string
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'custom-2']/field[@alias = 'custom.header.length-1']",
                    "valueType": "singleValue",
                    "singleValue": 16,
                }
            )
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'custom-2']/field[@alias = 'custom.header.data-2']",
                    "valueType": "singleValue",
                    "singleValue": "0101",
                }
            )

            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'custom-3']/field[@alias = 'custom.header.length-1']",
                    "valueType": "singleValue",
                    "singleValue": 16,
                }
            )
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'custom-3']/field[@alias = 'custom.header.data-2']",
                    "valueType": "singleValue",
                    "singleValue": f"00{(1 << pfc_class):02x}",
                }
            )

            for x in range(8):
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'custom-{x+4}']/field[@alias = 'custom.header.length-1']",
                        "valueType": "singleValue",
                        "singleValue": 16,
                    }
                )
                if x == pfc_class:
                    quanta_list = (["ffff"] * test.send_pfc.pause_count) + (["0"] * test.send_pfc.resume_count)
                    imports.append(
                        {
                            "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'custom-{x+4}']/field[@alias = 'custom.header.data-2']",
                            "valueType": "valueList",
                            "valueList": quanta_list,
                        }
                    )
                else:
                    imports.append(
                        {
                            "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/stack[@alias = 'custom-{x+4}']/field[@alias = 'custom.header.data-2']",
                            "valueType": "singleValue",
                            "singleValue": "0",
                        }
                    )

            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/configElement[{i}]/framePayload",
                    "type": "custom",
                    "customPattern": "00",
                    "customRepeat": True,
                }
            )

        self._import(imports)
        self._num_pfc_flows = i
        self._logger.info(f"Configured PFC tx: host count {i}, interval {test.send_pfc.interval_us} us, pause count {test.send_pfc.pause_count}, resume count {test.send_pfc.resume_count}...")

    def _get_host_index(self, host_name) -> int:
        for i in range(len(self._config.hosts)):
            if host_name == self._config.hosts[i].name:
                return i
        return None

    def _get_test_profile(self, test_profile_name):
        for test_profile in self._config.test_profiles:
            if test_profile.name == test_profile_name:
                #for ib_mtu in [256, 512, 1024, 2048, 4096, 8192]:
                # Following NVIDIA MTU: https://enterprise-support.nvidia.com/s/article/mtu-considerations-for-roce-based-applications
                for ib_mtu in [256, 512, 1024, 2048, 4096]:
                    if (
                        self._frame_overhead + ib_mtu
                        < test_profile.ethernet_mtu
                    ):
                        self._infiniband_mtu = ib_mtu
                    else:
                        break
                return test_profile
        raise Exception(
            f"Test profile {test_profile_name} not found in config"
        )

    def _get_layer1_profile(self, host_name):
        for layer1_profile in self._config.layer1_profiles:
            if host_name in layer1_profile.hosts:
                return layer1_profile

    def get_summary_data(self):
        dataframe = pandas.DataFrame.from_records(self._summary_data)
        return dataframe

    def get_application_data(self):
        dataframe = pandas.DataFrame.from_records(self._application_data)
        return dataframe

    def get_host_data(self):
        dataframe = pandas.DataFrame.from_records(self._host_data)
        return dataframe

    def _get_host(self, host_name):
        for host in self._config.hosts:
            if host.name == host_name:
                return host
        raise Exception(
            f"The host {host_name} does not exist in the configuration"
        )

    def _get_mac(self, host_name):
        for i in range(0, len(self._config.hosts)):
            if self._config.hosts[i].name == host_name:
                return f"00:CB:{i + 1:02X}:00:00:01"

    def _get_destination_mac(self, host_name):
        for i in range(0, len(self._config.hosts)):
            if self._config.hosts[i].name == host_name:
                if host_name not in self._dest_macs:
                    payload = {
                        "from": f"{self._topologies[i].href}/deviceGroup/1/ethernet/1/{self._ip_type}/1",
                        "properties": ["resolvedGatewayMac"],
                        "children": [],
                        "inlines": [],
                    }
                    response = self._select(payload)
                    self._dest_macs[host_name] = response.resolvedGatewayMac[0]
                return self._dest_macs[host_name]

    def _get_ip(self, host_name):
        host = self._get_host(host_name)
        return host.address

    def _set_data_size_properties_v1(self, test_profile):
        """Set flow framesize and framecount for the workload data size.
        Framesize must be <= frame_overhead + self._infiniband_mtu
        Framecount should be the amount to transmit the entire data size

        self._size is the current data size
        """
        host_count = len(test_profile.hosts)
        payload_size = self._size / host_count

        self._frame_size = (
            self._frame_overhead + self._infiniband_mtu
            if payload_size >= self._frame_overhead + self._infiniband_mtu
            else self._frame_overhead + payload_size
        )

        self._frame_count = (
            1
            if payload_size <= self._infiniband_mtu
            else payload_size / self._infiniband_mtu
        )

        imports = []

        if hasattr(test_profile, "burst"):
            burst = test_profile.burst

            # provide default values for optional parameters
            if not hasattr(burst, "burst_offset_percent"):
                burst.burst_offset_percent = 100
            if not hasattr(burst, "host_offset_percent"):
                burst.host_offset_percent = 0
            if not hasattr(burst, "delayed_start"):
                burst.delayed_start = False

            ETH_OVERHEAD = 20
            max_fps = self._link_speed * 1000000000 / ((self._frame_size + ETH_OVERHEAD) * 8)
            burst_fps = max_fps * burst.burst_rate_percent / 100.0
            burst_tx_time_ns = 1000000000.0 * burst.packets_per_burst / burst_fps

            print("Burst traffic:")
            print("  - burst length " + str(burst.packets_per_burst) + " packets")
            print("  - burst offset " + str(burst.burst_offset_percent) + "%")
            if burst.host_offset_percent == 0 and hasattr(burst, "host_offset_ns"):
                burst.host_offset_percent = 100.0 * burst.host_offset_ns / burst_tx_time_ns
                print("  - host offset " + str(burst.host_offset_ns) + " ns")
            else:
                print("  - host offset " + str(burst.host_offset_percent) + "%")
            if burst.delayed_start:
                print("  - delayed start, wait for each destination before starting flow")
            print("burst tx time " + str(burst_tx_time_ns) + " ns")

            # when to start this flow, as a percentage of burst tx time
            start_delay_list = []

            # number of active destinations for this source when this flow starts
            active_destinations_list = []
            current_src = 0
            for i in range(self._num_flows):
                src_index = self._map_flow_to_src_index[i + 1]
                if src_index != current_src:
                    current_src = src_index
                    if i == 0:
                        host_offset = 0
                    else:
                        host_offset += burst.host_offset_percent
                        self._show_burst_timing = False # only show burst timing once

                    if burst.delayed_start:
                        active_destinations = 0
                        for j in range(i, self._num_flows):
                            if self._map_flow_to_src_index[j + 1] != current_src:
                                break

                            # count the number of destinations which are already active
                            # when this source starts sending
                            if self._map_flow_to_dst_index[j + 1] < current_src:
                                active_destinations += 1
                    else:
                        active_destinations = self._map_flow_to_src_num_flows[i + 1]

                    flow_offset = 0
                else:
                    flow_offset += burst.burst_offset_percent

                start_delay = host_offset + flow_offset

                # check if source needs to wait for destination
                if burst.delayed_start:
                    dst_index = self._map_flow_to_dst_index[i + 1]
                    if dst_index > current_src:
                        start_delay = (dst_index - 1) * burst.host_offset_percent
                        if active_destinations == 0:
                            active_destinations = 1

                start_delay_list.append(start_delay)
                active_destinations_list.append(active_destinations)

                if self._show_burst_timing:
                    print(" " * int((host_offset + flow_offset) * 8 / 100) + "xxxxxxxx")

        item = 1
        for i in range(self._num_flows):
            imports.append(
                {
                    "xpath": f"/traffic/trafficItem[{item}]/highLevelStream[{i + 1}]/frameSize",
                    "fixedSize": self._frame_size,
                }
            )
            if not hasattr(test_profile, "burst"):
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/highLevelStream[{i + 1}]/transmissionControl",
                        "frameCount": self._frame_count,
                    }
                )
            else:
                # interburst gap calculation - final step depends on number of flows from this port
                average_fps = max_fps * burst.total_rate_percent / active_destinations_list[i] / 100.0
                interburst_gap_ns = int(1000000000.0 * burst.packets_per_burst * (1 / average_fps - 1 / burst_fps))
                start_delay_ns = int(start_delay_list[i] / 100.0 * 1000000000.0 * burst.packets_per_burst / burst_fps)

                ETH_MIN_GAP = 12
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/highLevelStream[{i + 1}]/transmissionControl",
                        "type": "burstFixedDuration",
                        "burstPacketCount": burst.packets_per_burst,
                        "minGapBytes": ETH_MIN_GAP,
                        "enableInterBurstGap": True,
                        "interBurstGap": interburst_gap_ns,
                        "interBurstGapUnits": "nanoseconds",
                        "repeatBurst": self._frame_count / burst.packets_per_burst,
                        "startDelay": start_delay_ns,
                        "startDelayUnits": "nanoseconds",
                    }
                )

        #
        # PFC frame rate and frame count:  send PFC frames as a small fraction of the data frames.
        #   - Translate interval to frame rate, as fraction of max frame rate
        #   - frame rate fraction = PFC frame rate / max frame rate
        #   - frame rate fraction = PFC frame count * PFC frame length / (data frame count * data frame length)
        #
        # So PFC frame count = data frame count * (data frame length / PFC frame length) * frame rate fraction
        #
        # When calculating frame lengths, include 20 bytes of overhead per Ethernet frame.
        #
        # This calculation assumes that the effective bandwidth is 100%.  When the effective bandwidth is less
        # than that, the job completion time is longer, and more PFC frames need to be sent.
        #
        if hasattr(test_profile, "send_pfc"):
            pfc = test_profile.send_pfc
            ETH_OVERHEAD = 20
            max_frame_rate = self._link_speed * 1000000000 / ((64 + ETH_OVERHEAD) * 8)
            pfc_frame_rate = 1000000.0 / pfc.interval_us
            frame_rate_fraction = pfc_frame_rate / max_frame_rate

            pfc_frame_count = self._frame_count * self._num_flows / host_count * (self._frame_size + ETH_OVERHEAD) / (64 + ETH_OVERHEAD) * frame_rate_fraction
            effective_bandwidth = pfc.resume_count * 1.0 / (pfc.pause_count + pfc.resume_count)

            # Check whether burst option imposes a lower ceiling
            if hasattr(test_profile, "burst"):
                if test_profile.burst.total_rate_percent / 100.0 < effective_bandwidth:
                    effective_bandwidth = test_profile.burst.total_rate_percent / 100.0

            pfc_frame_count = pfc_frame_count / effective_bandwidth

            # save for checking against actual bandwidth
            self._pfc_effective_bandwidth = effective_bandwidth * 100

            item = 2
            for i in range(self._num_pfc_flows):
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/highLevelStream[{i + 1}]/frameRate",
                        "rate": 100.0 * frame_rate_fraction
                    }
                )
                imports.append(
                    {
                        "xpath": f"/traffic/trafficItem[{item}]/highLevelStream[{i + 1}]/transmissionControl",
                        "frameCount": int(pfc_frame_count)
                    }
                )

        self._import(imports)
        url = f"{self._ixnetwork.href}/globals/progressDialog"
        TIMEOUT = 60
        start = time.time()
        while True:
            time.sleep(2)
            response = self._ixnetwork._connection._read(url)
            if response["isOpen"] == False:
                break
            elif time.time() - start > TIMEOUT:
                raise TimeoutError(
                    f"Time to apply framesize/framecount exceeded {TIMEOUT}s"
                )

    def _start_hw_flows_v1(self):
        try:
            self._plugin_manager.hook.reset_counters()
        except:
            pass

        self._traffic.StartStatelessTraffic()
        time.sleep(5)
        while self._traffic.refresh().State != "stopped":
            time.sleep(0.5)

    def _start_hw_flows(self):
        self._logger.info('Start traffic')
        try:
            self._plugin_manager.hook.reset_counters()
        except:
            pass

        self._traffic.Start()
        time.sleep(5)
        while self._traffic.refresh().State != "stopped":
            time.sleep(1)

    def _get_hw_statistics_v1(self):
        '''
        This function gets traffic item stats (Flow Statistics) that
        was created prior to the new IxNetwork RoCEv2 implementation
        '''
        host_count = len(self._test_profile.hosts)
        flow_view = self._ixnetwork.Statistics.View.find(
            Caption="^Flow Statistics$"
        )

        # _num_flows = totalHosts x totalQueuePairs
        flow_view.Data.PageSize = self._num_flows

        while True:
            if flow_view.Data.refresh().IsReady is True:
                break
            time.sleep(0.5)
        flow_data = flow_view.Data
        port_view = self._ixnetwork.Statistics.View.find(
            Caption="^Port Statistics$"
        )
        port_data = port_view.Data
        self._get_flow_statistics(flow_data, port_data)
        self._get_port_statistics(port_data)

    def _get_hw_statistics(self):
        '''
        This function gets RoCEv2 implementation stats
        '''
        host_count = len(self._test_profile.hosts)

        flow_view = self._ixnetwork.Statistics.View.find(
            Caption="^RoCEv2 Flow Statistics$"
        )

        # _num_flows = totalHosts x totalQueuePairs
        if self._num_flows > 2048:
            flow_view.Data.PageSize = 2048
        else:
            flow_view.Data.PageSize = self._num_flows

        while True:
            if flow_view.Data.refresh().IsReady is True:
                break
            time.sleep(0.5)

        flow_data = flow_view.Data
        port_view = self._ixnetwork.Statistics.View.find(
            Caption="^Port Statistics$"
        )
        port_data = port_view.Data
        self._get_rocev2_flow_statistics(flow_data, port_data)
        self._get_port_statistics(port_data)

    def _get_port_statistics(self, port_data):
        self._logger.info('Getting Port Statistics')
        for row in port_data.PageValues:
            row_values = self._get_row_values(port_data, row)
            self._host_data.append(
                {
                    "size": self._size,
                    "host": row_values["Port Name"],
                    "frames_tx": row_values["Frames Tx."],
                    "frames_rx": row_values["Valid Frames Rx."],
                    "tx_packets_phy": self._get_value(
                        row_values, "Scheduled Frames Tx."
                    ),
                    "rx_packets_phy": self._get_value(
                        row_values, "Data Integrity Frames Rx."
                    ),
                    "tx_bytes_phy": int(
                        self._get_value(row_values, "Scheduled Frames Tx.")
                    )
                    * self._frame_size,
                    "rx_bytes_phy": int(
                        self._get_value(
                            row_values, "Data Integrity Frames Rx."
                        )
                    )
                    * self._frame_size,
                }
            )
            for i in range(8):
                self._host_data[-1][f"rx_prio{i}_pause"] = self._get_value(
                    row_values, f"Rx Pause Priority Group {i} Frames"
                )

    def _get_timestamp(self, ixia_timestamp: str):
        """Ixia hardware timestamp is in this format 00:00:00.000000000
        Return the Ixia hardware timestamp as total nanoseconds
        """
        pieces = ixia_timestamp.split(".")
        if len(pieces) != 2:
            return 0
        else:
            ns = float(pieces[-1])
            hrs, mins, secs = pieces[0].split(":")
            ns += float(secs) * 1e9
            ns += float(mins) * 6e10
            ns += float(hrs) * 2.777778e13
            return ns

    def _get_row_values(self, data, row):
        row_values = {}
        for i in range(0, len(data.ColumnCaptions)):
            row_values[data.ColumnCaptions[i]] = row[0][i]
        return row_values

    def _get_value(self, row_values, caption):
        if caption in row_values:
            if len(row_values[caption]):
                return row_values[caption]
            else:
                return 0
        else:
            if self._v1:
                self._logger.warn(f"{caption} not present in statistics")
            return 0

    def _get_rocev2_flow_statistics(self, flow_data, port_data):
        if self._includeRoceV2NgpfStack is False:
            return

        self._logger.info('Getting RoCEv2 flow statistics')
        startGetStatsTime = time.perf_counter()
        # keep refreshing flow statistics until meaningful data is retrieved
        # for all rows

        start = time.time()
        while time.time() - start < 60:
            time.sleep(2)
            flow_data.refresh()
            refresh = True
            for row in flow_data.PageValues:
                row_values = self._get_row_values(flow_data, row)
                if (
                    (
                        row_values["Data Frames Tx"] != ""
                        and float(row_values["Data Frames Tx"]) > 0
                    )
                    and (
                        row_values["Data Frames Rx"] != ""
                        and float(row_values["Data Frames Rx"]) > 0
                    )
                    and (
                        row_values["First TimeStamp"] != ""
                    )
                    and (
                        row_values["Last TimeStamp"] != ""
                    )
                ):
                    refresh = False

            if refresh is False:
                self._logger.info('All flow stats are ready')
                break

        #assert len(flow_data.PageValues) == self._num_flows
        fct_times = []
        jct_timestamps = []

        for row in flow_data.PageValues:
            row_values = self._get_row_values(flow_data, row)

            first_ts = self._get_timestamp(
                row_values["First TimeStamp"]
            )

            jct_timestamps.append(first_ts)
            last_ts = self._get_timestamp(row_values["Last TimeStamp"])
            jct_timestamps.append(last_ts)
            overhead = (self._frame_overhead) * int(row_values["Data Frames Rx"])
            fct_times.append((last_ts - first_ts) / 1000.0)

            self._application_data.append(
                {
                    "size": self._size,
                    "fct (us)": f"{(last_ts - first_ts) / 1000.0:.3f}",
                    "start (us)": f"{first_ts / 1000.0:.3f}",
                    "end (us)": f"{last_ts / 1000.0:.3f}",
                    #"payload_bytes_rx (B)": int(row_values["Rx Bytes"]) - overhead,
                    "host_from": row_values["Tx Port"],
                    "host_to": row_values["Rx Port"],
                }
            )

        fct_times.sort()
        min_fct = fct_times[0]
        max_fct = fct_times[-1]
        avg_fct = statistics.mean(fct_times)
        percentile50 = fct_times[int(0.50 * len(fct_times))]
        percentile95 = fct_times[int(0.95 * len(fct_times))]

        jct_timestamps.sort()
        jct = (jct_timestamps[-1] - jct_timestamps[0]) / 1000.0

        try:
            self._plugin_manager.hook.get_counters(job_completion_us = jct)
        except:
            pass

        # algbw ("algorithm bandwidth"): size S / time t
        # If jct = 198287.185u
        # 1.34217728  /  0.198287185 = 6.77 GB/s
        algbw = 0
        if jct > 0:
            algbw = (self._size / 1e9) / (jct / 1e6)

        # busbw ("bus bandwidth"): bandwidth B actually used by each host.
        # For all-to-all (each host sends S/n bytes to multiple destinations), t = S/n * num_flows / (n * B)
        # So B = (S / t) / n * num_flows / n
        # If there's multiple QPs for each source/destination pair, that increases num_flows;
        # divide by number_queue_pairs_per_flow
        host_count = len(self._test_profile.hosts)
        busbw = algbw / host_count * self._num_flows / host_count / self._total_queue_pairs_per_flow

        # comparison to ideal amount of bandwidth
        # ideal: mtu:2048  frameOverhead:78  busbw=11.842123402858045   linkSpeed:100.0   idealFactor:0.9597000937207123
        preamble = 8
        ideal_factor = self._infiniband_mtu / (
            preamble + self._frame_overhead + self._infiniband_mtu
        )

        # The ideal calculation isn't calculating the max bandwidth: it's calculating what busbw is as a fraction of the max bandwidth
        ideal = busbw * 8 / (int(self._link_speed) * ideal_factor) * 100

        # For display, adjust busbw to include skipped flows which would be sent over NVLink,
        # to match nccl-tests.
        busbw = busbw / (self._num_flows / self._total_queue_pairs_per_flow)
        busbw = busbw * (host_count - 1) * host_count

        pfc_frames = 0
        for row in port_data.PageValues:
            row_values = self._get_row_values(port_data, row)
            # only count ports which are in the test
            if not row_values["Port Name"] in self._test_profile.hosts:
                continue
            for i in range(8):
                pfc_frames += int(
                    row_values[f"Rx Pause Priority Group {i} Frames"]
                )

        # DoDrillDownByOption() is not supported
        # ecn_ce_count = 0
        # if self._ip_type == "ipv4":
        #     ecnOffsetBits = 126
        # else:
        #     ecnOffsetBits = 122
        # egress_tracking = self._ixnetwork.Statistics.View.find().DoDrillDownByOption(
        #     Arg2=1,
        #     Arg3=f"Custom: (2 bits at offset {ecnOffsetBits})"
        # )
        # user_def_stats = self._session_assistant.StatViewAssistant("User Defined Statistics")
        # for rowNumber, flowStat in enumerate(user_def_stats.Rows):
        #     # skip header
        #     if rowNumber == 0:
        #         continue
        #     if flowStat["Egress Tracking"] == "3":
        #         ecn_ce_count = flowStat["Rx Frames"]
        #         break

        summary = {
            "size (B)": self._size,
            "time (us)": f"{jct:.3f}",
            "algbw (GB/s)": f"{algbw:.2f}",
            "busbw (GB/s)": f"{busbw:.2f}",
            "ideal (%)": f"{ideal:.2f}",
            "pfc (rx)": pfc_frames,
            #"ecn-ce (rx)": ecn_ce_count,
            "min fct (us)": f"{min_fct:.3f}",
            "avg fct (us)": f"{avg_fct:.3f}",
            "max fct (us)": f"{max_fct:.3f}",
            "P50 fct (us)": f"{percentile50:.3f}",
            "P95 fct (us)": f"{percentile95:.3f}"
        }
        self._summary_data.append(summary)

        totalFramesTx = 0
        totalFramesRx = 0
        for row in flow_data.PageValues:
            row_values = self._get_row_values(flow_data, row)
            txPort = row_values['Tx Port']
            rxPort = row_values['Rx Port']
            txFrames = row_values['Data Frames Tx']
            rxFrames = row_values['Data Frames Rx']

            if self._prechecks and self._config.prechecks.pfc_incast:
                self._logger.info(f'TxPort:{txPort}   TxFrames:{txFrames}   RxPort:{rxPort}   RxFrames:{rxFrames}')
                for i in range(len(self._config.hosts)):
                    host = self._config.hosts[i]
                    if host.name == rxPort and host.incast == 'rx':
                        totalFramesRx += int(rxFrames)

                    if host.name == txPort and host.incast == 'tx':
                        totalFramesTx += int(txFrames)

        if self._prechecks and self._config.prechecks.pfc_incast:
            if totalFramesTx != totalFramesRx:
                errorMsg = f'PFC Incast: TxFrames:{totalFramesTx}  !=  RxFrames:{totalFramesRx}'
                self._precheckSetupTasks['PFC Incast'].update({'result': 'Failed',
                                                               'errorMsg': self.wrapText(errorMsg, width=300)})
            else:
                self._logger.info(f'PFC Incast: No drop packets')
                self._precheckSetupTasks['PFC Incast'].update({'result': 'Passed'})

        self.getStats = time.perf_counter() - startGetStatsTime

    def _get_flow_statistics(self, flow_data, port_data):
        # keep refreshing flow statistics until meaningful data is retrieved
        # for all rows
        start = time.time()
        while time.time() - start < 60:
            time.sleep(2)
            flow_data.refresh()
            refresh = False
            for row in flow_data.PageValues:
                row_values = self._get_row_values(flow_data, row)
                if (
                    (
                        row_values["Tx Frame Rate"] != ""
                        and float(row_values["Tx Frame Rate"]) > 0
                    )
                    or (
                        row_values["Rx Frame Rate"] != ""
                        and float(row_values["Rx Frame Rate"]) > 0
                    )
                    or row_values["Loss %"] == ""
                    or row_values["First TimeStamp"] == ""
                ):
                    refresh = True
            if refresh is False:
                break

        assert len(flow_data.PageValues) == self._num_flows
        fct_times = []
        jct_timestamps = []
        for row in flow_data.PageValues:
            row_values = self._get_row_values(flow_data, row)
            if float(row_values["Loss %"]) > 0:
                self._logger.warn(
                    f'{row_values["Traffic Item"]} has loss of {row_values["Loss %"]}'
                )
            first_ts = self._get_timestamp(
                row_values["First TimeStamp"]
            ) - float(
                self._get_value(row_values, "Store-Forward Avg Latency (ns)")
            )
            jct_timestamps.append(first_ts)
            last_ts = self._get_timestamp(row_values["Last TimeStamp"])
            jct_timestamps.append(last_ts)
            overhead = (self._frame_overhead) * int(row_values["Rx Frames"])
            fct_times.append((last_ts - first_ts) / 1000.0)
            self._application_data.append(
                {
                    "size": self._size,
                    "fct (us)": f"{(last_ts - first_ts) / 1000.0:.3f}",
                    "start (us)": f"{first_ts / 1000.0:.3f}",
                    "end (us)": f"{last_ts / 1000.0:.3f}",
                    "payload_bytes_rx (B)": int(row_values["Rx Bytes"])
                    - overhead,
                    "host_from": row_values["Tx Port"],
                    "host_to": row_values["Rx Port"],
                }
            )
        fct_times.sort()
        min_fct = fct_times[0]
        max_fct = fct_times[-1]
        avg_fct = statistics.mean(fct_times)
        percentile50 = fct_times[int(0.50 * len(fct_times))]
        percentile95 = fct_times[int(0.95 * len(fct_times))]

        jct_timestamps.sort()
        jct = (jct_timestamps[-1] - jct_timestamps[0]) / 1000.0

        try:
            self._plugin_manager.hook.get_counters(job_completion_us = jct)
        except:
            pass

        # algbw ("algorithm bandwidth"): size S / time t
        algbw = 0
        if jct > 0:
            algbw = (self._size / 1e9) / (jct / 1e6)

        # busbw ("bus bandwidth"): bandwidth B actually used by each host.
        # For all-to-all (each host sends S/n bytes to multiple destinations), t = S/n * num_flows / (n * B)
        # So B = (S / t) / n * num_flows / n
        host_count = len(self._test_profile.hosts)
        busbw = (algbw / host_count) * (self._num_flows / host_count)

        # comparison to ideal amount of bandwidth
        preamble = 8
        ideal_factor = self._infiniband_mtu / (
            preamble + self._frame_overhead + self._infiniband_mtu
        )
        ideal = busbw * 8 / (self._link_speed * ideal_factor) * 100

        # comparison to predicted effective bandwidth used to calculate PFC frame count
        if hasattr(self, "_pfc_effective_bandwidth"):
            if ideal < self._pfc_effective_bandwidth - 1:
                self._logger.warn(
                    f"Predicted bandwidth used to calculate PFC frame count was {self._pfc_effective_bandwidth:.2f}, actual {ideal:.2f}"
                )

        # For display, adjust busbw to include skipped flows which would be sent over NVLink,
        # to match nccl-tests.
        busbw = busbw / self._num_flows
        busbw = busbw * (host_count - 1) * host_count

        pfc_frames = 0
        for row in port_data.PageValues:
            row_values = self._get_row_values(port_data, row)
            # only count ports which are in the test
            if not row_values["Port Name"] in self._test_profile.hosts:
                continue
            for i in range(8):
                pfc_frames += int(
                    row_values[f"Rx Pause Priority Group {i} Frames"]
                )

        ecn_ce_count = 0
        if self._ip_type == "ipv4":
            ecnOffsetBits = 126
        else:
            ecnOffsetBits = 122
        egress_tracking = self._ixnetwork.Statistics.View.find().DoDrillDownByOption(
            Arg2=1,
            Arg3=f"Custom: (2 bits at offset {ecnOffsetBits})"
        )
        user_def_stats = self._session_assistant.StatViewAssistant("User Defined Statistics")
        for rowNumber, flowStat in enumerate(user_def_stats.Rows):
            # skip header
            if rowNumber == 0:
                continue
            if flowStat["Egress Tracking"] == "3":
                ecn_ce_count = flowStat["Rx Frames"]
                break

        summary = {
            "size (B)": self._size,
            "time (us)": f"{jct:.3f}",
            "algbw (GB/s)": f"{algbw:.2f}",
            "busbw (GB/s)": f"{busbw:.2f}",
            "ideal (%)": f"{ideal:.2f}",
            "pfc (rx)": pfc_frames,
            "ecn-ce (rx)": ecn_ce_count,
            "min fct (us)": f"{min_fct:.3f}",
            "avg fct (us)": f"{avg_fct:.3f}",
            "P50 fct (us)": f"{percentile50:.3f}",
            "P95 fct (us)": f"{percentile95:.3f}",
            "max fct (us)": f"{max_fct:.3f}",
        }
        self._summary_data.append(summary)

    def _getPFCStatistics(self, expectedMinimumPFC=10):
        totalFramesRx = 0
        totalFramesTx = 0
        result = 'passed'
        errorMsg = ''

        self._logger.info('Verifying PFC stats')
        for stats in self._host_data:
            hostName = stats['host']
            framesTx = stats['frames_tx']
            framesRx = stats['frames_rx']
            framesPfc = stats['rx_prio0_pause']

            for i in range(len(self._config.hosts)):
                host = self._config.hosts[i]
                if host.name == hostName and host.incast == 'tx':
                    self._logger.info(f'Port:{hostName}  TxFrames:{framesTx}  PFC_Rx:{framesPfc}')
                    if int(framesPfc) < expectedMinimumPFC:
                        errorMsg += f'Incast PFC: {host.name} Tx port recieved less than minimum PFC frames:{expectedMinimumPFC}. Received:{framesPfc}.\n'
                        self._logger.error(errorMsg)
                        result = 'failed'

        if result == 'failed':
            self._precheckSetupTasks['PFC Incast'].update({'result': 'Failed',
                                                           'errorMsg': self.wrapText(errorMsg, width=300)})

#
# Shut down cleanly on Ctrl-C.
#

def signal_handler(sig, frame):
    print('Received Ctrl-C, shutting down')
    # if experiment:
    #     experiment.cleanup()
    sys.exit(0)


def install_signal_handler():
    signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    install_signal_handler()
    if len(sys.argv) == 1:
        KCCB(optional_args=["--help"])
    else:
        experiment = KCCB()
        experiment.run()

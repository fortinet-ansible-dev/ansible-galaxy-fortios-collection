#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_wireless_controller_wtp_profile
short_description: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and wtp_profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

requirements:
    - ansible>=2.9.0
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    wireless_controller_wtp_profile:
        description:
            - Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
        default: null
        type: dict
        suboptions:
            allowaccess:
                description:
                    - Control management access to the managed WTP, FortiAP, or AP. Separate entries with a space.
                type: list
                choices:
                    - telnet
                    - http
                    - https
                    - ssh
                    - snmp
            ap_country:
                description:
                    - Country in which this WTP, FortiAP or AP will operate .
                type: str
                choices:
                    - NA
                    - AL
                    - DZ
                    - AO
                    - AR
                    - AM
                    - AU
                    - AT
                    - AZ
                    - BH
                    - BD
                    - BB
                    - BY
                    - BE
                    - BZ
                    - BO
                    - BA
                    - BR
                    - BN
                    - BG
                    - KH
                    - CL
                    - CN
                    - CO
                    - CR
                    - HR
                    - CY
                    - CZ
                    - DK
                    - DO
                    - EC
                    - EG
                    - SV
                    - EE
                    - FI
                    - FR
                    - GE
                    - DE
                    - GR
                    - GL
                    - GD
                    - GU
                    - GT
                    - HT
                    - HN
                    - HK
                    - HU
                    - IS
                    - IN
                    - ID
                    - IR
                    - IE
                    - IL
                    - IT
                    - JM
                    - JO
                    - KZ
                    - KE
                    - KP
                    - KR
                    - KW
                    - LV
                    - LB
                    - LI
                    - LT
                    - LU
                    - MO
                    - MK
                    - MY
                    - MT
                    - MX
                    - MC
                    - MA
                    - MZ
                    - MM
                    - NP
                    - NL
                    - AN
                    - AW
                    - NZ
                    - NO
                    - OM
                    - PK
                    - PA
                    - PG
                    - PY
                    - PE
                    - PH
                    - PL
                    - PT
                    - PR
                    - QA
                    - RO
                    - RU
                    - RW
                    - SA
                    - RS
                    - ME
                    - SG
                    - SK
                    - SI
                    - ZA
                    - ES
                    - LK
                    - SE
                    - SD
                    - CH
                    - SY
                    - TW
                    - TZ
                    - TH
                    - TT
                    - TN
                    - TR
                    - AE
                    - UA
                    - GB
                    - US
                    - PS
                    - UY
                    - UZ
                    - VE
                    - VN
                    - YE
                    - ZB
                    - ZW
                    - JP
                    - CA
                    - CF
                    - BS
                    - BF
                    - KY
                    - CX
                    - GH
                    - GY
                    - CI
                    - MW
                    - MV
                    - FM
                    - KN
                    - LC
                    - VC
                    - SN
                    - TM
                    - TC
                    - UG
                    - VU
                    - AF
                    - AS
                    - BJ
                    - BM
                    - BT
                    - BW
                    - CM
                    - TD
                    - CG
                    - CD
                    - DM
                    - ET
                    - GF
                    - PF
                    - FO
                    - FJ
                    - GI
                    - GP
                    - IQ
                    - IM
                    - LA
                    - LS
                    - LY
                    - MG
                    - ML
                    - MH
                    - MQ
                    - MR
                    - MU
                    - YT
                    - MD
                    - NI
                    - NE
                    - MP
                    - PW
                    - RE
                    - BL
                    - MF
                    - PM
                    - SL
                    - SR
                    - TG
                    - VI
                    - WF
                    - ZM
            ap_handoff:
                description:
                    - Enable/disable AP handoff of clients to other APs .
                type: str
                choices:
                    - enable
                    - disable
            apcfg_profile:
                description:
                    - AP local configuration profile name. Source wireless-controller.apcfg-profile.name.
                type: str
            ble_profile:
                description:
                    - Bluetooth Low Energy profile name. Source wireless-controller.ble-profile.name.
                type: str
            comment:
                description:
                    - Comment.
                type: str
            control_message_offload:
                description:
                    - Enable/disable CAPWAP control message data channel offload.
                type: list
                choices:
                    - ebp-frame
                    - aeroscout-tag
                    - ap-list
                    - sta-list
                    - sta-cap-list
                    - stats
                    - aeroscout-mu
                    - sta-health
                    - spectral-analysis
            deny_mac_list:
                description:
                    - List of MAC addresses that are denied access to this WTP, FortiAP, or AP.
                type: list
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    mac:
                        description:
                            - A WiFi device with this MAC address is denied access to this WTP, FortiAP or AP.
                        type: str
            dtls_in_kernel:
                description:
                    - Enable/disable data channel DTLS in kernel.
                type: str
                choices:
                    - enable
                    - disable
            dtls_policy:
                description:
                    - WTP data channel DTLS policy .
                type: list
                choices:
                    - clear-text
                    - dtls-enabled
                    - ipsec-vpn
            energy_efficient_ethernet:
                description:
                    - Enable/disable use of energy efficient Ethernet on WTP.
                type: str
                choices:
                    - enable
                    - disable
            ext_info_enable:
                description:
                    - Enable/disable station/VAP/radio extension information.
                type: str
                choices:
                    - enable
                    - disable
            frequency_handoff:
                description:
                    - Enable/disable frequency handoff of clients to other channels .
                type: str
                choices:
                    - enable
                    - disable
            handoff_roaming:
                description:
                    - Enable/disable client load balancing during roaming to avoid roaming delay .
                type: str
                choices:
                    - enable
                    - disable
            handoff_rssi:
                description:
                    - Minimum received signal strength indicator (RSSI) value for handoff (20 - 30).
                type: int
            handoff_sta_thresh:
                description:
                    - Threshold value for AP handoff.
                type: int
            ip_fragment_preventing:
                description:
                    - Select how to prevent IP fragmentation for CAPWAP tunneled control and data packets .
                type: list
                choices:
                    - tcp-mss-adjust
                    - icmp-unreachable
            lan:
                description:
                    - WTP LAN port mapping.
                type: dict
                suboptions:
                    port_esl_mode:
                        description:
                            - ESL port mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port_esl_ssid:
                        description:
                            - Bridge ESL port to SSID. Source system.interface.name.
                        type: str
                    port_mode:
                        description:
                            - LAN port mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port_ssid:
                        description:
                            - Bridge LAN port to SSID. Source wireless-controller.vap.name.
                        type: str
                    port1_mode:
                        description:
                            - LAN port 1 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port1_ssid:
                        description:
                            - Bridge LAN port 1 to SSID. Source wireless-controller.vap.name.
                        type: str
                    port2_mode:
                        description:
                            - LAN port 2 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port2_ssid:
                        description:
                            - Bridge LAN port 2 to SSID. Source wireless-controller.vap.name.
                        type: str
                    port3_mode:
                        description:
                            - LAN port 3 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port3_ssid:
                        description:
                            - Bridge LAN port 3 to SSID. Source wireless-controller.vap.name.
                        type: str
                    port4_mode:
                        description:
                            - LAN port 4 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port4_ssid:
                        description:
                            - Bridge LAN port 4 to SSID. Source wireless-controller.vap.name.
                        type: str
                    port5_mode:
                        description:
                            - LAN port 5 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port5_ssid:
                        description:
                            - Bridge LAN port 5 to SSID. Source wireless-controller.vap.name.
                        type: str
                    port6_mode:
                        description:
                            - LAN port 6 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port6_ssid:
                        description:
                            - Bridge LAN port 6 to SSID. Source wireless-controller.vap.name.
                        type: str
                    port7_mode:
                        description:
                            - LAN port 7 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port7_ssid:
                        description:
                            - Bridge LAN port 7 to SSID. Source wireless-controller.vap.name.
                        type: str
                    port8_mode:
                        description:
                            - LAN port 8 mode.
                        type: str
                        choices:
                            - offline
                            - nat-to-wan
                            - bridge-to-wan
                            - bridge-to-ssid
                    port8_ssid:
                        description:
                            - Bridge LAN port 8 to SSID. Source wireless-controller.vap.name.
                        type: str
            lbs:
                description:
                    - Set various location based service (LBS) options.
                type: dict
                suboptions:
                    aeroscout:
                        description:
                            - Enable/disable AeroScout Real Time Location Service (RTLS) support .
                        type: str
                        choices:
                            - enable
                            - disable
                    aeroscout_ap_mac:
                        description:
                            - Use BSSID or board MAC address as AP MAC address in AeroScout AP messages .
                        type: str
                        choices:
                            - bssid
                            - board-mac
                    aeroscout_mmu_report:
                        description:
                            - Enable/disable compounded AeroScout tag and MU report .
                        type: str
                        choices:
                            - enable
                            - disable
                    aeroscout_mu:
                        description:
                            - Enable/disable AeroScout Mobile Unit (MU) support .
                        type: str
                        choices:
                            - enable
                            - disable
                    aeroscout_mu_factor:
                        description:
                            - AeroScout MU mode dilution factor .
                        type: int
                    aeroscout_mu_timeout:
                        description:
                            - AeroScout MU mode timeout (0 - 65535 sec).
                        type: int
                    aeroscout_server_ip:
                        description:
                            - IP address of AeroScout server.
                        type: str
                    aeroscout_server_port:
                        description:
                            - AeroScout server UDP listening port.
                        type: int
                    ekahau_blink_mode:
                        description:
                            - Enable/disable Ekahau blink mode (now known as AiRISTA Flow) to track and locate WiFi tags .
                        type: str
                        choices:
                            - enable
                            - disable
                    ekahau_tag:
                        description:
                            - WiFi frame MAC address or WiFi Tag.
                        type: str
                    erc_server_ip:
                        description:
                            - IP address of Ekahau RTLS Controller (ERC).
                        type: str
                    erc_server_port:
                        description:
                            - Ekahau RTLS Controller (ERC) UDP listening port.
                        type: int
                    fortipresence:
                        description:
                            - Enable/disable FortiPresence to monitor the location and activity of WiFi clients even if they don"t connect to this WiFi
                               network .
                        type: str
                        choices:
                            - foreign
                            - both
                            - disable
                    fortipresence_ble:
                        description:
                            - Enable/disable FortiPresence finding and reporting BLE devices.
                        type: str
                        choices:
                            - enable
                            - disable
                    fortipresence_frequency:
                        description:
                            - FortiPresence report transmit frequency (5 - 65535 sec).
                        type: int
                    fortipresence_port:
                        description:
                            - FortiPresence server UDP listening port .
                        type: int
                    fortipresence_project:
                        description:
                            - FortiPresence project name (max. 16 characters).
                        type: str
                    fortipresence_rogue:
                        description:
                            - Enable/disable FortiPresence finding and reporting rogue APs.
                        type: str
                        choices:
                            - enable
                            - disable
                    fortipresence_secret:
                        description:
                            - FortiPresence secret password (max. 16 characters).
                        type: str
                    fortipresence_server:
                        description:
                            - FortiPresence server IP address.
                        type: str
                    fortipresence_unassoc:
                        description:
                            - Enable/disable FortiPresence finding and reporting unassociated stations.
                        type: str
                        choices:
                            - enable
                            - disable
                    station_locate:
                        description:
                            - Enable/disable client station locating services for all clients, whether associated or not .
                        type: str
                        choices:
                            - enable
                            - disable
            led_schedules:
                description:
                    - Recurring firewall schedules for illuminating LEDs on the FortiAP. If led-state is enabled, LEDs will be visible when at least one of
                       the schedules is valid. Separate multiple schedule names with a space.
                type: list
                suboptions:
                    name:
                        description:
                            - LED schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name.
                        required: true
                        type: str
            led_state:
                description:
                    - Enable/disable use of LEDs on WTP .
                type: str
                choices:
                    - enable
                    - disable
            lldp:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) for the WTP, FortiAP, or AP .
                type: str
                choices:
                    - enable
                    - disable
            login_passwd:
                description:
                    - Set the managed WTP, FortiAP, or AP"s administrator password.
                type: str
            login_passwd_change:
                description:
                    - Change or reset the administrator password of a managed WTP, FortiAP or AP (yes, default, or no).
                type: str
                choices:
                    - yes
                    - default
                    - no
            max_clients:
                description:
                    - Maximum number of stations (STAs) supported by the WTP .
                type: int
            name:
                description:
                    - WTP (or FortiAP or AP) profile name.
                required: true
                type: str
            platform:
                description:
                    - WTP, FortiAP, or AP platform.
                type: dict
                suboptions:
                    ddscan:
                        description:
                            - Enable/disable use of one radio for dedicated dual-band scanning to detect RF characterization and wireless threat management.
                        type: str
                        choices:
                            - enable
                            - disable
                    mode:
                        description:
                            - Configure operation mode of 5G radios .
                        type: str
                        choices:
                            - single-5G
                            - dual-5G
                    type:
                        description:
                            - WTP, FortiAP or AP platform type. There are built-in WTP profiles for all supported FortiAP models. You can select a built-in
                               profile and customize it or create a new profile.
                        type: str
                        choices:
                            - AP-11N
                            - 220B
                            - 210B
                            - 222B
                            - 112B
                            - 320B
                            - 11C
                            - 14C
                            - 223B
                            - 28C
                            - 320C
                            - 221C
                            - 25D
                            - 222C
                            - 224D
                            - 214B
                            - 21D
                            - 24D
                            - 112D
                            - 223C
                            - 321C
                            - C220C
                            - C225C
                            - C23JD
                            - C24JE
                            - S321C
                            - S322C
                            - S323C
                            - S311C
                            - S313C
                            - S321CR
                            - S322CR
                            - S323CR
                            - S421E
                            - S422E
                            - S423E
                            - 421E
                            - 423E
                            - 221E
                            - 222E
                            - 223E
                            - 224E
                            - S221E
                            - S223E
                            - U421E
                            - U422EV
                            - U423E
                            - U221EV
                            - U223EV
                            - U24JEV
                            - U321EV
                            - U323EV
                            - 231E
                            - 321E
                            - 431F
                            - 432F
                            - 433F
                            - 231F
                            - 234F
                            - 23JF
                            - U431F
                            - U433F
                            - 831F
                            - U231F
                            - U234F
                            - U432F
            poe_mode:
                description:
                    - Set the WTP, FortiAP, or AP"s PoE mode.
                type: str
                choices:
                    - auto
                    - 8023af
                    - 8023at
                    - power-adapter
                    - full
                    - high
                    - low
            radio_1:
                description:
                    - Configuration options for radio 1.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - enable
                            - disable
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_high:
                        description:
                            - Automatic transmit power high limit in dBm (the actual range of transmit power depends on the AP platform type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_low:
                        description:
                            - Automatic transmission power low limit in dBm (the actual range of transmit power depends on the AP platform type).
                        type: int
                    auto_power_target:
                        description:
                            - The target of automatic transmit power adjustment in dBm. (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 1 operates on.
                        type: str
                        choices:
                            - 802.11a
                            - 802.11b
                            - 802.11g
                            - 802.11n
                            - 802.11n-5G
                            - 802.11ac
                            - 802.11n,g-only
                            - 802.11g-only
                            - 802.11n-only
                            - 802.11n-5G-only
                            - 802.11ac,n-only
                            - 802.11ac-only
                            - 802.11ax-5G
                            - 802.11ax
                            - 802.11ax,ac-only
                            - 802.11ax,ac,n-only
                            - 802.11ax-5G-only
                            - 802.11ax,n-only
                            - 802.11ax,n,g-only
                            - 802.11ax-only
                            - 802.11ac-2G
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - 5g-full
                            - 5g-high
                            - 5g-low
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - enable
                            - disable
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in msec (the actual range of beacon interval depends on the AP platform type).
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, 0 means disable. ).
                        type: int
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - enable
                            - disable
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - 80MHz
                            - 40MHz
                            - 20MHz
                            - 160MHz
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - enable
                            - disable
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - enable
                            - disable
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - enable
                            - disable
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - disable
                            - enable
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - low
                            - medium
                            - high
                    dtim:
                        description:
                            - DTIM interval. The frequency to transmit Delivery Traffic Indication Message (or Map) (DTIM) messages (1 - 255). Set higher to
                               save client battery life.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - enable
                            - disable
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - udp
                            - tcp
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mode:
                        description:
                            - Mode of radio 1. Radio 1 can be disabled, configured as an access point, a rogue AP monitor, or a sniffer.
                        type: str
                        choices:
                            - disabled
                            - ap
                            - monitor
                            - sniffer
                            - sam
                    power_level:
                        description:
                            - Radio power level as a percentage of the maximum transmit power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - dBm
                            - percentage
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: str
                        choices:
                            - tim
                            - ac-vo
                            - no-obss-scan
                            - no-11b-rate
                            - client-rate-follow
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - rtscts
                            - ctsonly
                            - disable
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - enable
                            - disable
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - open
                            - wpa-personal
                            - wpa-enterprise
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - ping
                            - iperf
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - enable
                            - disable
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - enable
                            - disable
                            - scan-only
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: str
                        choices:
                            - disable
                            - power-save
                            - aggr-limit
                            - retry-limit
                            - send-bar
                    vap_all:
                        description:
                            - Enable/disable the automatic inheritance of all Virtual Access Points (VAPs) .
                        type: str
                        choices:
                            - enable
                            - disable
                            - tunnel
                            - bridge
                            - manual
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name wireless-controller.vap.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - enable
                            - disable
            radio_2:
                description:
                    - Configuration options for radio 2.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - enable
                            - disable
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_high:
                        description:
                            - Automatic transmit power high limit in dBm (the actual range of transmit power depends on the AP platform type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_low:
                        description:
                            - Automatic transmission power low limit in dBm (the actual range of transmit power depends on the AP platform type).
                        type: int
                    auto_power_target:
                        description:
                            - The target of automatic transmit power adjustment in dBm. (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 2 operates on.
                        type: str
                        choices:
                            - 802.11a
                            - 802.11b
                            - 802.11g
                            - 802.11n
                            - 802.11n-5G
                            - 802.11ac
                            - 802.11n,g-only
                            - 802.11g-only
                            - 802.11n-only
                            - 802.11n-5G-only
                            - 802.11ac,n-only
                            - 802.11ac-only
                            - 802.11ax-5G
                            - 802.11ax
                            - 802.11ax,ac-only
                            - 802.11ax,ac,n-only
                            - 802.11ax-5G-only
                            - 802.11ax,n-only
                            - 802.11ax,n,g-only
                            - 802.11ax-only
                            - 802.11ac-2G
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - 5g-full
                            - 5g-high
                            - 5g-low
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - enable
                            - disable
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in msec (the actual range of beacon interval depends on the AP platform type).
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, 0 means disable. ).
                        type: int
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - enable
                            - disable
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - 80MHz
                            - 40MHz
                            - 20MHz
                            - 160MHz
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - enable
                            - disable
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - enable
                            - disable
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - enable
                            - disable
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - disable
                            - enable
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - low
                            - medium
                            - high
                    dtim:
                        description:
                            - DTIM interval. The frequency to transmit Delivery Traffic Indication Message (or Map) (DTIM) messages (1 - 255). Set higher to
                               save client battery life.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - enable
                            - disable
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - udp
                            - tcp
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mode:
                        description:
                            - Mode of radio 2. Radio 2 can be disabled, configured as an access point, a rogue AP monitor, or a sniffer.
                        type: str
                        choices:
                            - disabled
                            - ap
                            - monitor
                            - sniffer
                            - sam
                    power_level:
                        description:
                            - Radio power level as a percentage of the maximum transmit power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - dBm
                            - percentage
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: str
                        choices:
                            - tim
                            - ac-vo
                            - no-obss-scan
                            - no-11b-rate
                            - client-rate-follow
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - rtscts
                            - ctsonly
                            - disable
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - enable
                            - disable
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - open
                            - wpa-personal
                            - wpa-enterprise
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - ping
                            - iperf
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - enable
                            - disable
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - enable
                            - disable
                            - scan-only
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: str
                        choices:
                            - disable
                            - power-save
                            - aggr-limit
                            - retry-limit
                            - send-bar
                    vap_all:
                        description:
                            - Enable/disable the automatic inheritance of all Virtual Access Points (VAPs) .
                        type: str
                        choices:
                            - enable
                            - disable
                            - tunnel
                            - bridge
                            - manual
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name wireless-controller.vap.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - enable
                            - disable
            radio_3:
                description:
                    - Configuration options for radio 3.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - enable
                            - disable
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_high:
                        description:
                            - The upper bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_low:
                        description:
                            - The lower bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_target:
                        description:
                            - The target of automatic transmit power adjustment in dBm. (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 3 operates on.
                        type: str
                        choices:
                            - 802.11a
                            - 802.11b
                            - 802.11g
                            - 802.11n
                            - 802.11n-5G
                            - 802.11ac
                            - 802.11ax-5G
                            - 802.11ax
                            - 802.11n,g-only
                            - 802.11g-only
                            - 802.11n-only
                            - 802.11n-5G-only
                            - 802.11ac,n-only
                            - 802.11ac-only
                            - 802.11ax,ac-only
                            - 802.11ax,ac,n-only
                            - 802.11ax-5G-only
                            - 802.11ax,n-only
                            - 802.11ax,n,g-only
                            - 802.11ax-only
                            - 802.11ac-2G
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - 5g-full
                            - 5g-high
                            - 5g-low
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - enable
                            - disable
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in msec (the actual range of beacon interval depends on the AP platform type).
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, 0 means disable. ).
                        type: int
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - enable
                            - disable
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 160,80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - 160MHz
                            - 80MHz
                            - 40MHz
                            - 20MHz
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - enable
                            - disable
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - enable
                            - disable
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - enable
                            - disable
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - disable
                            - enable
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - low
                            - medium
                            - high
                    dtim:
                        description:
                            - Delivery Traffic Indication Map (DTIM) period (1 - 255). Set higher to save battery life of WiFi client in power-save mode.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - enable
                            - disable
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - udp
                            - tcp
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mode:
                        description:
                            - Mode of radio 3. Radio 3 can be disabled, configured as an access point, a rogue AP monitor, or a sniffer.
                        type: str
                        choices:
                            - disabled
                            - ap
                            - monitor
                            - sniffer
                            - sam
                    power_level:
                        description:
                            - Radio power level as a percentage of the maximum transmit power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - dBm
                            - percentage
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: str
                        choices:
                            - tim
                            - ac-vo
                            - no-obss-scan
                            - no-11b-rate
                            - client-rate-follow
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - rtscts
                            - ctsonly
                            - disable
                    radio_id:
                        description:
                            - radio-id
                        type: int
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - enable
                            - disable
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - open
                            - wpa-personal
                            - wpa-enterprise
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - ping
                            - iperf
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - enable
                            - disable
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - enable
                            - disable
                            - scan-only
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: str
                        choices:
                            - disable
                            - power-save
                            - aggr-limit
                            - retry-limit
                            - send-bar
                    vap_all:
                        description:
                            - Enable/disable the automatic inheritance of all Virtual Access Points (VAPs) .
                        type: str
                        choices:
                            - enable
                            - disable
                            - tunnel
                            - bridge
                            - manual
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name system.interface.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - enable
                            - disable
            radio_4:
                description:
                    - Configuration options for radio 4.
                type: dict
                suboptions:
                    airtime_fairness:
                        description:
                            - Enable/disable airtime fairness .
                        type: str
                        choices:
                            - enable
                            - disable
                    amsdu:
                        description:
                            - Enable/disable 802.11n AMSDU support. AMSDU can improve performance if supported by your WiFi clients .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_handoff:
                        description:
                            - Enable/disable AP handoff of clients to other APs .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_addr:
                        description:
                            - MAC address to monitor.
                        type: str
                    ap_sniffer_bufsize:
                        description:
                            - Sniffer buffer size (1 - 32 MB).
                        type: int
                    ap_sniffer_chan:
                        description:
                            - Channel on which to operate the sniffer .
                        type: int
                    ap_sniffer_ctl:
                        description:
                            - Enable/disable sniffer on WiFi control frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_data:
                        description:
                            - Enable/disable sniffer on WiFi data frame .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_beacon:
                        description:
                            - Enable/disable sniffer on WiFi management Beacon frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_other:
                        description:
                            - Enable/disable sniffer on WiFi management other frames  .
                        type: str
                        choices:
                            - enable
                            - disable
                    ap_sniffer_mgmt_probe:
                        description:
                            - Enable/disable sniffer on WiFi management probe frames .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_high:
                        description:
                            - The upper bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_level:
                        description:
                            - Enable/disable automatic power-level adjustment to prevent co-channel interference .
                        type: str
                        choices:
                            - enable
                            - disable
                    auto_power_low:
                        description:
                            - The lower bound of automatic transmit power adjustment in dBm (the actual range of transmit power depends on the AP platform
                               type).
                        type: int
                    auto_power_target:
                        description:
                            - The target of automatic transmit power adjustment in dBm. (-95 to -20).
                        type: str
                    band:
                        description:
                            - WiFi band that Radio 3 operates on.
                        type: str
                        choices:
                            - 802.11a
                            - 802.11b
                            - 802.11g
                            - 802.11n
                            - 802.11n-5G
                            - 802.11ac
                            - 802.11ax-5G
                            - 802.11ax
                            - 802.11n,g-only
                            - 802.11g-only
                            - 802.11n-only
                            - 802.11n-5G-only
                            - 802.11ac,n-only
                            - 802.11ac-only
                            - 802.11ax,ac-only
                            - 802.11ax,ac,n-only
                            - 802.11ax-5G-only
                            - 802.11ax,n-only
                            - 802.11ax,n,g-only
                            - 802.11ax-only
                            - 802.11ac-2G
                    band_5g_type:
                        description:
                            - WiFi 5G band type.
                        type: str
                        choices:
                            - 5g-full
                            - 5g-high
                            - 5g-low
                    bandwidth_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) bandwidth admission control to optimize WiFi bandwidth use. A request to join the wireless
                               network is only allowed if the access point has enough bandwidth to support it.
                        type: str
                        choices:
                            - enable
                            - disable
                    bandwidth_capacity:
                        description:
                            - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                        type: int
                    beacon_interval:
                        description:
                            - Beacon interval. The time between beacon frames in msec (the actual range of beacon interval depends on the AP platform type).
                        type: int
                    bss_color:
                        description:
                            - BSS color value for this 11ax radio (0 - 63, 0 means disable. ).
                        type: int
                    call_admission_control:
                        description:
                            - Enable/disable WiFi multimedia (WMM) call admission control to optimize WiFi bandwidth use for VoIP calls. New VoIP calls are
                               only accepted if there is enough bandwidth available to support them.
                        type: str
                        choices:
                            - enable
                            - disable
                    call_capacity:
                        description:
                            - Maximum number of Voice over WLAN (VoWLAN) phones supported by the radio (0 - 60).
                        type: int
                    channel:
                        description:
                            - Selected list of wireless radio channels.
                        type: list
                        suboptions:
                            chan:
                                description:
                                    - Channel number.
                                required: true
                                type: str
                    channel_bonding:
                        description:
                            - 'Channel bandwidth: 160,80, 40, or 20MHz. Channels may use both 20 and 40 by enabling coexistence.'
                        type: str
                        choices:
                            - 160MHz
                            - 80MHz
                            - 40MHz
                            - 20MHz
                    channel_utilization:
                        description:
                            - Enable/disable measuring channel utilization.
                        type: str
                        choices:
                            - enable
                            - disable
                    coexistence:
                        description:
                            - Enable/disable allowing both HT20 and HT40 on the same radio .
                        type: str
                        choices:
                            - enable
                            - disable
                    darrp:
                        description:
                            - Enable/disable Distributed Automatic Radio Resource Provisioning (DARRP) to make sure the radio is always using the most optimal
                               channel .
                        type: str
                        choices:
                            - enable
                            - disable
                    drma:
                        description:
                            - Enable/disable dynamic radio mode assignment (DRMA) .
                        type: str
                        choices:
                            - disable
                            - enable
                    drma_sensitivity:
                        description:
                            - Network Coverage Factor (NCF) percentage required to consider a radio as redundant .
                        type: str
                        choices:
                            - low
                            - medium
                            - high
                    dtim:
                        description:
                            - Delivery Traffic Indication Map (DTIM) period (1 - 255). Set higher to save battery life of WiFi client in power-save mode.
                        type: int
                    frag_threshold:
                        description:
                            - Maximum packet size that can be sent without fragmentation (800 - 2346 bytes).
                        type: int
                    frequency_handoff:
                        description:
                            - Enable/disable frequency handoff of clients to other channels .
                        type: str
                        choices:
                            - enable
                            - disable
                    iperf_protocol:
                        description:
                            - Iperf test protocol .
                        type: str
                        choices:
                            - udp
                            - tcp
                    iperf_server_port:
                        description:
                            - Iperf service port number.
                        type: int
                    max_clients:
                        description:
                            - Maximum number of stations (STAs) or WiFi clients supported by the radio. Range depends on the hardware.
                        type: int
                    max_distance:
                        description:
                            - Maximum expected distance between the AP and clients (0 - 54000 m).
                        type: int
                    mode:
                        description:
                            - Mode of radio 3. Radio 3 can be disabled, configured as an access point, a rogue AP monitor, or a sniffer.
                        type: str
                        choices:
                            - disabled
                            - ap
                            - monitor
                            - sniffer
                            - sam
                    power_level:
                        description:
                            - Radio power level as a percentage of the maximum transmit power (0 - 100).
                        type: int
                    power_mode:
                        description:
                            - Set radio effective isotropic radiated power (EIRP) in dBm or by a percentage of the maximum EIRP . This power takes into
                               account both radio transmit power and antenna gain. Higher power level settings may be constrained by local regulatory
                                  requirements and AP capabilities.
                        type: str
                        choices:
                            - dBm
                            - percentage
                    power_value:
                        description:
                            - Radio EIRP power in dBm (1 - 33).
                        type: int
                    powersave_optimize:
                        description:
                            - Enable client power-saving features such as TIM, AC VO, and OBSS etc.
                        type: str
                        choices:
                            - tim
                            - ac-vo
                            - no-obss-scan
                            - no-11b-rate
                            - client-rate-follow
                    protection_mode:
                        description:
                            - Enable/disable 802.11g protection modes to support backwards compatibility with older clients (rtscts, ctsonly, disable).
                        type: str
                        choices:
                            - rtscts
                            - ctsonly
                            - disable
                    rts_threshold:
                        description:
                            - Maximum packet size for RTS transmissions, specifying the maximum size of a data packet before RTS/CTS (256 - 2346 bytes).
                        type: int
                    sam_bssid:
                        description:
                            - BSSID for WiFi network.
                        type: str
                    sam_captive_portal:
                        description:
                            - Enable/disable Captive Portal Authentication .
                        type: str
                        choices:
                            - enable
                            - disable
                    sam_password:
                        description:
                            - Passphrase for WiFi network connection.
                        type: str
                    sam_report_intv:
                        description:
                            - SAM report interval (sec), 0 for a one-time report.
                        type: int
                    sam_security_type:
                        description:
                            - Select WiFi network security type .
                        type: str
                        choices:
                            - open
                            - wpa-personal
                            - wpa-enterprise
                    sam_server:
                        description:
                            - SAM test server IP address or domain name.
                        type: str
                    sam_ssid:
                        description:
                            - SSID for WiFi network.
                        type: str
                    sam_test:
                        description:
                            - Select SAM test type .
                        type: str
                        choices:
                            - ping
                            - iperf
                    sam_username:
                        description:
                            - Username for WiFi network connection.
                        type: str
                    short_guard_interval:
                        description:
                            - Use either the short guard interval (Short GI) of 400 ns or the long guard interval (Long GI) of 800 ns.
                        type: str
                        choices:
                            - enable
                            - disable
                    spectrum_analysis:
                        description:
                            - Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                        type: str
                        choices:
                            - enable
                            - disable
                            - scan-only
                    transmit_optimize:
                        description:
                            - Packet transmission optimization options including power saving, aggregation limiting, retry limiting, etc. All are enabled by
                               default.
                        type: str
                        choices:
                            - disable
                            - power-save
                            - aggr-limit
                            - retry-limit
                            - send-bar
                    vap_all:
                        description:
                            - Enable/disable the automatic inheritance of all Virtual Access Points (VAPs) .
                        type: str
                        choices:
                            - enable
                            - disable
                            - tunnel
                            - bridge
                            - manual
                    vaps:
                        description:
                            - Manually selected list of Virtual Access Points (VAPs).
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Virtual Access Point (VAP) name. Source wireless-controller.vap-group.name system.interface.name.
                                required: true
                                type: str
                    wids_profile:
                        description:
                            - Wireless Intrusion Detection System (WIDS) profile name to assign to the radio. Source wireless-controller.wids-profile.name.
                        type: str
                    zero_wait_dfs:
                        description:
                            - Enable/disable zero wait DFS on radio .
                        type: str
                        choices:
                            - enable
                            - disable
            split_tunneling_acl:
                description:
                    - Split tunneling ACL filter list.
                type: list
                suboptions:
                    dest_ip:
                        description:
                            - Destination IP and mask for the split-tunneling subnet.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
            split_tunneling_acl_local_ap_subnet:
                description:
                    - Enable/disable automatically adding local subnetwork of FortiAP to split-tunneling ACL .
                type: str
                choices:
                    - enable
                    - disable
            split_tunneling_acl_path:
                description:
                    - Split tunneling ACL path is local/tunnel.
                type: str
                choices:
                    - tunnel
                    - local
            tun_mtu_downlink:
                description:
                    - Downlink CAPWAP tunnel MTU (0, 576, or 1500 bytes).
                type: int
            tun_mtu_uplink:
                description:
                    - Uplink CAPWAP tunnel MTU (0, 576, or 1500 bytes).
                type: int
            wan_port_mode:
                description:
                    - Enable/disable using a WAN port as a LAN port.
                type: str
                choices:
                    - wan-lan
                    - wan-only
'''

EXAMPLES = '''
- hosts: fortigates
  collections:
    - fortinet.fortios
  connection: httpapi
  vars:
   vdom: "root"
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
    fortios_wireless_controller_wtp_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_wtp_profile:
        allowaccess: "telnet"
        ap_country: "NA"
        ap_handoff: "enable"
        apcfg_profile: "<your_own_value> (source wireless-controller.apcfg-profile.name)"
        ble_profile: "<your_own_value> (source wireless-controller.ble-profile.name)"
        comment: "Comment."
        control_message_offload: "ebp-frame"
        deny_mac_list:
         -
            id:  "11"
            mac: "<your_own_value>"
        dtls_in_kernel: "enable"
        dtls_policy: "clear-text"
        energy_efficient_ethernet: "enable"
        ext_info_enable: "enable"
        frequency_handoff: "enable"
        handoff_roaming: "enable"
        handoff_rssi: "19"
        handoff_sta_thresh: "20"
        ip_fragment_preventing: "tcp-mss-adjust"
        lan:
            port_esl_mode: "offline"
            port_esl_ssid: "<your_own_value> (source system.interface.name)"
            port_mode: "offline"
            port_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port1_mode: "offline"
            port1_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port2_mode: "offline"
            port2_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port3_mode: "offline"
            port3_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port4_mode: "offline"
            port4_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port5_mode: "offline"
            port5_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port6_mode: "offline"
            port6_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port7_mode: "offline"
            port7_ssid: "<your_own_value> (source wireless-controller.vap.name)"
            port8_mode: "offline"
            port8_ssid: "<your_own_value> (source wireless-controller.vap.name)"
        lbs:
            aeroscout: "enable"
            aeroscout_ap_mac: "bssid"
            aeroscout_mmu_report: "enable"
            aeroscout_mu: "enable"
            aeroscout_mu_factor: "48"
            aeroscout_mu_timeout: "49"
            aeroscout_server_ip: "<your_own_value>"
            aeroscout_server_port: "51"
            ekahau_blink_mode: "enable"
            ekahau_tag: "<your_own_value>"
            erc_server_ip: "<your_own_value>"
            erc_server_port: "55"
            fortipresence: "foreign"
            fortipresence_ble: "enable"
            fortipresence_frequency: "58"
            fortipresence_port: "59"
            fortipresence_project: "<your_own_value>"
            fortipresence_rogue: "enable"
            fortipresence_secret: "<your_own_value>"
            fortipresence_server: "<your_own_value>"
            fortipresence_unassoc: "enable"
            station_locate: "enable"
        led_schedules:
         -
            name: "default_name_67 (source firewall.schedule.group.name firewall.schedule.recurring.name)"
        led_state: "enable"
        lldp: "enable"
        login_passwd: "<your_own_value>"
        login_passwd_change: "yes"
        max_clients: "72"
        name: "default_name_73"
        platform:
            ddscan: "enable"
            mode: "single-5G"
            type: "AP-11N"
        poe_mode: "auto"
        radio_1:
            airtime_fairness: "enable"
            amsdu: "enable"
            ap_handoff: "enable"
            ap_sniffer_addr: "<your_own_value>"
            ap_sniffer_bufsize: "84"
            ap_sniffer_chan: "85"
            ap_sniffer_ctl: "enable"
            ap_sniffer_data: "enable"
            ap_sniffer_mgmt_beacon: "enable"
            ap_sniffer_mgmt_other: "enable"
            ap_sniffer_mgmt_probe: "enable"
            auto_power_high: "91"
            auto_power_level: "enable"
            auto_power_low: "93"
            auto_power_target: "<your_own_value>"
            band: "802.11a"
            band_5g_type: "5g-full"
            bandwidth_admission_control: "enable"
            bandwidth_capacity: "98"
            beacon_interval: "99"
            bss_color: "100"
            call_admission_control: "enable"
            call_capacity: "102"
            channel:
             -
                chan: "<your_own_value>"
            channel_bonding: "80MHz"
            channel_utilization: "enable"
            coexistence: "enable"
            darrp: "enable"
            drma: "disable"
            drma_sensitivity: "low"
            dtim: "111"
            frag_threshold: "112"
            frequency_handoff: "enable"
            iperf_protocol: "udp"
            iperf_server_port: "115"
            max_clients: "116"
            max_distance: "117"
            mode: "disabled"
            power_level: "119"
            power_mode: "dBm"
            power_value: "121"
            powersave_optimize: "tim"
            protection_mode: "rtscts"
            radio_id: "124"
            rts_threshold: "125"
            sam_bssid: "<your_own_value>"
            sam_captive_portal: "enable"
            sam_password: "<your_own_value>"
            sam_report_intv: "129"
            sam_security_type: "open"
            sam_server: "<your_own_value>"
            sam_ssid: "<your_own_value>"
            sam_test: "ping"
            sam_username: "<your_own_value>"
            short_guard_interval: "enable"
            spectrum_analysis: "enable"
            transmit_optimize: "disable"
            vap_all: "enable"
            vaps:
             -
                name: "default_name_140 (source wireless-controller.vap-group.name wireless-controller.vap.name)"
            wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
            zero_wait_dfs: "enable"
        radio_2:
            airtime_fairness: "enable"
            amsdu: "enable"
            ap_handoff: "enable"
            ap_sniffer_addr: "<your_own_value>"
            ap_sniffer_bufsize: "148"
            ap_sniffer_chan: "149"
            ap_sniffer_ctl: "enable"
            ap_sniffer_data: "enable"
            ap_sniffer_mgmt_beacon: "enable"
            ap_sniffer_mgmt_other: "enable"
            ap_sniffer_mgmt_probe: "enable"
            auto_power_high: "155"
            auto_power_level: "enable"
            auto_power_low: "157"
            auto_power_target: "<your_own_value>"
            band: "802.11a"
            band_5g_type: "5g-full"
            bandwidth_admission_control: "enable"
            bandwidth_capacity: "162"
            beacon_interval: "163"
            bss_color: "164"
            call_admission_control: "enable"
            call_capacity: "166"
            channel:
             -
                chan: "<your_own_value>"
            channel_bonding: "80MHz"
            channel_utilization: "enable"
            coexistence: "enable"
            darrp: "enable"
            drma: "disable"
            drma_sensitivity: "low"
            dtim: "175"
            frag_threshold: "176"
            frequency_handoff: "enable"
            iperf_protocol: "udp"
            iperf_server_port: "179"
            max_clients: "180"
            max_distance: "181"
            mode: "disabled"
            power_level: "183"
            power_mode: "dBm"
            power_value: "185"
            powersave_optimize: "tim"
            protection_mode: "rtscts"
            radio_id: "188"
            rts_threshold: "189"
            sam_bssid: "<your_own_value>"
            sam_captive_portal: "enable"
            sam_password: "<your_own_value>"
            sam_report_intv: "193"
            sam_security_type: "open"
            sam_server: "<your_own_value>"
            sam_ssid: "<your_own_value>"
            sam_test: "ping"
            sam_username: "<your_own_value>"
            short_guard_interval: "enable"
            spectrum_analysis: "enable"
            transmit_optimize: "disable"
            vap_all: "enable"
            vaps:
             -
                name: "default_name_204 (source wireless-controller.vap-group.name wireless-controller.vap.name)"
            wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
            zero_wait_dfs: "enable"
        radio_3:
            airtime_fairness: "enable"
            amsdu: "enable"
            ap_handoff: "enable"
            ap_sniffer_addr: "<your_own_value>"
            ap_sniffer_bufsize: "212"
            ap_sniffer_chan: "213"
            ap_sniffer_ctl: "enable"
            ap_sniffer_data: "enable"
            ap_sniffer_mgmt_beacon: "enable"
            ap_sniffer_mgmt_other: "enable"
            ap_sniffer_mgmt_probe: "enable"
            auto_power_high: "219"
            auto_power_level: "enable"
            auto_power_low: "221"
            auto_power_target: "<your_own_value>"
            band: "802.11a"
            band_5g_type: "5g-full"
            bandwidth_admission_control: "enable"
            bandwidth_capacity: "226"
            beacon_interval: "227"
            bss_color: "228"
            call_admission_control: "enable"
            call_capacity: "230"
            channel:
             -
                chan: "<your_own_value>"
            channel_bonding: "160MHz"
            channel_utilization: "enable"
            coexistence: "enable"
            darrp: "enable"
            drma: "disable"
            drma_sensitivity: "low"
            dtim: "239"
            frag_threshold: "240"
            frequency_handoff: "enable"
            iperf_protocol: "udp"
            iperf_server_port: "243"
            max_clients: "244"
            max_distance: "245"
            mode: "disabled"
            power_level: "247"
            power_mode: "dBm"
            power_value: "249"
            powersave_optimize: "tim"
            protection_mode: "rtscts"
            radio_id: "252"
            rts_threshold: "253"
            sam_bssid: "<your_own_value>"
            sam_captive_portal: "enable"
            sam_password: "<your_own_value>"
            sam_report_intv: "257"
            sam_security_type: "open"
            sam_server: "<your_own_value>"
            sam_ssid: "<your_own_value>"
            sam_test: "ping"
            sam_username: "<your_own_value>"
            short_guard_interval: "enable"
            spectrum_analysis: "enable"
            transmit_optimize: "disable"
            vap_all: "enable"
            vaps:
             -
                name: "default_name_268 (source wireless-controller.vap-group.name system.interface.name)"
            wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
            zero_wait_dfs: "enable"
        radio_4:
            airtime_fairness: "enable"
            amsdu: "enable"
            ap_handoff: "enable"
            ap_sniffer_addr: "<your_own_value>"
            ap_sniffer_bufsize: "276"
            ap_sniffer_chan: "277"
            ap_sniffer_ctl: "enable"
            ap_sniffer_data: "enable"
            ap_sniffer_mgmt_beacon: "enable"
            ap_sniffer_mgmt_other: "enable"
            ap_sniffer_mgmt_probe: "enable"
            auto_power_high: "283"
            auto_power_level: "enable"
            auto_power_low: "285"
            auto_power_target: "<your_own_value>"
            band: "802.11a"
            band_5g_type: "5g-full"
            bandwidth_admission_control: "enable"
            bandwidth_capacity: "290"
            beacon_interval: "291"
            bss_color: "292"
            call_admission_control: "enable"
            call_capacity: "294"
            channel:
             -
                chan: "<your_own_value>"
            channel_bonding: "160MHz"
            channel_utilization: "enable"
            coexistence: "enable"
            darrp: "enable"
            drma: "disable"
            drma_sensitivity: "low"
            dtim: "303"
            frag_threshold: "304"
            frequency_handoff: "enable"
            iperf_protocol: "udp"
            iperf_server_port: "307"
            max_clients: "308"
            max_distance: "309"
            mode: "disabled"
            power_level: "311"
            power_mode: "dBm"
            power_value: "313"
            powersave_optimize: "tim"
            protection_mode: "rtscts"
            rts_threshold: "316"
            sam_bssid: "<your_own_value>"
            sam_captive_portal: "enable"
            sam_password: "<your_own_value>"
            sam_report_intv: "320"
            sam_security_type: "open"
            sam_server: "<your_own_value>"
            sam_ssid: "<your_own_value>"
            sam_test: "ping"
            sam_username: "<your_own_value>"
            short_guard_interval: "enable"
            spectrum_analysis: "enable"
            transmit_optimize: "disable"
            vap_all: "enable"
            vaps:
             -
                name: "default_name_331 (source wireless-controller.vap-group.name system.interface.name)"
            wids_profile: "<your_own_value> (source wireless-controller.wids-profile.name)"
            zero_wait_dfs: "enable"
        split_tunneling_acl:
         -
            dest_ip: "<your_own_value>"
            id:  "336"
        split_tunneling_acl_local_ap_subnet: "enable"
        split_tunneling_acl_path: "tunnel"
        tun_mtu_downlink: "339"
        tun_mtu_uplink: "340"
        wan_port_mode: "wan-lan"

'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_legacy_fortiosapi
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import schema_to_module_spec
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_schema_versioning
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import is_same_comparison
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import serialize


def filter_wireless_controller_wtp_profile_data(json):
    option_list = ['allowaccess', 'ap_country', 'ap_handoff',
                   'apcfg_profile', 'ble_profile', 'comment',
                   'control_message_offload', 'deny_mac_list', 'dtls_in_kernel',
                   'dtls_policy', 'energy_efficient_ethernet', 'ext_info_enable',
                   'frequency_handoff', 'handoff_roaming', 'handoff_rssi',
                   'handoff_sta_thresh', 'ip_fragment_preventing', 'lan',
                   'lbs', 'led_schedules', 'led_state',
                   'lldp', 'login_passwd', 'login_passwd_change',
                   'max_clients', 'name', 'platform',
                   'poe_mode', 'radio_1', 'radio_2',
                   'radio_3', 'radio_4', 'split_tunneling_acl',
                   'split_tunneling_acl_local_ap_subnet', 'split_tunneling_acl_path', 'tun_mtu_downlink',
                   'tun_mtu_uplink', 'wan_port_mode']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if not data or index == len(path) or path[index] not in data or not data[path[index]]:
        return

    if index == len(path) - 1:
        data[path[index]] = ' '.join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [[u'control_message_offload'], [u'ip_fragment_preventing'], [u'radio_3', u'transmit_optimize'], [u'radio_3', u'powersave_optimize'],
                       [u'radio_2', u'transmit_optimize'], [u'radio_2', u'powersave_optimize'], [
                           u'radio_1', u'transmit_optimize'], [u'radio_1', u'powersave_optimize'],
                       [u'allowaccess'], [u'dtls_policy'], [u'radio_4', u'transmit_optimize'], [u'radio_4', u'powersave_optimize']]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def wireless_controller_wtp_profile(data, fos, check_mode=False):

    vdom = data['vdom']

    state = data['state']

    wireless_controller_wtp_profile_data = data['wireless_controller_wtp_profile']
    wireless_controller_wtp_profile_data = flatten_multilists_attributes(wireless_controller_wtp_profile_data)
    filtered_data = underscore_to_hyphen(filter_wireless_controller_wtp_profile_data(wireless_controller_wtp_profile_data))

    # check_mode starts from here
    if check_mode:
        mkey = fos.get_mkey('system', 'interface', filtered_data, vdom=vdom)
        current_data = fos.get('system', 'interface', vdom=vdom, mkey=mkey)
        is_existed = current_data and current_data.get('http_status') == 200 \
            and isinstance(current_data.get('results'), list) \
            and len(current_data['results']) > 0

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == 'present' or state is True:
            if mkey is None:
                return False, True, filtered_data

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data['results'][0]), serialize(filtered_data))
                return False, not is_same, filtered_data

            # record does not exist
            return False, True, filtered_data

        if state == 'absent':
            if mkey is None:
                return False, False, filtered_data

            if is_existed:
                return False, True, filtered_data
            return False, False, filtered_data

        return True, False, {'reason: ': 'Must provide state parameter'}

    if state == "present" or state is True:
        return fos.set('wireless-controller',
                       'wtp-profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('wireless-controller',
                          'wtp-profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_wireless_controller(data, fos, check_mode):

    if data['wireless_controller_wtp_profile']:
        resp = wireless_controller_wtp_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('wireless_controller_wtp_profile'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "comment": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "split_tunneling_acl": {
            "type": "list",
            "children": {
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "dest_ip": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "lbs": {
            "type": "dict",
            "children": {
                "fortipresence_port": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "erc_server_port": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "fortipresence_frequency": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "fortipresence_ble": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "fortipresence_project": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout_ap_mac": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "board-mac",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout_mmu_report": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "fortipresence": {
                    "type": "string",
                    "options": [
                        {
                            "value": "foreign",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "both",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ekahau_tag": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "fortipresence_unassoc": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "erc_server_ip": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout_mu_factor": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "fortipresence_server": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "station_locate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout_mu": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout_mu_timeout": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout_server_ip": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "fortipresence_secret": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "aeroscout_server_port": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "fortipresence_rogue": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ekahau_blink_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "control_message_offload": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "ebp-frame",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "aeroscout-tag",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ap-list",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "sta-list",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "sta-cap-list",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "stats",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "aeroscout-mu",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "sta-health",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                {
                    "value": "spectral-analysis",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "tun_mtu_downlink": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "tun_mtu_uplink": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ble_profile": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "lldp": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "login_passwd_change": {
            "type": "string",
            "options": [
                {
                    "value": "yes",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "default",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "no",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "platform": {
            "type": "dict",
            "children": {
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "AP-11N",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "220B",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "210B",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "222B",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "112B",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "320B",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "11C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "14C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "223B",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "28C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "320C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "221C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "25D",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "222C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "224D",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "214B",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "21D",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "24D",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "112D",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "223C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "321C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "C220C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "C225C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "C23JD",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "C24JE",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S321C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S322C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S323C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S311C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S313C",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S321CR",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S322CR",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S323CR",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S421E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S422E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S423E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "421E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "423E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "221E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "222E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "223E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "224E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S221E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "S223E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U421E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U422EV",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U423E",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U221EV",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U223EV",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U24JEV",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U321EV",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "U323EV",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "231E",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "321E",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "431F",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "432F",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "433F",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "231F",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "234F",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "23JF",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "U431F",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "U433F",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "831F",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "U231F",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "U234F",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "U432F",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "single-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "dual-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ddscan": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "frequency_handoff": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "deny_mac_list": {
            "type": "list",
            "children": {
                "mac": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "split_tunneling_acl_path": {
            "type": "string",
            "options": [
                {
                    "value": "tunnel",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "local",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ip_fragment_preventing": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "tcp-mss-adjust",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "icmp-unreachable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "radio_3": {
            "type": "dict",
            "children": {
                "transmit_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "power-save",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "aggr-limit",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "retry-limit",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "send-bar",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_bufsize": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "frag_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "bandwidth_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "coexistence": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_low": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_ctl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "bandwidth_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "bss_color": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                "band_5g_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "5g-full",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-high",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-low",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_bonding": {
                    "type": "string",
                    "options": [
                        {
                            "value": "160MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "80MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "40MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "20MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "dtim": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_high": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "iperf_server_port": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vaps": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "short_guard_interval": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "powersave_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "tim",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "ac-vo",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "no-obss-scan",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "no-11b-rate",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "client-rate-follow",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_level": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_chan": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_addr": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "radio_id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.3": True,
                        "v6.2.5": False,
                        "v6.2.7": False
                    }
                },
                "ap_sniffer_data": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "wids_profile": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "vap_all": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": False,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": False,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "tunnel",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "bridge",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "manual",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "rts_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "iperf_protocol": {
                    "type": "string",
                    "options": [
                        {
                            "value": "udp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tcp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "channel": {
                    "type": "list",
                    "children": {
                        "chan": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "protection_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "rtscts",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "ctsonly",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "drma": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_security_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "open",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-personal",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-enterprise",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "power_value": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ap_sniffer_mgmt_probe": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "zero_wait_dfs": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "spectrum_analysis": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.4.1": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.4.1": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "scan-only",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_utilization": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "frequency_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_password": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "drma_sensitivity": {
                    "type": "string",
                    "options": [
                        {
                            "value": "low",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "medium",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "high",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "band": {
                    "type": "string",
                    "options": [
                        {
                            "value": "802.11a",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11b",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11g",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n,g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n-5G-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n,g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac-2G",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_mgmt_beacon": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "beacon_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_mgmt_other": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_ssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "max_distance": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_test": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ping",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "iperf",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "power_level": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "max_clients": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "airtime_fairness": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "darrp": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_report_intv": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_bssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sam_captive_portal": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "amsdu": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_target": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_server": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sam_username": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disabled",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "ap",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "sniffer",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "sam",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "power_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "dBm",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "percentage",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True
            }
        },
        "radio_2": {
            "type": "dict",
            "children": {
                "transmit_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "power-save",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "aggr-limit",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "retry-limit",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "send-bar",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_bufsize": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_bssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "frag_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "bandwidth_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "coexistence": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_low": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_ctl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "bandwidth_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "bss_color": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                "band_5g_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "5g-full",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-high",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-low",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_bonding": {
                    "type": "string",
                    "options": [
                        {
                            "value": "80MHz",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "40MHz",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "20MHz",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "160MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "dtim": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_high": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "iperf_server_port": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vaps": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "short_guard_interval": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "powersave_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "tim",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "ac-vo",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "no-obss-scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "no-11b-rate",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "client-rate-follow",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_level": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_chan": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_addr": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "spectrum_analysis": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "scan-only",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_data": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "wids_profile": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "vap_all": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": False,
                                "v6.0.5": True,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": False,
                                "v6.0.5": True,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "tunnel",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "bridge",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "manual",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "rts_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "iperf_protocol": {
                    "type": "string",
                    "options": [
                        {
                            "value": "udp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tcp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "channel": {
                    "type": "list",
                    "children": {
                        "chan": {
                            "type": "string",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "protection_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "rtscts",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "ctsonly",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "drma": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_security_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "open",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-personal",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-enterprise",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "power_value": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ap_sniffer_mgmt_probe": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "zero_wait_dfs": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_utilization": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "frequency_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_password": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "drma_sensitivity": {
                    "type": "string",
                    "options": [
                        {
                            "value": "low",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "medium",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "high",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "band": {
                    "type": "string",
                    "options": [
                        {
                            "value": "802.11a",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11b",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11g",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n-5G",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ac",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n,g-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11g-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n-5G-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ac,n-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ac-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ax-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n,g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac-2G",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_mgmt_beacon": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "beacon_interval": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_mgmt_other": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_ssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "max_distance": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_test": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ping",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "iperf",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "power_level": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "max_clients": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "airtime_fairness": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "darrp": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_report_intv": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "radio_id": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": True,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "sam_captive_portal": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "amsdu": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_target": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_server": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sam_username": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "ap",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "sniffer",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "sam",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "power_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "dBm",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "percentage",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "radio_1": {
            "type": "dict",
            "children": {
                "transmit_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "power-save",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "aggr-limit",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "retry-limit",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "send-bar",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_bufsize": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_bssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "frag_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "bandwidth_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "coexistence": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_low": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_ctl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "bandwidth_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "bss_color": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                "band_5g_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "5g-full",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-high",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-low",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_bonding": {
                    "type": "string",
                    "options": [
                        {
                            "value": "80MHz",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "40MHz",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "20MHz",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "160MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "dtim": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_high": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "iperf_server_port": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vaps": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "short_guard_interval": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "powersave_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "tim",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "ac-vo",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "no-obss-scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "no-11b-rate",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "client-rate-follow",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_level": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_chan": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_addr": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "spectrum_analysis": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "scan-only",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_data": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "wids_profile": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "vap_all": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": False,
                                "v6.0.5": True,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": False,
                                "v6.0.5": True,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "tunnel",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "bridge",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "manual",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "rts_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "iperf_protocol": {
                    "type": "string",
                    "options": [
                        {
                            "value": "udp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tcp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "channel": {
                    "type": "list",
                    "children": {
                        "chan": {
                            "type": "string",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "protection_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "rtscts",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "ctsonly",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "drma": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_security_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "open",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-personal",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-enterprise",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "power_value": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ap_sniffer_mgmt_probe": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "zero_wait_dfs": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_utilization": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "frequency_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_password": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "drma_sensitivity": {
                    "type": "string",
                    "options": [
                        {
                            "value": "low",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "medium",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "high",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "band": {
                    "type": "string",
                    "options": [
                        {
                            "value": "802.11a",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11b",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11g",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n-5G",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ac",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n,g-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11g-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11n-5G-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ac,n-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ac-only",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "802.11ax-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n,g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac-2G",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_mgmt_beacon": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "beacon_interval": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ap_sniffer_mgmt_other": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_ssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "max_distance": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_test": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ping",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "iperf",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "power_level": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "max_clients": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "airtime_fairness": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "darrp": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sam_report_intv": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "radio_id": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": True,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "sam_captive_portal": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "amsdu": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "auto_power_target": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_server": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sam_username": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "ap",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "sniffer",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "sam",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "power_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "dBm",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "percentage",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "allowaccess": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "telnet",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "http",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "https",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ssh",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "snmp",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "dtls_in_kernel": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "handoff_sta_thresh": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "lan": {
            "type": "dict",
            "children": {
                "port7_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port3_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port_esl_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                "port4_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port4_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port3_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port6_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port5_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port6_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port1_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port2_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port8_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port5_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port_esl_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                "port7_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port8_ssid": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port1_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "port2_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "offline",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "nat-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-wan",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "bridge-to-ssid",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "dtls_policy": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "clear-text",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "dtls-enabled",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ipsec-vpn",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "apcfg_profile": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "ext_info_enable": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "radio_4": {
            "type": "dict",
            "children": {
                "transmit_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "power-save",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "aggr-limit",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "retry-limit",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "send-bar",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_bufsize": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "frag_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "bandwidth_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "coexistence": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_low": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_ctl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "bandwidth_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "bss_color": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                "band_5g_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "5g-full",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-high",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "5g-low",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_bonding": {
                    "type": "string",
                    "options": [
                        {
                            "value": "160MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "80MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "40MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "20MHz",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "dtim": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_high": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "iperf_server_port": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vaps": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "short_guard_interval": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "powersave_optimize": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "tim",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "ac-vo",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "no-obss-scan",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "no-11b-rate",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "client-rate-follow",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_level": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_chan": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_addr": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "spectrum_analysis": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.4.1": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.4.1": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "scan-only",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_data": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "wids_profile": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "vap_all": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": False,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": False,
                                "v6.4.4": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "tunnel",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "bridge",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "manual",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "rts_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "iperf_protocol": {
                    "type": "string",
                    "options": [
                        {
                            "value": "udp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tcp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "channel": {
                    "type": "list",
                    "children": {
                        "chan": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "protection_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "rtscts",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "ctsonly",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "drma": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_security_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "open",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-personal",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wpa-enterprise",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "power_value": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ap_sniffer_mgmt_probe": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "zero_wait_dfs": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "channel_utilization": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "frequency_handoff": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_password": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "drma_sensitivity": {
                    "type": "string",
                    "options": [
                        {
                            "value": "low",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "medium",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "high",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "band": {
                    "type": "string",
                    "options": [
                        {
                            "value": "802.11a",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11b",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11g",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-5G",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n,g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11n-5G-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,ac,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-5G-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax,n,g-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ax-only",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "802.11ac-2G",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_mgmt_beacon": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "beacon_interval": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "ap_sniffer_mgmt_other": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_ssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "max_distance": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_test": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ping",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "iperf",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_admission_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "power_level": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "max_clients": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "airtime_fairness": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "darrp": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_report_intv": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "call_capacity": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "sam_bssid": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sam_captive_portal": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "amsdu": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "auto_power_target": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                "sam_server": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sam_username": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disabled",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "ap",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "sniffer",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "sam",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "power_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "dBm",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "percentage",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": False,
                "v6.2.5": True,
                "v6.2.7": True
            }
        },
        "poe_mode": {
            "type": "string",
            "options": [
                {
                    "value": "auto",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "8023af",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "8023at",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "power-adapter",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "full",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "high",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                },
                {
                    "value": "low",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ap_country": {
            "type": "string",
            "options": [
                {
                    "value": "NA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AL",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "DZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AM",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AU",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BH",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BD",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BB",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BY",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BN",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "BG",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "KH",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CL",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CN",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "HR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CY",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "DK",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "DO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "EC",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "EG",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SV",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "EE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "FI",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "FR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "GE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "DE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "GR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "GL",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "GD",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "GU",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "GT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "HT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "HN",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "HK",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "HU",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "IS",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "IN",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ID",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "IR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "IE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "IL",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "IT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "JM",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "JO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "KZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "KE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "KP",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "KR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "KW",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "LV",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "LB",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "LI",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "LT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "LU",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MK",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MY",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MX",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MC",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "MM",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "NP",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "NL",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AN",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AW",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "NZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "NO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "OM",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PK",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PG",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PY",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PH",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PL",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "QA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "RO",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "RU",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "RW",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "RS",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ME",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SG",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SK",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SI",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ZA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ES",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "LK",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SD",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CH",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "SY",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "TW",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "TZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "TH",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "TT",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "TN",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "TR",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "AE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "UA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "GB",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "US",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "PS",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "UY",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "UZ",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "VE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "VN",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "YE",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ZB",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ZW",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "JP",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CA",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "CF",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                {
                    "value": "BS",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "BF",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "KY",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "CX",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "GH",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "GY",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "CI",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "MW",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "MV",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "FM",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "KN",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "LC",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "VC",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "SN",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "TM",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "TC",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "UG",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "VU",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "AF",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "AS",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "BJ",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "BM",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "BT",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "BW",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "CM",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "TD",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "CG",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "CD",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "DM",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ET",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "GF",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "PF",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "FO",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "FJ",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "GI",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "GP",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "IQ",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "IM",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "LA",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "LS",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "LY",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MG",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ML",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MH",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MQ",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MR",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MU",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "YT",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MD",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "NI",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "NE",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MP",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "PW",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "RE",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "BL",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "MF",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "PM",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "SL",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "SR",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "TG",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "VI",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "WF",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ZM",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "energy_efficient_ethernet": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "handoff_rssi": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ap_handoff": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "max_clients": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "login_passwd": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "handoff_roaming": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "split_tunneling_acl_local_ap_subnet": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "led_schedules": {
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "wan_port_mode": {
            "type": "string",
            "options": [
                {
                    "value": "wan-lan",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "wan-only",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "led_state": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        }
    },
    "revisions": {
        "v6.0.0": True,
        "v7.0.0": True,
        "v6.0.5": True,
        "v6.4.4": True,
        "v6.4.0": True,
        "v6.4.1": True,
        "v6.2.0": True,
        "v6.2.3": True,
        "v6.2.5": True,
        "v6.2.7": True,
        "v6.0.11": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": bool},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "wireless_controller_wtp_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["wireless_controller_wtp_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_wtp_profile"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "wireless_controller_wtp_profile")

        is_error, has_changed, result = fortios_wireless_controller(module.params, fos, module.check_mode)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv")

    if not is_error:
        if versions_check_result and versions_check_result['matched'] is False:
            module.exit_json(changed=has_changed, version_check_warning=versions_check_result, meta=result)
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        if versions_check_result and versions_check_result['matched'] is False:
            module.fail_json(msg="Error in repo", version_check_warning=versions_check_result, meta=result)
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()

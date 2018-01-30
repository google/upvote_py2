# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Constants for VirusTotal."""

from upvote.shared import constants


RESPONSE_CODE = constants.Namespace(tuples=[
    ('UNKNOWN', 0),
    ('PENDING', -2),
    ('ANALYZED', 1),
])

ANALYSIS_STATE = constants.UppercaseNamespace(
    names=('UNKNOWN', 'PENDING', 'ANALYZED'))
ANALYSIS_STATE.DefineMap('FROM_RESPONSE_CODE', {
    RESPONSE_CODE.UNKNOWN: ANALYSIS_STATE.UNKNOWN,
    RESPONSE_CODE.PENDING: ANALYSIS_STATE.PENDING,
    RESPONSE_CODE.ANALYZED: ANALYSIS_STATE.ANALYZED,
})

# NOTE: This list contains all scanners that will be used in displaying results
# to users. Its default is the list of all VirusTotal scanners (as of 17-11-01).
# These can be added or removed based on institutional trust, false-positive
# tolerance, or just general preference.
TRUSTED_AV_VENDORS = set([
    'ALYac', 'AVG', 'AVware', 'Ad-Aware', 'AegisLab', 'AhnLab-V3',
    'Antiy-AVL', 'Arcabit', 'Avast', 'Avast-Mobile', 'Avira',
    'Baidu', 'BitDefender', 'Bkav', 'CAT-QuickHeal', 'CMC',
    'ClamAV', 'Comodo', 'Cyren', 'DrWeb', 'ESET-NOD32', 'Emsisoft',
    'F-Prot', 'F-Secure', 'Fortinet', 'GData', 'Ikarus',
    'Jiangmin', 'K7AntiVirus', 'K7GW', 'Kaspersky', 'Kingsoft',
    'MAX', 'Malwarebytes', 'McAfee', 'McAfee-GW-Edition',
    'MicroWorld-eScan', 'Microsoft', 'NANO-Antivirus', 'Panda',
    'Qihoo-360', 'Rising', 'SUPERAntiSpyware', 'Sophos',
    'Symantec', 'Tencent', 'TheHacker', 'TotalDefense',
    'TrendMicro', 'TrendMicro-HouseCall', 'VBA32', 'VIPRE',
    'ViRobot', 'Webroot', 'WhiteArmor', 'Yandex', 'Zillya',
    'ZoneAlarm', 'Zoner', 'nProtect'
])

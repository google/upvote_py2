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

"""Constants specific to the santa_api module."""

from upvote.shared import constants


PREFLIGHT = constants.LowercaseNamespace([
    'BATCH_SIZE', 'BLACKLIST_REGEX', 'CLEAN_SYNC', 'CLIENT_MODE',
    'HOSTNAME', 'OS_BUILD', 'OS_VERSION', 'PRIMARY_USER', 'REQUEST_CLEAN_SYNC',
    'SANTA_VERSION', 'SERIAL_NUM', 'UPLOAD_LOGS_URL', 'WHITELIST_REGEX',
    'BUNDLES_ENABLED',])


EVENT_UPLOAD = constants.LowercaseNamespace([
    'CN', 'CURRENT_SESSIONS', 'DECISION', 'EVENT_UPLOAD_BUNDLE_BINARIES',
    'EVENTS', 'EXECUTING_USER', 'EXECUTION_TIME', 'FILE_BUNDLE_ID',
    'FILE_BUNDLE_NAME', 'FILE_BUNDLE_PATH', 'FILE_BUNDLE_VERSION',
    'FILE_BUNDLE_VERSION_STRING', 'FILE_BUNDLE_EXECUTABLE_REL_PATH',
    'FILE_NAME', 'FILE_PATH', 'FILE_SHA256', 'LOGGED_IN_USERS', 'ORG', 'OU',
    'PID', 'PPID', 'QUARANTINE_AGENT_BUNDLE_ID', 'QUARANTINE_DATA_URL',
    'QUARANTINE_REFERER_URL', 'QUARANTINE_TIMESTAMP', 'REQUEST_UPLOADS',
    'REQUEST_UPLOADS_URL', 'SHA256', 'SIGNING_CHAIN', 'VALID_FROM',
    'VALID_UNTIL', 'FILE_BUNDLE_HASH', 'FILE_BUNDLE_BINARY_COUNT',])


RULE_DOWNLOAD = constants.LowercaseNamespace([
    'CREATION_TIME', 'CURSOR', 'CUSTOM_MSG', 'POLICY', 'RULE_TYPE', 'RULES',
    'SHA256', 'FILE_BUNDLE_HASH', 'FILE_BUNDLE_BINARY_COUNT',])


POSTFLIGHT = constants.LowercaseNamespace(['BACKOFF'])

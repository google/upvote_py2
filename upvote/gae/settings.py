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

"""Common Upvote GAE settings."""

from common import context

from upvote.gae.utils import settings_utils
from upvote.shared import constants


# The email domain of the users accessing Upvote.
#
# For users authenticating with GMail accounts:
#   USER_EMAIL_DOMAIN = 'gmail.com'
# For Foo Inc. employees authenticating with a GSuite-hosted email:
#   USER_EMAIL_DOMAIN = 'foo.com'
#
# NOTE: Must be all lowercase.
USER_EMAIL_DOMAIN = 'todo-example-domain.com'

# Whether all new applications will be checked against binary analysis service.
#
# NOTE: This is a relatively high QPS option for the VirusTotal API and will
# likely exceed free-tier levels.
ENABLE_BINARY_ANALYSIS_PRECACHING = False

# Sets the method by which events are associated with users in Upvote.
#
# This configures whether events are associated with the OS user that executed
# the event or with the host owner. Notably, host owners for Santa clients can
# be configured in the settings while the executing user is dependent on the OS
# setup.
#
# See docs for further discussion.
EVENT_CREATION = constants.EVENT_CREATION.HOST_OWNER

# The default execution mode for clients syncing for the first time.
SANTA_DEFAULT_CLIENT_MODE = constants.SANTA_CLIENT_MODE.LOCKDOWN
# If provided, a regex string that matches execution paths (read: not files)
# from which executions will be allowed.
# NOTE: This regex must be written in ICU format. Docs can be found here:
# https://developer.apple.com/documentation/foundation/nsregularexpression
SANTA_DIRECTORY_WHITELIST_REGEX = None
# If provided, a regex string that matches execution paths (read: not files)
# from which executions will be blocked.
# NOTE: This regex must be written in ICU format. Docs can be found here:
# https://developer.apple.com/documentation/foundation/nsregularexpression
SANTA_DIRECTORY_BLACKLIST_REGEX = None
# The maximum number of events that a Santa client will attempt to upload in a
# single request.
SANTA_EVENT_BATCH_SIZE = 100
# The maximum number of rules that Upvote will attempt to send to clients in a
# single request.
SANTA_RULE_BATCH_SIZE = 250
# Whether Upvote will require connecting clients to provide an XSRF token.
SANTA_REQUIRE_XSRF = True
# Whether Santa clients will upload bundles.
#
# See docs for feature details.
SANTA_BUNDLES_ENABLED = True
# The failure mode of Santa client authentication.
#
# NOTE: By default, there is no authentication mechanism implemented for Santa
# clients (See upvote/gae/modules/santa_api/auth.py). This setting will only
# have an effect if some authentication procedure is written.
SANTA_CLIENT_VALIDATION = constants.VALIDATION_MODE.FAIL_CLOSED

# A list of email addresses of users that will always have the permissions of
# administrators.
FAILSAFE_ADMINISTRATORS = []

# The score thresholds beyond which a Blockable will transition to the
# associated state.
#
# Blockables are created with an UNAPPROVED state. If they sink below the BANNED
# threshold (-15 by default), they become banned. If they rise above, say, the
# GLOBALLY_WHITELISTED threshold, they become globally whitelisted.
VOTING_THRESHOLDS = {
    constants.STATE.BANNED: -26,
    constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING: 5,
    constants.STATE.GLOBALLY_WHITELISTED: 50,
}

# The vote weight available to a user with the associated role.
#
# These are generally determined in relation to the VOTING_THRESHOLDS above. For
# instance, the defaults of 5 USER upvotes leading to a local whitelist and 2
# ADMIN upvotes leading to a global whitelist are important relation to
# consider.
#
# See docs for further discussion.
VOTING_WEIGHTS = {
    constants.USER_ROLE.UNTRUSTED_USER: 0,
    constants.USER_ROLE.USER: 1,
    constants.USER_ROLE.TRUSTED_USER: 3,
    constants.USER_ROLE.SUPERUSER: 25,
    constants.USER_ROLE.SECURITY: 25,
    constants.USER_ROLE.ADMINISTRATOR: 25,
}

# Maps elevated-privilege roles to a list of user group names.
#
# These groups are expanded to users (See upvote/gae/shared/common/groups.py)
# and modified with their roles via the /cron/roles/sync cron.
GROUP_ROLE_ASSIGNMENTS = {
    constants.USER_ROLE.UNTRUSTED_USER: [],
    constants.USER_ROLE.TRUSTED_USER: [],
    constants.USER_ROLE.SUPERUSER: [],
    constants.USER_ROLE.SECURITY: [],
    constants.USER_ROLE.ADMINISTRATOR: ['admin-users'],
}

# Certificate hashes that are critical to the macOS platform.
CRITICAL_MAC_OS_CERT_HASHES = [

    # Google Certificate for Chrome
    '345a8e098bd04794aaeefda8c9ef56a0bf3d3706d67d35bc0e23f11bb3bffce5',

    # Apple Software Signing for macOS 10.10, 10.11, 10.12, and 10.13
    '2aa4b9973b7ba07add447ee4da8b5337c3ee2c3a991911e80e7282e8a751fc32',

    # Google Certificate for Santa
    '33b9aee3b089c922952c9240a40a0daa271bebf192cf3f7d964722e8f2170e48']

# These groups mandate a specific client mode for all Santa clients belonging to
# the users in the associated group.
#
# These may be helpful in rolling out lockdown mode to a large fleet.
LOCKDOWN_GROUP = ''
MONITOR_GROUP = ''

# **Bit9-only** The Active Directory domain of Bit9 host users.
#
# Used to determine the users associated with Bit9 events.
AD_DOMAIN = 'TODO-EXAMPLE-DOMAIN'

# **Bit9-only** The hostname of the Active Directory.
#
# Used to construct FQDNs for Bit9 hosts.
#
# NOTE: Must be all lowercase.
AD_HOSTNAME = 'ad.todo-example-domain.com'

# NOTE: Incomplete.
# Sets a static alert (aka "blood bar") for all users of the system to
# communicate abnormal system conditions.
SITE_ALERT = {
    'message': '',
    'severity': '',
    'is_active': False,
}


class ProdEnv(settings_utils.DefaultEnv):
  """The production environment namespace."""
  NAME = 'Prod'

  HOSTNAME = 'XXX-REPLACE-WITH-PROJECT-ID-XXX.appspot.com'
  PROJECT_ID = 'XXX-REPLACE-WITH-PROJECT-ID-XXX'
  DATASTORE_BACKUP_BUCKET = 'XXX-REPLACE-WITH-PROJECT-ID-XXX'

  # The address of the Bit9 frontend server from which the REST API is served.
  # The path /api/bit9platform/v1 at this address should display the API docs.
  BIT9_REST_URL = 'address-of-my-bit9-frontend-server.com'

  # Whether the BigQuery streaming feature is enabled.
  #
  # BigQuery streaming extracts a number of system events (e.g. Execution event,
  # Blockable state change, User vote, etc.) and streams them to tables in
  # BigQuery.
  #
  # See docs for complete setup instructions.
  ENABLE_BIGQUERY_STREAMING = False


class LocalEnv(settings_utils.DefaultEnv):
  """The Local environment namespace."""
  NAME = 'Local'

  HOSTNAME = '0.0.0.0:8080'

  PROJECT_ID = 'auto'

  ENABLE_BIGQUERY_STREAMING = False


@context.LazyProxy
def ENV():
  return settings_utils.CurrentEnvironment()

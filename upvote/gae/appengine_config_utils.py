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

"""Utility methods for appengine_config.py.

The primary reason this exists as a separate module is to facilitate unit
testing, as everything in appengine_config.py is run at import time.
"""
from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as model_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import santa
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import user_map
from upvote.gae.shared.common import utils
from upvote.shared import constants


class Error(Exception):
  """Module-level base Exception."""


class NotRunningLocally(Error):
  """Raised when calling a method that can only be used on local deployments."""


def EnsureCritialRules():
  """Pre-populates Datastore with any critical Rule entities."""
  for critical_hash in settings.CRITICAL_MAC_OS_CERT_HASHES:

    cert = santa.SantaCertificate.get_by_id(critical_hash)

    if not cert:
      cert = santa.SantaCertificate(
          id=critical_hash, id_type=constants.ID_TYPE.SHA256)
      cert.put()

    # Check for at least one matching SantaRule.
    rule_missing = santa.SantaRule.query(
        ancestor=cert.key).get(keys_only=True) is None

    # Doesn't exist? Add it!
    if rule_missing:
      santa.SantaRule(
          parent=cert.key,
          rule_type=constants.RULE_TYPE.CERTIFICATE,
          policy=constants.RULE_POLICY.WHITELIST).put()


def CreateTestEntities(email_addr):
  """Create some test Datastore data if specified, but only if running locally.

  Note that this code doesn't (and shouldn't) delete any existing entities.
  The risk of such code being accidentally triggered in prod is too great, so
  if local entities need to be deleted, use the local Datastore viewer (e.g.
  http://127.0.0.1:8000/datastore).

  Args:
    email_addr: Email address of the local users for whom test data should
        be created.

  Raises:
    NotRunningLocally: if called anywhere other than a local deployment.
  """
  if not utils.RunningLocally():
    raise NotRunningLocally

  # Create a user entity with all available roles.
  user = base.User.GetOrInsert(email_addr=email_addr)
  base.User.SetRoles(email_addr, constants.USER_ROLE.SET_ALL)

  username = user_map.EmailToUsername(email_addr)

  # Create associated SantaHosts for the user.
  santa_hosts = test_utils.CreateSantaHosts(2, primary_user=username)

  # For each SantaHost, create some SantaEvents.
  for santa_host in santa_hosts:
    for santa_blockable in test_utils.CreateSantaBlockables(5):

      parent_key = model_utils.ConcatenateKeys(
          user.key, santa_host.key, santa_blockable.key)
      test_utils.CreateSantaEvent(
          santa_blockable,
          executing_user=username,
          event_type=constants.EVENT_TYPE.BLOCK_BINARY,
          host_id=santa_host.key.id(),
          parent=parent_key)

  # Create associated Bit9Hosts for the user.
  bit9_hosts = test_utils.CreateBit9Hosts(2, users=[username])

  # For each Bit9Host, create some Bit9Events.
  for bit9_host in bit9_hosts:
    for bit9_binary in test_utils.CreateBit9Binaries(5):

      parent_key = model_utils.ConcatenateKeys(
          user.key, bit9_host.key, bit9_binary.key)
      test_utils.CreateBit9Event(
          bit9_binary,
          executing_user=username,
          event_type=constants.EVENT_TYPE.BLOCK_BINARY,
          host_id=bit9_host.key.id(),
          parent=parent_key)

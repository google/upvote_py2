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

"""Model definitions for the various hosts Upvote interacts with."""

import datetime

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel
from upvote.gae.datastore.models import mixin
from upvote.shared import constants


class Host(mixin.Base, polymodel.PolyModel):
  """A device running client software and has interacted with Upvote.

  key = Device UUID reported by client.

  Attributes:
    hostname: str, the hostname at last preflight.
    recorded_dt: datetime, time of insertion.
    hidden: boolean, whether the host will be hidden from the user by default.
  """
  hostname = ndb.StringProperty()
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)
  hidden = ndb.BooleanProperty(default=False)

  @staticmethod
  def NormalizeId(host_id):
    return host_id.upper()


class Bit9Host(mixin.Bit9, Host):
  """A Host in Bit9.

  Corresponds to Bit9's "computer" object.

  key = The **string** id of the Bit9 computer object

  Attributes:
    last_event_dt: datetime, The time of the last event blocked on the host.
    policy_key: Key, The policy currently applied to this host.
    users: list<str>, The list of **usernames** associated with this host.
  """
  last_event_dt = ndb.DateTimeProperty(
      default=datetime.datetime.utcfromtimestamp(0))
  policy_key = ndb.KeyProperty()
  users = ndb.StringProperty(repeated=True)

  @classmethod
  @ndb.transactional
  def ChangePolicyKey(cls, host_id, new_policy_key):
    host = cls.get_by_id(host_id)
    host.policy_key = new_policy_key
    host.put()

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    result = super(Bit9Host, self).to_dict(include=include, exclude=exclude)

    if self.policy_key:
      policy = self.policy_key.get()
      result['policy_enforcement_level'] = policy.enforcement_level
    return result


class SantaHost(mixin.Santa, Host):
  """A host running Santa that has interacted with Upvote.

  key = Mac Hardware UUID

  Attributes:
    serial_num: str, the hardware serial number.
    primary_user: str, the primary user of the machine.
    santa_version: str, the version of Santa at last preflight.
    os_version: str, OS version at last preflight.
    os_build: str, OS build at last preflight.
    last_preflight_dt: date, date of last preflight.
    last_preflight_ip: str, IP during last preflight.
    last_postflight_dt: date, date of last postflight.
    client_mode: str, the mode Santa should be running in on this host.
    client_mode_lock: bool, True if role-based mode setting should be ignored.

    directory_whitelist_regex: str, binaries run from paths matched with this
        regex will be allowed to run.
    directory_blacklist_regex: str, binaries run from paths matched with this
        regex will be blocked from running.
    rule_sync_dt: dt, when last sync occurred with RuleDownload.
  """
  serial_num = ndb.StringProperty()
  primary_user = ndb.StringProperty()
  santa_version = ndb.StringProperty()
  os_version = ndb.StringProperty()
  os_build = ndb.StringProperty()
  last_preflight_dt = ndb.DateTimeProperty()
  last_preflight_ip = ndb.StringProperty()
  last_postflight_dt = ndb.DateTimeProperty()
  client_mode = ndb.StringProperty(
      choices=constants.CLIENT_MODE.SET_ALL,
      default=constants.CLIENT_MODE.LOCKDOWN)

  client_mode_lock = ndb.BooleanProperty(default=False)

  directory_whitelist_regex = ndb.StringProperty()
  directory_blacklist_regex = ndb.StringProperty()

  transitive_whitelisting_enabled = ndb.BooleanProperty(default=False)

  rule_sync_dt = ndb.DateTimeProperty()

  @property
  def host_id(self):
    return self.key.id()

  @classmethod
  @ndb.transactional
  def ChangeClientMode(cls, host_id, new_client_mode):
    host = cls.get_by_id(host_id)
    host.client_mode_lock = True
    host.client_mode = new_client_mode
    host.put()

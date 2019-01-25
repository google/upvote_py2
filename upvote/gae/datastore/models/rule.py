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

"""Models for storing all of Upvote's enforcement rules."""

import datetime

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import mixin
from upvote.gae.utils import user_utils
from upvote.shared import constants


# Done for the sake of brevity.
LOCAL = constants.RULE_SCOPE.LOCAL
GLOBAL = constants.RULE_SCOPE.GLOBAL


class Rule(mixin.Base, polymodel.PolyModel):
  """A rule generated from voting or manually inserted by an authorized user.

  Attributes:
    rule_type: string, the type of blockable the rule applies to, ie
        binary, certificate.
    policy: string, the assertion of the rule, ie whitelisted, blacklisted.
    in_effect: bool, is this rule still in effect. Set to False when superceded.
    recorded_dt: datetime, insertion time.
    host_id: str, id of the host or blank for global.
    user_key: key, for locally scoped rules, the user for whom the rule was
        created.
  """
  rule_type = ndb.StringProperty(
      choices=constants.RULE_TYPE.SET_ALL, required=True)
  policy = ndb.StringProperty(
      choices=constants.RULE_POLICY.SET_ALL, required=True)
  in_effect = ndb.BooleanProperty(default=True)
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)
  updated_dt = ndb.DateTimeProperty(auto_now=True)
  host_id = ndb.StringProperty(default='')
  user_key = ndb.KeyProperty()

  def MarkDisabled(self):
    self.in_effect = False

  def InsertBigQueryRow(self, **kwargs):

    user = None
    if self.user_key:
      user = user_utils.EmailToUsername(self.user_key.id())

    defaults = {
        'sha256': self.key.parent().id(),
        'timestamp': datetime.datetime.utcnow(),
        'scope': LOCAL if self.host_id or self.user_key else GLOBAL,
        'policy': self.policy,
        'target_type': self.rule_type,
        'device_id': self.host_id if self.host_id else None,
        'user': user}
    defaults.update(kwargs.copy())

    tables.RULE.InsertRow(**defaults)


class Bit9Rule(mixin.Bit9, Rule):
  """A rule dictating a certain policy should be applied to a blockable.

  Attributes:
    is_committed: bool, Whether the policy has been committed to Bit9.
    is_fulfilled: bool, Whether the local policy was fulfilled by Bit9.
        If not, the specific host has no fileInstance entity associated with
        the associated blockable (i.e. the host has never seen it before) so
        local whitelisting is impossible. It can become fulfilled in the future
        if the blockable is run on the host.
        This field is only meaningful for local rules when is_committed is True.
  """
  is_committed = ndb.BooleanProperty(default=False)
  is_fulfilled = ndb.BooleanProperty()


class SantaRule(mixin.Santa, Rule):
  """Represents a Rule that should be downloaded by Santa clients.

  Attributes:
    custom_msg: str, a custom message to show when the rule is activated.
  """
  policy = ndb.StringProperty(
      choices=constants.RULE_POLICY.SET_SANTA, required=True)
  custom_msg = ndb.StringProperty(default='', indexed=False)

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
  """A Rule specific to the Bit9 client..

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


class RuleChangeSet(ndb.Model):
  """A group of rules to be committed to Bit9's DB.

  While Rule.policy provides the same type of field to change_type, change_type
  is included here so that the underlying Rule policies can change or Rule(s)
  can be marked in_effect=False and the RuleChangeSet entities can still be
  committed to the DB accurately and in-order.

  Attributes:
    blockable_key: Key, The key of the blockable for which the change set
        applies. This allows distinct projection queries for all Blockables with
        outstanding change sets.
    rule_keys: list<Key>, The list of rule keys to be modified by this change.
    change_type: RULE_POLICY, The change in policy that should be applied to the
        provided rules.
    recorded_dt: datetime, The time at which this entity was created.
  """

  def _GetBlockableKey(self):
    if self.key is None:
      raise ValueError('Parent must be provided.')
    blockable_key = self.key.parent()
    # If self.key is not None, self.key should be at least 2 pairs long.
    assert blockable_key is not None
    if blockable_key.kind() != 'Blockable':
      raise ValueError('Parent must be a Blockable key.')
    return blockable_key

  blockable_key = ndb.ComputedProperty(_GetBlockableKey)
  rule_keys = ndb.KeyProperty(repeated=True)
  change_type = ndb.StringProperty(choices=constants.RULE_POLICY.SET_BIT9)
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)


class SantaRule(mixin.Santa, Rule):
  """A Rule specific to the Santa client.

  Attributes:
    custom_msg: str, a custom message to show when the rule is activated.
  """
  policy = ndb.StringProperty(
      choices=constants.RULE_POLICY.SET_SANTA, required=True)
  custom_msg = ndb.StringProperty(default='', indexed=False)

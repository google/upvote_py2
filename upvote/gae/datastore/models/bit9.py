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

"""Models specific to Bit9."""

import datetime
import logging

from google.appengine.ext import ndb

from common.cloud_kms import kms_ndb
from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import mixin
from upvote.gae.datastore.models import singleton
from upvote.shared import constants

_KEY_LOC = 'global'
_KEY_RING = 'ring'
_KEY_NAME = 'bit9'


class Bit9ApiAuth(singleton.Singleton):
  """The Bit9 API key.

  This class is intended to be a singleton as there should only be a single
  Bit9 API key associated with a project.
  """
  api_key = kms_ndb.EncryptedBlobProperty(_KEY_NAME, _KEY_RING, _KEY_LOC)


class Bit9Policy(mixin.Bit9, ndb.Model):
  """A Host policy in Bit9.

  Corresponds to Bit9's "policy" object.

  key = The **string** id of the Bit9 policy object

  Attributes:
    name: str, The name of the policy.
    enforcement_level: BIT9_ENFORCEMENT_LEVEL, The 'target enforcement level'
        (i.e. strictness) associated with the policy. More restrictive policies
        have 'higher' enforcement levels.
    updated_dt: datetime, The time the policy was modified last.
  """
  name = ndb.StringProperty()
  enforcement_level = ndb.StringProperty(
      choices=constants.BIT9_ENFORCEMENT_LEVEL.SET_ALL)
  updated_dt = ndb.DateTimeProperty(auto_now=True)


class Bit9Host(mixin.Bit9, base.Host):
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
  def GetAssociatedHostIds(cls, user):
    """Returns the IDs of each host associated with the given user."""
    host_query = cls.query(cls.users == user.nickname)
    return [key.id() for key in host_query.fetch(keys_only=True)]

  def IsAssociatedWithUser(self, user):
    """Returns whether the given user is associated with this host."""
    return user.nickname in self.users

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    result = super(Bit9Host, self).to_dict(include=include, exclude=exclude)

    if self.policy_key:
      policy = self.policy_key.get()
      result['policy_enforcement_level'] = policy.enforcement_level
    return result


class Bit9Event(mixin.Bit9, base.Event):
  """An event from Bit9.

  Attributes:
    description: str, Description.
    is_anomalous: bool, Indicates whether an unfulfilled local rule existed
        prior to execution but wasn't in effect due to Bit9's local rule
        enforcement semantics.
    bit9_id: int, The largest Bit9 database ID associated with this event.
  """
  description = ndb.StringProperty()
  is_anomalous = ndb.BooleanProperty(default=False)
  bit9_id = ndb.IntegerProperty(default=0)

  @property
  def run_by_local_admin(self):
    return self.executing_user == constants.LOCAL_ADMIN.WINDOWS

  def _DedupeMoreRecentEvent(self, more_recent_event):
    """Updates if the related Event is more recent than the current one."""
    if self.bit9_id > more_recent_event.bit9_id:
      logging.warning(
          'Database ID out-of-order with respect to event timestamp: '
          '(id=%s, dt=%s) occurred earlier than (id=%s, dt=%s)', self.bit9_id,
          self.last_blocked_dt, more_recent_event.bit9_id,
          more_recent_event.last_blocked_dt)

    super(Bit9Event, self)._DedupeMoreRecentEvent(more_recent_event)

    self.is_anomalous = more_recent_event.is_anomalous

  def Dedupe(self, related_event):
    """See base class."""
    super(Bit9Event, self).Dedupe(related_event)

    # We only care about the most recent event with respect to its ID in Bit9.
    self.bit9_id = max(self.bit9_id, related_event.bit9_id)


class Bit9Binary(mixin.Bit9, base.Binary):
  """A file that has been blocked by Bit9.

  key = hash of blockable

  Attributes:
    # Selected properties corresponding to "File Properties" section in Bit9
    # Parity console "File Instance Details" view.
    description: str, Description.
    file_type: str, File Type.
    first_seen_name: str, First seen name.
    first_seen_date: datetime, First seen date.
    first_seen_computer:str, First seen host.
    first_seen_path: str, First seen path.
    detected_installer: bool, Whether Bit9's heuristic marked the binary as an
        installer.
    is_installer: bool, The binary's prescribed installer state.
    md5: str, MD5.
    product_version: str, Product version.
    sha1: str, SHA-1.
    company: str, Company associated with the file.
    file_size: int, File size, in bytes.
    file_catalog_id: str, The ID of the Bit9 fileCatalog entry corresponding to
        this blockable.
  """
  description = ndb.StringProperty()
  file_type = ndb.StringProperty()
  first_seen_name = ndb.StringProperty()
  first_seen_date = ndb.DateTimeProperty()
  first_seen_computer = ndb.StringProperty()
  first_seen_path = ndb.StringProperty()
  detected_installer = ndb.BooleanProperty(default=False)
  is_installer = ndb.BooleanProperty(default=False)

  md5 = ndb.StringProperty()
  product_version = ndb.StringProperty()
  sha1 = ndb.StringProperty()
  company = ndb.StringProperty()
  file_size = ndb.IntegerProperty()
  file_catalog_id = ndb.StringProperty()

  def PersistRow(self, action, timestamp=None):
    if timestamp is None:
      timestamp = datetime.datetime.now()
    tables.BINARY.InsertRow(
        sha256=self.key.id(),
        timestamp=timestamp,
        action=action,
        state=self.state,
        score=self.score,
        platform=self.GetPlatformName(),
        client=self.GetClientName(),
        first_seen_file_name=self.first_seen_name,
        cert_fingerprint=self.cert_id)

  def CalculateInstallerState(self):
    """Returns the blockable's installer state as prescribed by Upvote.

    NOTE: Due to the ancestor query, this method will not reflect changes within
    uncommitted transactions.

    Returns:
      The current installer state prescribed by Upvote.
    """
    # pylint: disable=g-explicit-bool-comparison
    query = Bit9Rule.query(
        Bit9Rule.in_effect == True,
        ndb.OR(
            Bit9Rule.policy == constants.RULE_POLICY.FORCE_INSTALLER,
            Bit9Rule.policy == constants.RULE_POLICY.FORCE_NOT_INSTALLER),
        ancestor=self.key
    ).order(-Bit9Rule.updated_dt)
    # pylint: enable=g-explicit-bool-comparison

    installer_rule = query.get()
    if installer_rule is None:
      return self.detected_installer
    else:
      return installer_rule.policy == constants.RULE_POLICY.FORCE_INSTALLER


class Bit9Certificate(mixin.Bit9, base.Certificate):
  """A certificate used to codesign at least one SantaBlockable.

  key = SHA-256 hash of certificate

  Attributes:
    valid_from_dt: date, datetime that cert is valid from.
    valid_until_dt: date, datetime that cert is valid until.
    parent_certificate_thumbprint: str, Thumbprint of parent certificate.
  """
  valid_from_dt = ndb.DateTimeProperty()
  valid_to_dt = ndb.DateTimeProperty()
  parent_certificate_thumbprint = ndb.StringProperty()

  def PersistRow(self, action, timestamp=None):
    if timestamp is None:
      timestamp = datetime.datetime.now()
    tables.CERTIFICATE.InsertRow(
        fingerprint=self.key.id(),
        timestamp=timestamp,
        action=action,
        not_before=self.valid_from_dt,
        not_after=self.valid_to_dt,
        state=self.state,
        score=self.score,
        common_name='Unknown',
        organization='Unknown',
        organizational_unit='Unknown')


class Bit9Rule(mixin.Bit9, base.Rule):
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


class BanDescriptionNote(base.Note):
  """Description of why a binary was banned.

  Used to uniquely identify ban descriptions from other notes.
  """


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

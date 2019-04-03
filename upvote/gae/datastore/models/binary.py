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

"""Model definitions for Upvote."""
import datetime

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

from upvote.gae.bigquery import tables
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import mixin
from upvote.gae.datastore.models import note as note_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import vote as vote_models
from upvote.shared import constants


# Done for the sake of brevity.
_POLICY = constants.RULE_POLICY


class Error(Exception):
  """Base error for models."""


class InvalidArgumentError(Error):
  """The called function received an invalid argument."""


class Blockable(mixin.Base, polymodel.PolyModel):
  """An entity that has been blocked.

  key = id of blockable file

  Attributes:
    id_type: str, type of the id used as the key.
    blockable_hash: str, the hash of the blockable, may also be the id.
    file_name: str, name of the file this blockable represents.
    publisher: str, name of the publisher of the file.
    product_name: str, Product name.
    version: str, Product version.

    occurred_dt: datetime, when the blockable was first seen.
    updated_dt: datetime, when this blockable was last updated.
    recorded_dt: datetime, when this file was first seen.

    score: int, social-voting score for this blockable.

    flagged: bool, True if a user has flagged this file as potentially unsafe.

    notes: str[], list of notes attached to this blockable.
    state: str, state of this blockable
    state_change_dt: datetime, when the state of this blockable changed.
  """

  def _CalculateScore(self):
    # NOTE: Since the 'score' property is a ComputedProperty, it will
    # be re-computed before every put. Consequently, when a Blockable is put for
    # the first time, we won't see a pre-existing value for 'score'. Here, we
    # avoid the score calculation for newly-created Blockables as they shouldn't
    # have any Votes associated with them and, thus, should have a score of 0.
    if not datastore_utils.HasValue(self, 'score'):
      return 0

    tally = 0
    votes = self.GetVotes()
    for vote in votes:
      if vote.was_yes_vote:
        tally += vote.weight
      else:
        tally -= vote.weight
    return tally

  id_type = ndb.StringProperty(choices=constants.ID_TYPE.SET_ALL, required=True)
  blockable_hash = ndb.StringProperty()
  file_name = ndb.StringProperty()
  publisher = ndb.StringProperty()
  product_name = ndb.StringProperty()
  version = ndb.StringProperty()

  occurred_dt = ndb.DateTimeProperty()
  updated_dt = ndb.DateTimeProperty(auto_now=True)
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)

  flagged = ndb.BooleanProperty(default=False)

  notes = ndb.KeyProperty(kind=note_models.Note, repeated=True)
  state = ndb.StringProperty(
      choices=constants.STATE.SET_ALL,
      required=True,
      default=constants.STATE.UNTRUSTED)
  state_change_dt = ndb.DateTimeProperty(auto_now_add=True)

  score = ndb.ComputedProperty(_CalculateScore)

  def ChangeState(self, new_state):
    """Helper method for changing the state of this Blockable.

    Args:
      new_state: New state value to set.
    """
    self.state = new_state
    self.state_change_dt = datetime.datetime.utcnow()
    self.put()

    self.InsertBigQueryRow(
        constants.BLOCK_ACTION.STATE_CHANGE, timestamp=self.state_change_dt)

  def GetVotes(self):
    """Queries for all Votes cast for this Blockable.

    Returns:
      A list of cast Votes.
    """
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    return vote_models.Vote.query(
        vote_models.Vote.in_effect == True, ancestor=self.key).fetch()
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison

  def GetEvents(self):
    """Retrieves all Events for this Blockable.

    Intended to help replace the need for the 'request' property of the
    models.BlockEvent class, since DB ReferenceProperties don't appear to exist
    in NDB.

    Returns:
      A list of all Event entities associated with this Blockable.
    """
    return event_models.Event.query(
        event_models.Event.blockable_key == self.key).fetch()

  def ResetState(self):
    """Resets blockable to UNTRUSTED with no votes."""
    self.state = constants.STATE.UNTRUSTED
    self.state_change_dt = datetime.datetime.utcnow()
    self.flagged = False
    self.put()

    self.InsertBigQueryRow(
        constants.BLOCK_ACTION.RESET, timestamp=self.state_change_dt)

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    if exclude is None: exclude = []
    exclude += ['score']
    result = super(Blockable, self).to_dict(include=include, exclude=exclude)

    # NOTE: This is not ideal but it prevents CalculateScore from being
    # called when serializing Blockables. This will return an inaccurate value
    # if a vote was cast after the Blockable was retrieved but this can be
    # avoided by wrapping the call to to_dict in a transaction.
    result['score'] = datastore_utils.GetLocalComputedPropertyValue(
        self, 'score')

    return result

  @classmethod
  def get_by_id(cls, blockable_id, **kwargs):
    if isinstance(blockable_id, str):
      blockable_id = blockable_id.lower()
    return super(Blockable, cls).get_by_id(blockable_id, **kwargs)

  def IsInstance(self, class_name):
    """Alternative to the built-in isinstance() function.

    Determines class heredity without requiring the caller to import the
    specific Model subclass being tested for, which has been a repeated source
    of circular build dependencies due to the tight coupling of some of Upvote's
    Datastore Models.

    Args:
      class_name: str, The name of the class we're looking for.

    Returns:
      Whether this Blockable has the given class name in its ancestry.
    """
    class_names = set(c.lower() for c in self._class_key())
    return class_name.lower() in class_names


class Binary(Blockable):
  """A binary to be blocked.

  Attributes:
    cert_key: The Key to the Certificate entity of the binary's signing cert.
  """
  cert_key = ndb.KeyProperty()

  @property
  def rule_type(self):
    return constants.RULE_TYPE.BINARY

  @property
  def cert_id(self):
    return self.cert_key and self.cert_key.id()

  @classmethod
  def TranslatePropertyQuery(cls, field, value):
    if field == 'cert_id':
      if value:
        cert_key = ndb.Key('Certificate', value).urlsafe()
      else:
        cert_key = None
      return 'cert_key', cert_key
    return field, value

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    result = super(Binary, self).to_dict(include=include, exclude=exclude)
    result['cert_id'] = self.cert_id
    return result

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {
        'sha256': self.key.id(),
        'timestamp': datetime.datetime.utcnow(),
        'action': action,
        'state': self.state,
        'score': self.score,
        'platform': self.GetPlatformName(),
        'client': self.GetClientName(),
        'first_seen_file_name': self.file_name,
        'cert_fingerprint': self.cert_id}
    defaults.update(kwargs.copy())

    tables.BINARY.InsertRow(**defaults)


class Bit9Binary(mixin.Bit9, Binary):
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

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {'first_seen_file_name': self.first_seen_name}
    defaults.update(kwargs.copy())

    super(Bit9Binary, self).InsertBigQueryRow(action, **defaults)

  def CalculateInstallerState(self):
    """Returns the blockable's installer state as prescribed by Upvote.

    NOTE: Due to the ancestor query, this method will not reflect changes within
    uncommitted transactions.

    Returns:
      The current installer state prescribed by Upvote.
    """
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    query = rule_models.Bit9Rule.query(
        rule_models.Bit9Rule.in_effect == True,
        ndb.OR(
            rule_models.Bit9Rule.policy == _POLICY.FORCE_INSTALLER,
            rule_models.Bit9Rule.policy == _POLICY.FORCE_NOT_INSTALLER),
        ancestor=self.key
    ).order(-rule_models.Bit9Rule.updated_dt)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison

    installer_rule = query.get()
    if installer_rule is None:
      return self.detected_installer
    else:
      return installer_rule.policy == _POLICY.FORCE_INSTALLER


class SantaBlockable(mixin.Santa, Binary):
  """An binary that has been blocked by Santa.

  key = hash of blockable

  Attributes:
    bundle_id: str, CFBundleIdentifier. The enclosing bundle's unique
        identifier.
    cert_sha256: str, SHA-256 of the codesigning cert, if any.
  """
  bundle_id = ndb.StringProperty()

  # DEPRECATED
  cert_sha256 = ndb.StringProperty()  # Use binary_models.Binary.cert_key

  @property
  def cert_id(self):
    return (self.cert_key and self.cert_key.id()) or self.cert_sha256

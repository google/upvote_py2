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

"""Models for storing state of user-requested lockdown exemptions."""

import logging

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel
from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import mixin
from upvote.shared import constants


class Error(Exception):
  """Base error class for the module."""


class AlreadyExistsError(Error):
  """Raised when attempting to create a second Exemption entity for a host."""


class InvalidExemptionError(Error):
  """Raised when attempting an operation on an Exemption that doesn't exist."""


class InvalidStateChangeError(Error):
  """Raised when attempting to change an Exemption to an invalid state."""


class UnknownPlatformError(Error):
  """Raised if the platform of an Exemption cannot be determined."""


class Record(ndb.Model):
  """A record in an exemptions history.

  Describes an event that changes the state of an exemption

  Attributes:
    datetime: datetime, The time the event happened that issued this record
    state: str, The ending state of the exemption
    details: list<str>, a list of strings that can justify the change
  """
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)
  state = ndb.StringProperty(
      choices=constants.EXEMPTION_STATE.SET_ALL, required=True)
  details = ndb.StringProperty(repeated=True)


class Exemption(mixin.Base, polymodel.PolyModel):
  """An execution exemption.

  Attributes:
    creation_dt: datetime, time the Exemption was created.
    deactivation_dt: datetime, time the Exemption was deactivated.
    state: str, the current Exemption state.
    history: list<Record>, history of changes and the details of those changes.
  """
  creation_dt = ndb.DateTimeProperty(auto_now_add=True)
  deactivation_dt = ndb.DateTimeProperty(required=True)
  state = ndb.StringProperty(
      choices=constants.EXEMPTION_STATE.SET_ALL,
      default=constants.EXEMPTION_STATE.REQUESTED)
  history = ndb.LocalStructuredProperty(Record, repeated=True)

  def CanChangeToState(self, new_state):
    valid_states = constants.EXEMPTION_STATE.MAP_VALID_STATE_CHANGES[self.state]
    allowed = new_state in valid_states
    if not allowed:
      logging.warning(
          'Exemption for host %s cannot change state from %s to %s',
          self.key.parent().id(), self.state, new_state)
    return allowed

  @classmethod
  def CreateKey(cls, host_id):
    return ndb.Key(host_models.Host, host_id, cls, '1')

  @classmethod
  def Get(cls, host_id):
    return cls.CreateKey(host_id).get()

  @classmethod
  def Exists(cls, host_id):
    return cls.Get(host_id) is not None

  @classmethod
  def GetPlatform(cls, exm_key):
    host = exm_key.parent().get()
    platform = host.GetPlatformName()
    if platform not in constants.PLATFORM.SET_ALL:
      message = 'Host %s has an unknown platform: %s' % (
          host.key.id(), platform)
      raise UnknownPlatformError(message)
    return platform

  @classmethod
  def GetHostId(cls, exm_key):
    return exm_key.parent().id()

  @classmethod
  @ndb.transactional
  def Insert(cls, host_id, deactivation_dt, reason, other_text=None):
    """Inserts a new Exemption entity into Datastore.

    Args:
      host_id: The unique identifier of the host receiving the Exemption.
      deactivation_dt: The deactivation time of the Exemption.
      reason: The enumerated reason given for requesting the Exemption.
      other_text: The optional text provided when requesting the Exemption.

    Returns:
      The NDB Key of the newly-created Exemption.

    Raises:
      AlreadyExistsError: when attempting to create a second Exemption for a
          given host_id.
    """
    # Make sure that an Exemption doesn't already exist before calling put().
    if cls.Exists(host_id):
      raise AlreadyExistsError('Exemption already exists for host %s' % host_id)

    # Compose a new entity and persist it.
    exm_key = cls.CreateKey(host_id)
    details = [reason, other_text] if other_text else [reason]
    record = Record(state=constants.EXEMPTION_STATE.REQUESTED, details=details)
    exm = cls(key=exm_key, deactivation_dt=deactivation_dt, history=[record])
    exm.put()

    tables.EXEMPTION.InsertRow(
        device_id=host_id,
        timestamp=exm.history[0].recorded_dt,
        state=constants.EXEMPTION_STATE.REQUESTED,
        details=exm.history[0].details)

    return exm_key

  @classmethod
  @ndb.transactional
  def ChangeState(cls, exm_key, new_state, details=None):
    """Changes the state of a given Exemption.

    Args:
      exm_key: The NDB Key of the Exemption.
      new_state: The new state to transition to.
      details: A list of strings that can justify the change.

    Raises:
      InvalidExemptionError: If the Key doesn't correspond to an actual
          Exemption.
      InvalidStateChangeError: If the desired state cannot be transitioned to
          from the current state.
    """
    host_id = exm_key.parent().id()

    # Verify that we're trying to change state on a valid Exemption.
    exm = exm_key.get()
    if not exm:
      raise InvalidExemptionError('No Exemption exists for host %s' % host_id)

    # Verify that the desired state can be reached from the current state.
    if not exm.CanChangeToState(new_state):
      raise InvalidStateChangeError('%s to %s' % (exm.state, new_state))

    if details is None:
      details = []

    logging.info(
        'Exemption for host %s changing state from %s to %s', host_id,
        exm.state, new_state)
    exm.state = new_state
    exm.history.append(Record(state=new_state, details=details))
    exm.put()

    tables.EXEMPTION.InsertRow(
        device_id=host_id,
        timestamp=exm.history[-1].recorded_dt,
        state=new_state,
        details=details)

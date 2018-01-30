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

"""Models definitions for Upvote tickets."""

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

from upvote.gae.shared.models import base
from upvote.shared import constants


class Ticket(base.BaseModelMixin, polymodel.PolyModel):
  """An Upvote ticket.

  Attributes:
    ticket_id: str, The numeric ticket ID.
    recorded_dt: datetime, when this item was inserted.
    is_open: bool, whether this ticket is still active.
  """
  ticket_id = ndb.StringProperty()
  recorded_dt = ndb.DateTimeProperty(auto_now_add=True)
  is_open = ndb.BooleanProperty(default=True)


class HostExceptionTicket(Ticket):
  """A ticket requesting an exception for a given host.

  Attributes:
    user_id: str, email of the user requesting the exception.
    host_id: str, ID of the host for which the exception is being requested.
    reason: str, the justification for why the exception was requested.
    other_test: str, when reason is OTHER, this field contains a plain english
        justification for why the exception was requested.
  """
  user_id = ndb.StringProperty()
  host_id = ndb.StringProperty()
  reason = ndb.StringProperty(choices=constants.HOST_EXEMPTION_REASON.SET_ALL)
  other_text = ndb.StringProperty(indexed=False)

  @classmethod
  def GetParentKey(cls, user_id, host_id):
    return ndb.Key('Host', host_id, 'User', user_id)

  @classmethod
  @ndb.transactional
  def get_open_or_insert_did_insert(cls, user_id, host_id, **kwargs):
    """Inserts or retrieves the HostExceptionTicket object.

    Args:
      user_id: str, user_id property of the ticket to insert/create.
      host_id: str, host_id property of the ticket to insert/create.
      **kwargs: dict, Any kwargs that should be passed to the constructor if the
          ticket is inserted.

    Returns:
      (HostExceptionTicket, bool), A 2-tuple of the newly-created or
          pre-existing model and a boolean representing whether the model
          was created.
    """
    parent_key = cls.GetParentKey(user_id, host_id)
    open_query = cls.query(cls.is_open == True, ancestor=parent_key)  # pylint: disable=g-explicit-bool-comparison
    ticket = open_query.get()
    exists = bool(ticket)
    if not exists:
      ticket = cls(user_id=user_id, host_id=host_id, parent=parent_key,
                   **kwargs)
      ticket.put()
    return ticket, not exists

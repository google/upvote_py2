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

"""Handlers related to Events."""
import httplib
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.ext import ndb

from upvote.gae.datastore import utils as model_utils
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import bit9 as bit9_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.web import base
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import user_map
from upvote.shared import constants


def _GetEventContext(events):
  """Adds relevant entities corresponding to the listed Events.

  The entities included (if present) are the Blockable run, the Certificate
  associated with run, the Host on which it was run, and the Vote cast by the
  user.

  Args:
    events: list of base.Events, The events for which context should be fetched.

  Returns:
    A list of dicts where each dict is of the form:
        {'event': Event, 'blockable': Blockable, 'cert': Certificate,
         'host': Host, 'vote': Vote}
    If any of the entities are not found (e.g. the user hasn't voted on a
    Blockable), that dict entry is present but set to None.
  """
  host_futures = ndb.get_multi_async(
      ndb.Key(base_models.Host, event.host_id) for event in events)

  # Fetch the entities associated with Event.blockable_key.
  blockable_futures = ndb.get_multi_async(
      event.blockable_key for event in events)
  vote_futures = ndb.get_multi_async(
      base_models.Vote.GetKey(event.blockable_key, event.user_key)
      for event in events)

  # Fetch the entities associated with SantaEvent.bundle_key.
  has_bundle = (
      lambda e: isinstance(e, santa_models.SantaEvent) and e.bundle_key)
  bundle_futures = [
      (event.bundle_key.get_async()
       if has_bundle(event) else model_utils.GetNoOpFuture())
      for event in events]
  bundle_vote_futures = [
      (base_models.Vote.GetKey(event.bundle_key, event.user_key).get_async()
       if has_bundle(event) else model_utils.GetNoOpFuture())
      for event in events]

  # Fetch the Certificate associated with the Event.
  cert_futures = []
  for event in events:
    if event.cert_key:
      cert_future = event.cert_key.get_async()
    elif isinstance(event, santa_models.SantaEvent) and event.cert_sha256:
      cert_future = ndb.Key(
          santa_models.SantaCertificate, event.cert_sha256).get_async()
    else:
      cert_future = model_utils.GetNoOpFuture()
    cert_futures.append(cert_future)

  # Merge all Event context entities into their associated dicts.
  events_with_context = []
  for i, event in enumerate(events):
    context_dict = {
        'event': event,
        'host': host_futures[i].get_result(),
    }
    bundle = bundle_futures[i].get_result()
    if bundle is None:
      context_dict.update({
          'blockable': blockable_futures[i].get_result(),
          'cert': cert_futures[i].get_result(),
          'vote': vote_futures[i].get_result(),
      })
    else:
      context_dict.update({
          'blockable': bundle,
          'cert': bundle.main_cert_key,
          'vote': bundle_vote_futures[i].get_result(),
      })
    events_with_context.append(context_dict)

  return events_with_context


class EventQueryHandler(base.BaseQueryHandler):
  """Handler for querying events."""

  MODEL_CLASS = base_models.Event

  @property
  def RequestCounter(self):
    return monitoring.event_requests

  @handlers.RecordRequest
  def get(self):
    # Determine whether Event should be returned with context.
    with_context = self.request.get('withContext').lower() == 'true'
    context_callback = _GetEventContext if with_context else None

    self._Query(context_callback)

  def _QueryModel(self, search_dict):
    # Add search keys provided as query params.
    urlsafe_key = self.request.get('blockableKey')
    if urlsafe_key:
      search_dict['blockableKey'] = urlsafe_key

    host_id = self.request.get('hostId')
    if host_id:
      search_dict['hostId'] = host_id

    # Determine scope of query and enforce ACL if queried as admin.
    if self.request.get('asAdmin').lower() == 'true':
      logging.info('Getting all events as Admin.')
      self.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_EVENTS)
      ancestor = None
    else:
      logging.info('Getting events for user: %s', self.user.nickname)
      ancestor = self.user.key

    query = super(EventQueryHandler, self)._QueryModel(
        search_dict, ancestor=ancestor)

    return query.order(-self.MODEL_CLASS.last_blocked_dt)


class Bit9EventQueryHandler(EventQueryHandler):

  MODEL_CLASS = bit9_models.Bit9Event


class SantaEventQueryHandler(EventQueryHandler):

  MODEL_CLASS = santa_models.SantaEvent


class EventHandler(base.BaseHandler):
  """Handler for interacting with individual events."""

  def get(self, event_key):  # pylint: disable=g-bad-name
    try:
      key = ndb.Key(urlsafe=event_key)
    # NOTE: There is an open bug related to the inconsistent errors
    # raised by the ndb.Key urlsafe constructor.
    # See https://github.com/googlecloudplatform/datastore-ndb-python/issues/143
    except:  # pylint: disable=bare-except
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Event key %s could not be parsed' % event_key)
    else:
      event = key.get()
      if event:
        with_context = (self.request.get('withContext').lower() == 'true')
        response_data = _GetEventContext([event])[0] if with_context else event
        if event.executing_user != self.user.nickname:
          self.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_EVENTS)
        self.respond_json(response_data)
      else:
        self.abort(httplib.NOT_FOUND, explanation='Event not found')


class RecentEventHandler(base.BaseHandler):
  """Handler for getting the most recent Event for a blockable, for a user."""

  def get(self, blockable_id):  # pylint: disable=g-bad-name
    blockable = base_models.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found')

    username = self.request.get('asUser')
    if username:
      self.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_EVENTS)
      user = user_models.User.GetById(user_map.UsernameToEmail(username))
    else:
      user = self.user

    # If the blockable is a bundle, search by the 'bundle_key' property instead
    # of 'blockable_key'.
    blockable_filter = (
        santa_models.SantaEvent.bundle_key == blockable.key
        if isinstance(blockable, santa_models.SantaBundle) else
        base_models.Event.blockable_key == blockable.key)

    event_query = (base_models.Event
                   .query(ancestor=user.key)
                   .filter(blockable_filter)
                   .order(-base_models.Event.last_blocked_dt))

    event = event_query.get()

    response_data = event
    if event:
      with_context = (self.request.get('withContext').lower() == 'true')
      response_data = _GetEventContext([event])[0] if with_context else event

    self.respond_json(response_data)


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/events', [
    webapp2.Route(
        '/most-recent/<blockable_id>',
        handler=RecentEventHandler),
    webapp2.Route(
        '/query/bit9',
        handler=Bit9EventQueryHandler),
    webapp2.Route(
        '/query/santa',
        handler=SantaEventQueryHandler),
    webapp2.Route(
        '/query',
        handler=EventQueryHandler),
    webapp2.Route(
        '/<event_key>',
        handler=EventHandler),
])

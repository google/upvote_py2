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

"""Views related to hosts."""
import datetime
import httplib
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.ext import ndb

from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import tickets as tickets_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.modules.upvote_app.api.web import monitoring
from upvote.gae.utils import handler_utils
from upvote.gae.utils import xsrf_utils
from upvote.shared import constants


class HostQueryHandler(handler_utils.UserFacingQueryHandler):
  """Handler for querying hosts."""

  MODEL_CLASS = host_models.Host

  @property
  def RequestCounter(self):
    return monitoring.host_requests

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)
  @handler_utils.RecordRequest
  def get(self):
    self._Query()


class SantaHostQueryHandler(HostQueryHandler):
  """Handler for querying santa hosts."""

  MODEL_CLASS = host_models.SantaHost


class HostHandler(handler_utils.UserFacingHandler):
  """Handler for interacting with specific hosts."""

  def get(self, host_id):
    host_id = host_models.Host.NormalizeId(host_id)
    logging.info('Host handler get method called with ID=%s.', host_id)
    host = host_models.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')
    elif not model_utils.IsHostAssociatedWithUser(host, self.user):
      self.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)
    self.respond_json(host)

  @handler_utils.RequireCapability(constants.PERMISSIONS.EDIT_HOSTS)
  @xsrf_utils.RequireToken
  def post(self, host_id):
    host_id = host_models.Host.NormalizeId(host_id)
    logging.info('Host handler post method called with ID=%s.', host_id)

    host = host_models.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')

    if self.request.get('clientMode'):
      host.client_mode = self.request.get('clientMode')
    if self.request.get('clientModeLock'):
      host.client_mode_lock = (self.request.get('clientModeLock') == 'true')
    if self.request.get('shouldUploadLogs'):
      host.should_upload_logs = (
          self.request.get('shouldUploadLogs') == 'true')

    host.put()

    self.respond_json(host)


class AssociatedHostHandler(handler_utils.UserFacingHandler):
  """Handler for interacting with specific hosts."""

  def _GetAssociatedHosts(self, user):
    host_keys = model_utils.GetHostKeysForUser(user)
    hosts = ndb.get_multi(host_keys)
    hosts = filter(None, hosts)

    # If Santa hosts have never synced rules or Bit9 hosts never reported an
    # event, push them to the end of the list.
    epoch = datetime.datetime.utcfromtimestamp(0)

    def ByFreshness(host):
      if isinstance(host, host_models.Bit9Host):
        return host.last_event_dt or epoch
      elif isinstance(host, host_models.SantaHost):
        return host.rule_sync_dt or epoch

    return sorted(hosts, key=ByFreshness, reverse=True)

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)
  def GetByUserId(self, user_id):
    logging.info('Getting associated Hosts for user_id=%s', user_id)
    user = user_models.User.GetById(user_id)
    if user is None:
      self.abort(httplib.NOT_FOUND, explanation='User not found')

    hosts = self._GetAssociatedHosts(user)
    self.respond_json(hosts)

  def GetSelf(self):
    logging.info('Getting associated Hosts for self (%s)', self.user.email)
    hosts = self._GetAssociatedHosts(self.user)
    self.respond_json(hosts)


class HostExceptionHandler(handler_utils.UserFacingHandler):
  """Handler for interacting with host exceptions."""

  def get(self, host_id):
    host_id = host_models.Host.NormalizeId(host_id)
    logging.info('Host exception handler GET called with ID=%s.', host_id)

    host = host_models.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if (not self.user.is_admin and
        not model_utils.IsHostAssociatedWithUser(host, self.user)):
      logging.warning(
          'Host exception for ID=%s queried by unauthorized user=%s.',
          host_id, self.user.email)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with requesting user')

    # Users are allowed to query for any ticket filed for a host with which they
    # are associated.
    user_id = self.request.get('user_id').lower() or self.user.email

    parent_key = tickets_models.HostExceptionTicket.GetParentKey(
        user_id, host_id)
    ticket = tickets_models.HostExceptionTicket.query(ancestor=parent_key).get()
    if not ticket:
      logging.error(
          'Host exception not found for ID=%s filed by user=%s.', host_id,
          user_id)
      self.abort(
          httplib.NOT_FOUND, explanation='Host exception ticket not found')

    self.respond_json(ticket)

  @handler_utils.RequireCapability(constants.PERMISSIONS.REQUEST_EXEMPTION)
  @xsrf_utils.RequireToken
  def post(self, host_id):
    host_id = host_models.Host.NormalizeId(host_id)
    logging.info('Host exception handler POST called with ID=%s.', host_id)

    host = host_models.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if not (self.user.is_admin or
            model_utils.IsHostAssociatedWithUser(host, self.user)):
      logging.error(
          'Host exception for ID=%s requested by unauthorized user=%s.',
          host_id, self.user.email)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with requesting user')

    # Extract and validate POST data fields
    reason = self.request.get('reason')
    other_text = self.request.get('otherText') or None
    if not reason:
      self.abort(httplib.BAD_REQUEST, explanation='No reason provided')
    elif reason not in constants.EXEMPTION_REASON.SET_ALL:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Invalid reason provided: %s' % reason)
    elif reason == constants.EXEMPTION_REASON.OTHER and not other_text:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='No explanation for "Other" reason provided')

    # Check if an outstanding request exists. If not, create one.
    ticket_model, inserted = (
        tickets_models.HostExceptionTicket.get_open_or_insert_did_insert(
            self.user.email, host_id, reason=reason, other_text=other_text,
            is_open=False))
    if not inserted:
      logging.warning(
          'Duplicate host exception ticket requested: requested='
          '(%s, %s, %s, %s) existing=%s', self.user.email, host_id, reason,
          other_text, ticket_model)
      self.abort(httplib.CONFLICT, explanation='Ticket already exists')

    # NOTE: THIS IS TEMPORARY!!! Remove when pilot is over.
    host.client_mode_lock = True
    host.client_mode = constants.SANTA_CLIENT_MODE.MONITOR
    host.put()

    tables.HOST.InsertRow(
        device_id=host_id,
        timestamp=host.last_postflight_dt,
        action=constants.HOST_ACTION.MODE_CHANGE,
        hostname=host.hostname,
        platform=constants.PLATFORM.MACOS,
        users=model_utils.GetUsersAssociatedWithSantaHost(host_id),
        mode=host.client_mode)

    self.respond_json(host)


class LockdownHandler(handler_utils.UserFacingHandler):
  """Handler for enrolling a host in Lockdown."""

  @xsrf_utils.RequireToken
  def post(self, host_id):
    host_id = host_models.Host.NormalizeId(host_id)
    logging.info('Lockdown handler POST called with ID=%s.', host_id)

    host = host_models.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if not (self.user.is_admin or
            model_utils.IsHostAssociatedWithUser(host, self.user)):
      logging.error(
          'Lockdown for ID=%s requested by unauthorized user=%s.',
          host_id, self.user.email)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with requesting user')

    host.client_mode_lock = True
    host.client_mode = constants.SANTA_CLIENT_MODE.LOCKDOWN
    host.put()

    tables.HOST.InsertRow(
        device_id=host_id,
        timestamp=host.last_postflight_dt,
        action=constants.HOST_ACTION.MODE_CHANGE,
        hostname=host.hostname,
        platform=constants.PLATFORM.MACOS,
        users=model_utils.GetUsersAssociatedWithSantaHost(host_id),
        mode=host.client_mode)

    self.respond_json(host)


class VisibilityHandler(handler_utils.UserFacingHandler):
  """Handler for changing the hidden attribute of a host."""

  @xsrf_utils.RequireToken
  def put(self, host_id, hidden):
    host_id = host_models.Host.NormalizeId(host_id)

    host = host_models.Host.get_by_id(host_id)
    if not host:
      self.abort(httplib.NOT_FOUND, explanation='Host %s not found' % host_id)

    if not model_utils.IsHostAssociatedWithUser(host, self.user):
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host %s not associated with user %s' % (
              host_id, self.user.email))

    hidden = hidden.lower()
    if hidden != 'true' and hidden != 'false':
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Required hidden parameter \'true\' or \'false\'')

    host.hidden = hidden == 'true'
    host.put()


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/hosts', [
    webapp2.Route(
        '/associated/<user_id>',
        handler=AssociatedHostHandler,
        handler_method='GetByUserId',
        methods=['GET']),
    webapp2.Route(
        '/associated',
        handler=AssociatedHostHandler,
        handler_method='GetSelf',
        methods=['GET']),
    webapp2.Route(
        '/query/santa',
        handler=SantaHostQueryHandler),
    webapp2.Route(
        '/query',
        handler=HostQueryHandler),
    webapp2.Route(
        '/<host_id>/request-exception',
        handler=HostExceptionHandler),
    webapp2.Route(
        '/<host_id>/request-lockdown',
        handler=LockdownHandler,
        methods=['POST']),
    webapp2.Route(
        '/<host_id>',
        handler=HostHandler),
    webapp2.Route(
        '/<host_id>/hidden/<hidden>',
        handler=VisibilityHandler),
])

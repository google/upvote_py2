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

from google.appengine.ext import ndb

from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.handlers import base
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import xsrf_utils
from upvote.gae.shared.models import base as base_db
from upvote.gae.shared.models import bigquery as bigquery_db
from upvote.gae.shared.models import bit9 as bit9_db
from upvote.gae.shared.models import santa as santa_db
from upvote.gae.shared.models import tickets as tickets_db
from upvote.shared import constants


class HostQueryHandler(base.BaseQueryHandler):
  """Handler for querying hosts."""

  MODEL_CLASS = base_db.Host

  @property
  def RequestCounter(self):
    return monitoring.host_requests

  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)
  @handlers.RecordRequest
  def get(self):
    self._Query()


class SantaHostQueryHandler(HostQueryHandler):
  """Handler for querying santa hosts."""

  MODEL_CLASS = santa_db.SantaHost


class HostHandler(base.BaseHandler):
  """Handler for interacting with specific hosts."""

  def get(self, host_id):
    host_id = base_db.Host.NormalizeId(host_id)
    logging.debug('Host handler get method called with ID=%s.', host_id)
    host = base_db.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')
    elif not host.IsAssociatedWithUser(self.user):
      self.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)
    self.respond_json(host)

  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)
  @xsrf_utils.RequireToken
  def post(self, host_id):
    host_id = base_db.Host.NormalizeId(host_id)
    logging.debug('Host handler post method called with ID=%s.', host_id)

    host = base_db.Host.get_by_id(host_id)
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


class AssociatedHostHandler(base.BaseHandler):
  """Handler for interacting with specific hosts."""

  def _GetAssociatedHosts(self, user):
    bit9_ids = bit9_db.Bit9Host.GetAssociatedHostIds(user)
    santa_ids = santa_db.SantaHost.GetAssociatedHostIds(user)
    host_ids = bit9_ids + santa_ids
    hosts = ndb.get_multi(
        ndb.Key(base_db.Host, host_id) for host_id in host_ids)
    hosts = filter(None, hosts)

    # If Santa hosts have never synced rules or Bit9 hosts never reported an
    # event, push them to the end of the list.
    epoch = datetime.datetime.utcfromtimestamp(0)

    def ByFreshness(host):
      if isinstance(host, bit9_db.Bit9Host):
        return host.last_event_dt or epoch
      elif isinstance(host, santa_db.SantaHost):
        return host.rule_sync_dt or epoch

    return sorted(hosts, key=ByFreshness, reverse=True)

  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)
  def GetByUserId(self, user_id):
    logging.debug('Getting associated Hosts for user_id=%s', user_id)
    user = base_db.User.GetById(user_id)
    if user is None:
      self.abort(httplib.NOT_FOUND, explanation='User not found')

    hosts = self._GetAssociatedHosts(user)
    self.respond_json(hosts)

  def GetSelf(self):
    logging.debug('Getting associated Hosts for self (%s)', self.user.email)
    hosts = self._GetAssociatedHosts(self.user)
    self.respond_json(hosts)


class HostExceptionHandler(base.BaseHandler):
  """Handler for interacting with host exceptions."""

  def get(self, host_id):
    host_id = base_db.Host.NormalizeId(host_id)
    logging.debug('Host exception handler GET called with ID=%s.', host_id)

    host = base_db.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if (not self.user.is_admin and
        not host.IsAssociatedWithUser(self.user)):
      logging.warning(
          'Host exception for ID=%s queried by unauthorized user=%s.',
          host_id, self.user.email)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with requesting user')

    # Users are allowed to query for any ticket filed for a host with which they
    # are associated.
    user_id = self.request.get('user_id').lower() or self.user.email

    parent_key = tickets_db.HostExceptionTicket.GetParentKey(user_id, host_id)
    ticket = tickets_db.HostExceptionTicket.query(ancestor=parent_key).get()
    if not ticket:
      logging.error(
          'Host exception not found for ID=%s filed by user=%s.', host_id,
          user_id)
      self.abort(
          httplib.NOT_FOUND, explanation='Host exception ticket not found')

    self.respond_json(ticket)

  @base.RequireCapability(constants.PERMISSIONS.REQUEST_HOST_EXEMPTION)
  @xsrf_utils.RequireToken
  def post(self, host_id):
    host_id = base_db.Host.NormalizeId(host_id)
    logging.debug('Host exception handler POST called with ID=%s.', host_id)

    host = base_db.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if not (self.user.is_admin or host.IsAssociatedWithUser(self.user)):
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
    elif reason not in constants.HOST_EXEMPTION_REASON.SET_ALL:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Invalid reason provided: %s' % reason)
    elif reason == constants.HOST_EXEMPTION_REASON.OTHER and not other_text:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='No explanation for "Other" reason provided')

    # Check if an outstanding request exists. If not, create one.
    ticket_model, inserted = (
        tickets_db.HostExceptionTicket.get_open_or_insert_did_insert(
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

    bigquery_db.HostRow.DeferCreate(
        device_id=host_id,
        timestamp=host.last_postflight_dt,
        action=constants.HOST_ACTION.MODE_CHANGE,
        hostname=host.hostname,
        platform=constants.PLATFORM.MACOS,
        users=santa_db.SantaHost.GetAssociatedUsers(host_id),
        mode=host.client_mode)

    self.respond_json(host)


class LockdownHandler(base.BaseHandler):
  """Handler for enrolling a host in Lockdown."""

  @xsrf_utils.RequireToken
  def post(self, host_id):
    host_id = base_db.Host.NormalizeId(host_id)
    logging.debug('Lockdown handler POST called with ID=%s.', host_id)

    host = base_db.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if not (self.user.is_admin or host.IsAssociatedWithUser(self.user)):
      logging.error(
          'Lockdown for ID=%s requested by unauthorized user=%s.',
          host_id, self.user.email)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with requesting user')

    host.client_mode_lock = True
    host.client_mode = constants.SANTA_CLIENT_MODE.LOCKDOWN
    host.put()

    bigquery_db.HostRow.DeferCreate(
        device_id=host_id,
        timestamp=host.last_postflight_dt,
        action=constants.HOST_ACTION.MODE_CHANGE,
        hostname=host.hostname,
        platform=constants.PLATFORM.MACOS,
        users=santa_db.SantaHost.GetAssociatedUsers(host_id),
        mode=host.client_mode)

    self.respond_json(host)


class HostEventRateHandler(base.BaseHandler):
  """Handler for calculating the rate of events a given host encounters."""

  def get(self, host_id):  # pylint: disable=g-bad-name
    host_id = base_db.Host.NormalizeId(host_id)
    host = base_db.Host.get_by_id(host_id)
    if host is None:
      self.abort(httplib.NOT_FOUND, explanation='Host not found')
    elif not host.IsAssociatedWithUser(self.user):
      self.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_HOSTS)

    # We choose 70 days so that there are exactly 50.0 workdays.
    duration_to_fetch = datetime.timedelta(days=70)
    was_max, block_rate = host.GetUserBlockRate(
        self.user, duration_to_fetch=duration_to_fetch)
    self.respond_json({
        'at_max': was_max,
        'avg_rate': block_rate})


class VisibilityHandler(base.BaseHandler):
  """Handler for changing the hidden attribute of a host."""

  @xsrf_utils.RequireToken
  def put(self, host_id, hidden):
    host_id = base_db.Host.NormalizeId(host_id)

    host = base_db.Host.get_by_id(host_id)
    if not host:
      self.abort(httplib.NOT_FOUND, explanation='Host %s not found' % host_id)

    if not host.IsAssociatedWithUser(self.user):
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

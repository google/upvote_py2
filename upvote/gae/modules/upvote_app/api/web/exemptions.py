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

"""Handlers related to exemptions."""

import httplib
import logging

import webapp2
from webapp2_extras import routes

from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.lib.exemption import api as exemption_api
from upvote.gae.utils import handler_utils
from upvote.gae.utils import xsrf_utils
from upvote.shared import constants


class ExemptionHandler(handler_utils.UserFacingHandler):
  """Base class for all Exemption-related handlers."""

  def dispatch(self):

    # All handlers require a host_id, so make sure one was provided.
    host_id = self.request.route_kwargs.get('host_id')
    if not host_id:
      self.abort(httplib.BAD_REQUEST, explanation='No host ID provided')

    # Retrieve the corresponding Host entity. Bail if it doesn't exist.
    host_id = host_models.Host.NormalizeId(host_id)
    self.host = host_models.Host.get_by_id(host_id)
    if self.host is None:
      message = 'Host %s does not exist' % host_id
      logging.error(message)
      self.abort(httplib.NOT_FOUND, explanation=message)

    # Make sure the Host has a valid platform, otherwise things will break.
    platform = self.host.GetPlatformName()
    if platform not in constants.PLATFORM.SET_ALL:
      message = 'Platform "%s" is not supported' % platform
      logging.error(message)
      self.abort(httplib.NOT_IMPLEMENTED, explanation=message)

    # Disable all Exemption-related requests for Windows hosts until that
    # platform is fully supported.
    if platform == constants.PLATFORM.WINDOWS:
      message = 'Windows is not currently supported'
      logging.error(message)
      self.abort(httplib.NOT_IMPLEMENTED, explanation=message)

    # Load the Exemption entity for use within the handlers. It's possible that
    # one doesn't yet exist.
    self.exm = exemption_models.Exemption.Get(host_id)

    # Pass the normalized host_id on to the handlers.
    self.request.route_kwargs['host_id'] = host_id

    super(ExemptionHandler, self).dispatch()

  def _RespondWithExemptionAndTransitiveState(self, exm_key):
    """Responds with an Exemption and transitive status (if applicable)."""
    response_dict = {'exemption': exm_key.get()}
    host = self.host.key.get()
    if host.GetPlatformName() == constants.PLATFORM.MACOS:
      response_dict['transitiveWhitelistingEnabled'] = (
          host.transitive_whitelisting_enabled)
    self.respond_json(response_dict)


class GetExemptionHandler(ExemptionHandler):
  """Handler for retrieving Exemptions."""

  def get(self, host_id):

    logging.info('Retrieving Exemption for host %s', host_id)

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if not (self.user.is_admin or
            model_utils.IsHostAssociatedWithUser(self.host, self.user)):
      logging.warning(
          'User %s is not authorized to access Exemption for host %s',
          self.user.nickname, host_id)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with user %s' % self.user.nickname)

    if self.exm is None:
      self.abort(httplib.NOT_FOUND, explanation='Exemption not found')

    self.respond_json(self.exm)


class RequestExemptionHandler(ExemptionHandler):
  """Handler for requesting host exemptions."""

  @handler_utils.RequireCapability(constants.PERMISSIONS.REQUEST_EXEMPTION)
  @xsrf_utils.RequireToken
  def post(self, host_id):

    # This request should only be available to admins or users who have (at
    # least at one time) had control of the host.
    if not (self.user.is_admin or
            model_utils.IsHostAssociatedWithUser(self.host, self.user)):
      logging.warning(
          'User %s is not authorized to request an Exemption for host %s',
          self.user.nickname, host_id)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with user %s' % self.user.nickname)

    # Extract and validate the exemption reason.
    reason = self.request.get('reason')
    other_text = self.request.get('otherText') or None
    if not reason:
      self.abort(httplib.BAD_REQUEST, explanation='No reason provided')
    elif reason == constants.EXEMPTION_REASON.OTHER and not other_text:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='No explanation for "Other" reason provided')

    # Extract and validate the exemption duration.
    duration = self.request.get('duration')
    if not duration:
      self.abort(
          httplib.BAD_REQUEST, explanation='Exemption term not provided')

    # Request a new Exemption, and bail if something goes wrong.
    try:
      exemption_api.Request(host_id, reason, other_text, duration)
    except exemption_api.InvalidRenewalError:
      self.abort(httplib.BAD_REQUEST, 'Request cannot be renewed at this time')
    except exemption_api.InvalidReasonError:
      self.abort(httplib.BAD_REQUEST, 'Invalid reason provided')
    except exemption_api.InvalidDurationError:
      self.abort(httplib.BAD_REQUEST, 'Invalid duration provided')
    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while escalating Exemption for host %s', host_id)
      self.abort(
          httplib.INTERNAL_SERVER_ERROR,
          explanation='Error while escalating exemption')

    # Start processing the Exemption right away, rather than waiting for the
    # 15 minute cron to catch it. On the off chance the cron fires between the
    # above Request() call and here, catch and ignore InvalidStateChangeErrors.
    try:
      exm_key = exemption_models.Exemption.CreateKey(host_id)
      exemption_api.Process(exm_key)
    except exemption_models.InvalidStateChangeError:
      logging.warning('Error encountered while processing Exemption')

    self._RespondWithExemptionAndTransitiveState(exm_key)


class EscalateExemptionHandler(ExemptionHandler):
  """Handler for escalating an exemption request to a ticket."""

  def post(self, host_id):

    if not self.exm:
      self.abort(httplib.NOT_FOUND, explanation='Exemption not found')

    # Humans should never trigger the transition from PENDING to ESCALATED, only
    # api.Process() should.
    if self.exm.key.get().state == constants.EXEMPTION_STATE.PENDING:
      self.abort(
          httplib.FORBIDDEN, explanation='Cannot escalate a pending request')

    try:
      exemption_api.Escalate(self.exm.key)
    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while escalating Exemption for host %s', host_id)
      self.abort(
          httplib.INTERNAL_SERVER_ERROR,
          explanation='Error while escalating exemption')

    self.respond_json(self.exm.key.get())


class ApproveExemptionHandler(ExemptionHandler):
  """Handler for allowing an admin to approve an escalated exemption."""

  @handler_utils.RequireCapability(constants.PERMISSIONS.MANAGE_EXEMPTIONS)
  def post(self, host_id):

    if not self.exm:
      self.abort(httplib.NOT_FOUND, explanation='Exemption not found')

    # Humans should never trigger the transition from PENDING to APPROVED, only
    # api.Process() should.
    if self.exm.key.get().state == constants.EXEMPTION_STATE.PENDING:
      self.abort(
          httplib.FORBIDDEN, explanation='Cannot approve a pending request')

    # Extract and validate POST data fields.
    justification = self.request.get('justification')
    if not justification:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='No justification for approval provided')

    try:
      exemption_api.Approve(self.exm.key, details=[justification])
    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while approving Exemption for host %s', host_id)
      self.abort(
          httplib.INTERNAL_SERVER_ERROR,
          explanation='Error while approving exemption')

    self._RespondWithExemptionAndTransitiveState(self.exm.key)


class DenyExemptionHandler(ExemptionHandler):
  """Handler for allowing an admin to deny an escalated exemption."""

  @handler_utils.RequireCapability(constants.PERMISSIONS.MANAGE_EXEMPTIONS)
  def post(self, host_id):

    if not self.exm:
      self.abort(httplib.NOT_FOUND, explanation='Exemption not found')

    # Humans should never trigger the transition from PENDING to DENIED, only
    # api.Process() should.
    if self.exm.key.get().state == constants.EXEMPTION_STATE.PENDING:
      self.abort(httplib.FORBIDDEN, explanation='Cannot deny a pending request')

    justification = self.request.get('justification')
    if not justification:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='No justification for denial provided')

    try:
      exemption_api.Deny(self.exm.key, details=[justification])
    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while denying Exemption for host %s', host_id)
      self.abort(
          httplib.INTERNAL_SERVER_ERROR,
          explanation='Error while denying exemption')

    self.respond_json(self.exm.key.get())


class RevokeExemptionHandler(ExemptionHandler):
  """Handler for allowing an admin to revoke an approved exemption."""

  @handler_utils.RequireCapability(constants.PERMISSIONS.MANAGE_EXEMPTIONS)
  def post(self, host_id):

    if not self.exm:
      self.abort(httplib.NOT_FOUND, explanation='Exemption not found')

    # Extract and validate POST data fields.
    justification = self.request.get('justification')
    if not justification:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='No justification for revoking exemption provided')

    try:
      exemption_api.Revoke(self.exm.key, [justification])
    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while revoking Exemption for host %s', host_id)
      self.abort(
          httplib.INTERNAL_SERVER_ERROR,
          explanation='Error while revoking exemption')

    self._RespondWithExemptionAndTransitiveState(self.exm.key)


class CancelExemptionHandler(ExemptionHandler):
  """Handler for allowing a user to cancel their own exemption."""

  def post(self, host_id):

    if not self.exm:
      self.abort(httplib.NOT_FOUND, explanation='Exemption not found')

    # Verify that the current user is associated with the Host.
    # NOTE: Admins don't get a pass here, they can (and should) use the
    # above 'revoke' handler instead.
    if not model_utils.IsHostAssociatedWithUser(self.host, self.user):
      logging.error(
          'Host %s not associated with user %s', host_id, self.user.nickname)
      self.abort(
          httplib.FORBIDDEN,
          explanation='Host not associated with requesting user')

    try:
      exemption_api.Cancel(self.exm.key)
    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while cancelling Exemption for host %s', host_id)
      self.abort(
          httplib.INTERNAL_SERVER_ERROR,
          explanation='Failed to cancel exemption')

    self._RespondWithExemptionAndTransitiveState(self.exm.key)


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/exemptions', [
    webapp2.Route(
        '/<host_id>',
        handler=GetExemptionHandler),
    webapp2.Route(
        '/<host_id>/request',
        handler=RequestExemptionHandler),
    webapp2.Route(
        '/<host_id>/escalate',
        handler=EscalateExemptionHandler),
    webapp2.Route(
        '/<host_id>/approve',
        handler=ApproveExemptionHandler),
    webapp2.Route(
        '/<host_id>/deny',
        handler=DenyExemptionHandler),
    webapp2.Route(
        '/<host_id>/revoke',
        handler=RevokeExemptionHandler),
    webapp2.Route(
        '/<host_id>/cancel',
        handler=CancelExemptionHandler)
])

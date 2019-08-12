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

"""Module containing Exemption-related notification logic."""

import datetime

from google.appengine.ext import deferred
from upvote.gae import settings
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.utils import env_utils
from upvote.gae.utils import mail_utils
from upvote.gae.utils import template_utils
from upvote.shared import constants


# Done for brevity.
_STATE = constants.EXEMPTION_STATE

_EMAIL_TEMPLATE_MAP = {
    _STATE.APPROVED: 'exemption_approved.html',
    _STATE.CANCELLED: 'exemption_cancelled.html',
    _STATE.DENIED: 'exemption_denied.html',
    _STATE.EXPIRED: 'exemption_expired.html',
    _STATE.REQUESTED: 'exemption_requested.html',
    _STATE.REVOKED: 'exemption_revoked.html'}


class Error(Exception):
  """Base error class for this module."""


class UnsupportedPlatformError(Error):
  """Raised if an Exemption with an unsupported platform is encountered."""


def _GetDeviceName(host):
  """Helper function for getting a user-friendly device name from a Host.

  Args:
    host: The Host entity we want a name from.

  Returns:
    A user-friendly device name.
  """
  # Only take the first dot-separated piece of the hostname.
  return host.hostname.split('.')[0]


def _GetClientName(host):
  """Helper function for getting a user-friendly client name from a Host.

  Args:
    host: The Host entity we want a name from.

  Returns:
    A user-friendly client name.
  """
  return constants.CLIENT.MAP_TO_COMMON_NAME[host.GetClientName()]


def _SendEmail(exm_key, body):
  """Helper function for sending an Exemption-related email.

  Args:
    exm_key: The Key of the Exemption.
    body: The body of the email.

  Raises:
    UnsupportedPlatformError: if the platform of the corresponding Host is
        unsupported.
  """
  platform = exemption_models.Exemption.GetPlatform(exm_key)
  host_key = exm_key.parent()
  host = host_key.get()

  subject = '%s exemption update for %s' % (
      _GetClientName(host), _GetDeviceName(host))

  # Figure out who the email should be sent to.
  if platform == constants.PLATFORM.WINDOWS:
    to = host.users
  elif platform == constants.PLATFORM.MACOS:
    to = [host.primary_user]
  else:
    raise UnsupportedPlatformError(
        'Host %s has an unsupported platform: %s' % (host_key.id(), platform))

  mail_utils.Send(subject, body, to=to, html=True)


def SendUpdateEmail(exm_key, new_state, details=None):
  """Sends an email when an Exemption is updated.

  Args:
    exm_key: The Key of the Exemption.
    new_state: The new state the Exemption is transitioning to.
    details: Optional list of detail strings explaining the transition.

  Raises:
    UnsupportedPlatformError: if the platform of the corresponding Host is
        unsupported.
  """
  template_name = _EMAIL_TEMPLATE_MAP[new_state]

  host_key = exm_key.parent()
  host = host_key.get()

  body = template_utils.RenderEmailTemplate(
      template_name,
      client_name=_GetClientName(host),
      details=details,
      device_id=host_key.id(),
      device_name=_GetDeviceName(host),
      upvote_hostname=env_utils.ENV.HOSTNAME)

  _SendEmail(exm_key, body)


def DeferUpdateEmail(exm_key, new_state, details=None, transactional=False):
  deferred.defer(
      SendUpdateEmail, exm_key, new_state, details=details,
      _queue=constants.TASK_QUEUE.EXEMPTIONS, _transactional=transactional)


def SendExpirationEmail(exm_key):
  """Sends an email regarding an Exemption that is about to expire.

  Args:
    exm_key: The Key of the Exemption.

  Raises:
    UnsupportedPlatformError: if the platform of the corresponding Host is
        unsupported.
  """
  exm = exm_key.get()
  deactivation_dt = exm.deactivation_dt
  expiration_str = deactivation_dt.strftime('%B %d, %Y at %I:%M%p (UTC)')

  host_key = exm_key.parent()
  host = host_key.get()

  send_email = True

  # For SantaHosts, don't bother sending the expiration email if there hasn't
  # been a sync in a sufficiently long period of time.
  if host.GetClientName() == constants.CLIENT.SANTA:
    now = datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(days=settings.HOST_INACTIVITY_THRESHOLD)
    send_email = host.last_postflight_dt and host.last_postflight_dt > cutoff

  if send_email:
    body = template_utils.RenderEmailTemplate(
        'exemption_will_expire.html',
        client_name=_GetClientName(host),
        device_id=host_key.id(),
        device_name=_GetDeviceName(host),
        expiration_str=expiration_str,
        upvote_hostname=env_utils.ENV.HOSTNAME)
    _SendEmail(exm_key, body)

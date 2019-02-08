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

"""Module containing all Exemption decision-making logic."""

import datetime
import logging

from concurrent import futures

from google.appengine.ext import ndb

from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.lib.bit9 import api as bit9_api
from upvote.gae.lib.bit9 import utils as bit9_utils
from upvote.gae.lib.exemption import checks
from upvote.gae.lib.exemption import notify
from upvote.gae.lib.exemption import monitoring
from upvote.shared import constants


# Done for brevity.
_STATE = constants.EXEMPTION_STATE


class Error(Exception):
  """Base error class for this module."""


class UnknownHostError(Error):
  """Raised when a particular host cannot be found."""


class InvalidEnforcementLevelError(Error):
  """Raised when an invalid Bit9 enforcement level is provided."""


class UnknownPolicyError(Error):
  """Raised if a Bit9 host has an unknown policy."""


class InvalidClientModeError(Error):
  """Raised when an invalid Santa client mode is provided."""


class UnsupportedPlatformError(Error):
  """Raised if an Exemption with an unsupported platform is encountered."""


class InvalidStateChangeError(Error):
  """Raised when attempting to change an Exemption to an invalid state."""


class InvalidReasonError(Error):
  """Raised when an invalid EXEMPTION_REASON is provided."""


class InvalidDurationError(Error):
  """Raised when an invalid EXEMPTION_DURATION is provided."""


class InvalidRenewalError(Error):
  """Raised when trying to make an invalid Exemption renewal."""


_POLICY_CHECKS = {
    constants.PLATFORM.MACOS: [],
    constants.PLATFORM.WINDOWS: [],
}


def _ChangeEnforcementInBit9(host_id, new_enforcement_level):
  """Changes enforcement level for a Bit9Host.

  Args:
    host_id: The ID of the Bit9Host.
    new_enforcement_level: The new enforcement level to set for the Bit9Host.

  Raises:
    UnknownHostError: if the host cannot be found in Datastore.
    InvalidEnforcementLevelError: if the provided enforcement level is invalid.
    UnknownPolicyError: if the host's Bit9 policy is unknown.
  """
  # Verify the host_id corresponds to an actual Bit9Host.
  if not host_models.Bit9Host.get_by_id(host_id):
    monitoring.enforcement_errors.Increment()
    raise UnknownHostError('Host %s is unknown' % host_id)

  # Verify the specified enforcement level is valid.
  if new_enforcement_level not in constants.BIT9_ENFORCEMENT_LEVEL.SET_ALL:
    monitoring.enforcement_errors.Increment()
    raise InvalidEnforcementLevelError(
        'Invalid Bit9 enforcement level: %s' % new_enforcement_level)

  # Retrieve the current Computer policy from Bit9.
  computer = bit9_api.Computer.get(int(host_id), bit9_utils.CONTEXT)
  current_policy_id = computer.policy_id

  # Determine the appropriate policy for the new enforcement level.
  policy_map = constants.BIT9_ENFORCEMENT_LEVEL.MAP_TO_POLICY_ID
  new_policy_id = policy_map.get(new_enforcement_level)

  # If there's not a valid policy, bail.
  if not new_policy_id:
    monitoring.enforcement_errors.Increment()
    raise UnknownPolicyError(
        'Host %s has an unknown policy ID: %s' % (host_id, current_policy_id))

  logging.info(
      'Changing policy from %s to %s', current_policy_id, new_policy_id)

  # Write the new policy back to Bit9.
  computer.policy_id = new_policy_id
  computer.put(bit9_utils.CONTEXT)

  # Change the policy Key on the entity itself.
  new_policy_key = ndb.Key(host_models.Bit9Policy, new_policy_id)
  host_models.Bit9Host.ChangePolicyKey(host_id, new_policy_key)

  # Insert a row into BigQuery reflecting the change.
  host = host_models.Bit9Host.get_by_id(host_id)
  tables.HOST.InsertRow(
      device_id=host_id,
      timestamp=datetime.datetime.utcnow(),
      action=constants.HOST_ACTION.MODE_CHANGE,
      hostname=host.hostname,
      platform=constants.PLATFORM.WINDOWS,
      users=host.users,
      mode=new_enforcement_level)


def _ChangeEnforcementInSanta(host_id, new_client_mode):
  """Toggles between MONITOR and LOCKDOWN for a SantaHost.

  Args:
    host_id: The ID of the SantaHost.
    new_client_mode: The new client mode to set for the SantaHost.

  Raises:
    UnknownHostError: if the host cannot be found in Datastore.
    InvalidClientModeError: if the provided client mode is invalid.
  """
  # Verify the host_id corresponds to an actual SantaHost.
  host = host_models.SantaHost.get_by_id(host_id)
  if not host:
    monitoring.enforcement_errors.Increment()
    raise UnknownHostError('Host %s is unknown' % host_id)

  # Verify the specified client mode is valid.
  if new_client_mode not in constants.CLIENT_MODE.SET_ALL:
    monitoring.enforcement_errors.Increment()
    raise InvalidClientModeError(
        'Invalid Santa client mode: %s' % new_client_mode)

  host_models.SantaHost.ChangeClientMode(host_id, new_client_mode)

  # If changing to MONITOR mode and transitive whitelisting is enabled, disable
  # it.
  if (new_client_mode == constants.CLIENT_MODE.MONITOR and
      host.transitive_whitelisting_enabled):
    host_models.SantaHost.ChangeTransitiveWhitelisting(host_id, False)

  host = host_models.Host.get_by_id(host_id)
  tables.HOST.InsertRow(
      device_id=host_id,
      timestamp=datetime.datetime.utcnow(),
      action=constants.HOST_ACTION.MODE_CHANGE,
      hostname=host.hostname,
      platform=constants.PLATFORM.MACOS,
      # Can't use GetUsersAssociatedWithSantaHost() due to non-ancestor query.
      users=[host.primary_user],
      mode=host.client_mode)


def _EnableLockdown(exm_key):
  """Enables LOCKDOWN mode for a given Exemption.

  Args:
    exm_key: The Key of the Exemption we're enabling LOCKDOWN for.

  Raises:
    UnsupportedPlatformError: if the platform of the corresponding Host is
        unsupported.
  """
  host_id = exm_key.parent().id()
  platform = exemption_models.Exemption.GetPlatform(exm_key)
  logging.info('Enabling LOCKDOWN mode for Host %s', host_id)

  if platform == constants.PLATFORM.WINDOWS:
    _ChangeEnforcementInBit9(host_id, constants.BIT9_ENFORCEMENT_LEVEL.LOCKDOWN)

  elif platform == constants.PLATFORM.MACOS:
    _ChangeEnforcementInSanta(host_id, constants.CLIENT_MODE.LOCKDOWN)

  else:
    monitoring.enforcement_errors.Increment()
    raise UnsupportedPlatformError(
        'Host %s has an unsupported platform: %s' % (host_id, platform))


def _DisableLockdown(exm_key):
  """Disables LOCKDOWN mode for a given Exemption.

  Args:
    exm_key: The Key of the Exemption we're disabling LOCKDOWN for.

  Raises:
    UnsupportedPlatformError: if the platform of the corresponding Host is
        unsupported.
  """
  host_id = exm_key.parent().id()
  platform = exemption_models.Exemption.GetPlatform(exm_key)
  logging.info('Disabling LOCKDOWN mode for Host %s', host_id)

  if platform == constants.PLATFORM.WINDOWS:
    _ChangeEnforcementInBit9(host_id, constants.BIT9_ENFORCEMENT_LEVEL.MONITOR)

  elif platform == constants.PLATFORM.MACOS:
    _ChangeEnforcementInSanta(host_id, constants.CLIENT_MODE.MONITOR)

  else:
    monitoring.enforcement_errors.Increment()
    raise UnsupportedPlatformError(
        'Host %s has an unsupported platform: %s' % (host_id, platform))


@ndb.transactional
def Request(host_id, reason, other_text, duration):
  """Creates a new Exemption, or reuses an existing one.

  If no corresponding Exemption exists, creates a new one in the REQUESTED
  state. Otherwise, if one exists in a terminal state
  (CANCELLED/REVOKED/EXPIRED), sets it back to REQUESTED with the new
  deactivation date.

  Args:
    host_id: (str) Host ID
    reason: (str) The reason for requesting an Exemption. Must be one of
        constants.EXEMPTION_REASON.
    other_text: (str) Additional text if the reason is OTHER
    duration: (str) The requested duration of the Exemption. Must be one of
        constants.EXEMPTION_DURATION.

  Raises:
    InvalidReasonError: if the provided reason is invalid.
    InvalidDurationError: if the provided duration is invalid.
    InvalidRenewalError: if the Exemption cannot currently be renewed.
  """
  logging.info('Requesting Exemption for host %s', host_id)

  # Validate the reason.
  if reason not in constants.EXEMPTION_REASON.SET_ALL:
    message = 'Invalid reason provided: %s' % reason
    logging.error(message)
    raise InvalidReasonError(message)

  # Validate the duration.
  if duration not in constants.EXEMPTION_DURATION.SET_ALL:
    message = 'Invalid exemption duration: %s' % duration
    logging.error(message)
    raise InvalidDurationError(message)

  duration_delta = datetime.timedelta(
      days=constants.EXEMPTION_DURATION.MAP_TO_DAYS[duration])
  deactivation_dt = datetime.datetime.utcnow() + duration_delta

  exm = exemption_models.Exemption.Get(host_id)

  # If an Exemption has never existed for this host_id, just create one.
  if exm is None:
    exm_key = exemption_models.Exemption.Insert(
        host_id, deactivation_dt, reason, other_text=other_text)
    notify.DeferUpdateEmail(exm_key, _STATE.REQUESTED, transactional=True)
    return

  # If we're dealing with an existing Exemption which can state change back to
  # REQUESTED, then make the change.
  if exm.CanChangeToState(_STATE.REQUESTED):
    exm_key = exemption_models.Exemption.CreateKey(host_id)
    details = [reason, other_text] if other_text else [reason]
    exemption_models.Exemption.ChangeState(
        exm_key, _STATE.REQUESTED, details=details)
    exm.deactivation_dt = deactivation_dt
    exm.put()
    notify.DeferUpdateEmail(exm_key, _STATE.REQUESTED, transactional=True)

  # Otherwise, we've received a request for an invalid renewal.
  else:
    message = 'Host %s already has a(n) %s Exemption' % (host_id, exm.state)
    logging.error(message)
    raise InvalidRenewalError(message)


def Process(exm_key):
  """Checks if a REQUESTED Exemption is compatible with all policies.

  Args:
    exm_key: The NDB Key of the Exemption entity.
  """
  host_id = exm_key.parent().id()
  logging.info('Processing Exemption for host %s', host_id)

  # Change state from REQUESTED to PENDING.
  try:
    exemption_models.Exemption.ChangeState(exm_key, _STATE.PENDING)

  # Process() shouldn't be transactional due to all the potential calls out made
  # below. Because of this, it's entirely possible that the calls to Process()
  # in RequestExemptionHandler and ProcessExemptions could both end up trying to
  # transition this Exemption to PENDING at the same time. It's a benign race
  # condition, so we should just note it and move on.
  except exemption_models.InvalidStateChangeError:
    logging.warning(
        'Error encountered while processing Exemption for host %s', host_id)
    return

  # Any other Exceptions should make noise.
  except Exception:  # pylint: disable=broad-except
    monitoring.processing_errors.Increment()
    logging.exception(
        'Error encountered while processing Exemption for host %s', host_id)
    return

  try:

    # If no platform can be determined, auto-deny, because it means there's a
    # bug. Otherwise this request will just endlessly bounce between REQUESTED
    # and PENDING.
    try:
      platform = exemption_models.Exemption.GetPlatform(exm_key)
    except exemption_models.UnknownPlatformError:
      message = 'Host %s has an unknown platform' % host_id
      logging.error(message)
      monitoring.processing_errors.Increment()
      Deny(exm_key, details=[message])
      return

    # If no policy has been defined for the platform, auto-deny, because it
    # means there's a bug. Otherwise this request will just endlessly bounce
    # between REQUESTED and PENDING.
    if platform not in _POLICY_CHECKS:
      message = 'Platform "%s" is unsupported' % platform
      logging.error(message)
      monitoring.processing_errors.Increment()
      Deny(exm_key, details=[message])
      return

    # An empty policy should fail open, otherwise it would require a no-op check
    # which always returns APPROVED. An empty policy that fails closed would be
    # better suited by simply disabling the exemption system altogether.
    policy_checks = _POLICY_CHECKS[platform]
    if not policy_checks:
      logging.info('Empty policy defined for platform "%s"', platform)
      Approve(exm_key)
      return

    # Create a ThreadPoolExecutor and run the individual policy checks.
    logging.info(
        'Executing %d policy check(s) against host %s', len(policy_checks),
        host_id)
    with futures.ThreadPoolExecutor(max_workers=len(policy_checks)) as executor:
      running_futures = [
          executor.submit(check, exm_key) for check in policy_checks]
      done_futures = futures.wait(running_futures).done
      results = [done_future.result() for done_future in done_futures]

    # If any of the checks return a non-'outcome' state, auto-deny, because it
    # means there's a bug. Otherwise this request will just endlessly bounce
    # between REQUESTED and PENDING.
    for result in results:
      if result.state not in _STATE.SET_OUTCOME:
        message = '%s returned an invalid state: %s' % (
            result.name, result.state)
        logging.error(message)
        monitoring.processing_errors.Increment()
        Deny(exm_key, details=[message])
        return

    details = [result.detail for result in results if result.detail]

    # Outcome precedence is: any(DENIED) > any(ESCALATED) > any(APPROVED).
    if any(result.state == _STATE.DENIED for result in results):
      Deny(exm_key, details=details)
    elif any(result.state == _STATE.ESCALATED for result in results):
      Escalate(exm_key, details=details)
    else:
      Approve(exm_key, details=details)

  except Exception as e:  # pylint: disable=broad-except

    logging.exception(
        'Error encountered while processing Exemption for host %s', host_id)
    monitoring.processing_errors.Increment()

    # If something breaks, revert back to REQUESTED so the cron can retry.
    exemption_models.Exemption.ChangeState(
        exm_key, _STATE.REQUESTED,
        details=['Error while processing: ' + str(e)])


@ndb.transactional(xg=True)  # xg due to Windows (Bit9Host & Bit9ApiAuth)
def Approve(exm_key, details=None):
  """Transitions an Exemption to the APPROVED state.

  Args:
    exm_key: The NDB Key of the Exemption entity.
    details: Optional list of strings describing the rationale.

  Raises:
    InvalidStateChangeError: If the desired state cannot be transitioned to from
        the current state.
  """
  host_id = exemption_models.Exemption.GetHostId(exm_key)
  logging.info('Approving Exemption for Host %s', host_id)

  # Verify that the desired state change is still valid.
  exm = exm_key.get()
  if not exm.CanChangeToState(_STATE.APPROVED):
    raise InvalidStateChangeError('%s to %s' % (exm.state, _STATE.APPROVED))

  _DisableLockdown(exm_key)
  exemption_models.Exemption.ChangeState(
      exm_key, _STATE.APPROVED, details=details)
  notify.DeferUpdateEmail(
      exm_key, _STATE.APPROVED, details=details, transactional=True)


@ndb.transactional
def Deny(exm_key, details=None):
  """Transitions an Exemption to the DENIED state.

  Args:
    exm_key: The NDB Key of the Exemption entity.
    details: Optional list of strings describing the rationale.

  Raises:
    InvalidStateChangeError: If the desired state cannot be transitioned to from
        the current state.
  """
  host_id = exemption_models.Exemption.GetHostId(exm_key)
  logging.info('Denying Exemption for Host %s', host_id)

  # Verify that the desired state change is still valid.
  exm = exm_key.get()
  if not exm.CanChangeToState(_STATE.DENIED):
    raise InvalidStateChangeError('%s to %s' % (exm.state, _STATE.DENIED))

  exemption_models.Exemption.ChangeState(
      exm_key, _STATE.DENIED, details=details)
  notify.DeferUpdateEmail(
      exm_key, _STATE.DENIED, details=details, transactional=True)


@ndb.transactional
def Escalate(exm_key, details=None):
  """Transitions an Exemption to the ESCALATED state.

  Args:
    exm_key: The NDB Key of the Exemption entity.
    details: Optional list of strings describing the rationale.

  Raises:
    InvalidStateChangeError: If the desired state cannot be transitioned to from
        the current state.
  """
  host_id = exemption_models.Exemption.GetHostId(exm_key)
  logging.info('Escalating Exemption for Host %s', host_id)

  # Verify that the desired state change is still valid.
  exm = exm_key.get()
  if not exm.CanChangeToState(_STATE.ESCALATED):
    raise InvalidStateChangeError('%s to %s' % (exm.state, _STATE.ESCALATED))

  exemption_models.Exemption.ChangeState(
      exm_key, _STATE.ESCALATED, details=details)


@ndb.transactional(xg=True)  # xg due to Windows (Bit9Host & Bit9ApiAuth)
def Expire(exm_key):
  """Transitions an Exemption to the EXPIRED state.

  Args:
    exm_key: The NDB Key of the Exemption entity.

  Raises:
    InvalidStateChangeError: If the desired state cannot be transitioned to from
        the current state.
  """
  host_id = exemption_models.Exemption.GetHostId(exm_key)
  logging.info('Expiring Exemption for Host %s', host_id)

  # Verify that the desired state change is still valid.
  exm = exm_key.get()
  if not exm.CanChangeToState(_STATE.EXPIRED):
    raise InvalidStateChangeError('%s to %s' % (exm.state, _STATE.EXPIRED))

  _EnableLockdown(exm_key)
  exemption_models.Exemption.ChangeState(exm_key, _STATE.EXPIRED)
  notify.DeferUpdateEmail(exm_key, _STATE.EXPIRED, transactional=True)


@ndb.transactional(xg=True)  # xg due to Windows (Bit9Host & Bit9ApiAuth)
def Revoke(exm_key, details):
  """Transitions an Exemption to the REVOKED state.

  Args:
    exm_key: The NDB Key of the Exemption entity.
    details: List of strings describing the rationale.

  Raises:
    InvalidStateChangeError: If the desired state cannot be transitioned to from
        the current state.
  """
  host_id = exemption_models.Exemption.GetHostId(exm_key)
  logging.info('Revoking Exemption for Host %s', host_id)

  # Verify that the desired state change is still valid.
  exm = exm_key.get()
  if not exm.CanChangeToState(_STATE.REVOKED):
    raise InvalidStateChangeError('%s to %s' % (exm.state, _STATE.REVOKED))

  _EnableLockdown(exm_key)
  exemption_models.Exemption.ChangeState(
      exm_key, _STATE.REVOKED, details=details)
  notify.DeferUpdateEmail(
      exm_key, _STATE.REVOKED, details=details, transactional=True)


@ndb.transactional(xg=True)  # xg due to Windows (Bit9Host & Bit9ApiAuth)
def Cancel(exm_key):
  """Transitions an Exemption to the CANCELLED state.

  Args:
    exm_key: The NDB Key of the Exemption entity.

  Raises:
    InvalidStateChangeError: If the desired state cannot be transitioned to from
        the current state.
  """
  host_id = exemption_models.Exemption.GetHostId(exm_key)
  logging.info('Cancelling Exemption for Host %s', host_id)

  # Verify that the desired state change is still valid.
  exm = exm_key.get()
  if not exm.CanChangeToState(_STATE.CANCELLED):
    raise InvalidStateChangeError('%s to %s' % (exm.state, _STATE.CANCELLED))

  _EnableLockdown(exm_key)
  exemption_models.Exemption.ChangeState(exm_key, _STATE.CANCELLED)
  notify.DeferUpdateEmail(exm_key, _STATE.CANCELLED, transactional=True)

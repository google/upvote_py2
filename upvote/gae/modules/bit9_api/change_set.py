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

"""Module for committing Upvote Rules to the Bit9 database."""

import datetime
import functools
import logging

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae.datastore.models import bit9
from upvote.gae.modules.bit9_api import constants as bit9_constants
from upvote.gae.modules.bit9_api import utils
from upvote.gae.modules.bit9_api.api import api
from upvote.shared import constants

_COMMIT_RETRIES = 3

# The amount of time since last sync for which a Computer is considered active.
_ACTIVITY_WINDOW = datetime.timedelta(days=1)


class Error(Exception):
  """Base exception class."""


class TransientError(Error):
  """The operation encountered a temporary error state."""


class WaitingForSyncError(TransientError):
  """The operation could not be completed due to a pending client sync."""


def _WithRetries(
    max_retries=_COMMIT_RETRIES, errors_to_retry=(TransientError,)):
  """Retry the decorated function when given exceptions are raised."""
  def Decorator(func):
    """The function decorator."""
    @functools.wraps(func)
    def Wrapper(*args, **kwargs):
      last_error = None
      for _ in xrange(1 + max_retries):
        try:
          return func(*args, **kwargs)
        except errors_to_retry as last_error:  # pylint: disable=broad-except
          continue
      raise last_error  # pylint: disable=raising-bad-type

    # Rip off Python 3 and make this thing easier to debug.
    Wrapper.__wrapped__ = func

    return Wrapper
  return Decorator


@_WithRetries()
def _ChangeLocalState(new_state, file_catalog_id, host_id):
  """Handles requests for changing local approval state."""
  logging.info(
      'Changing local state to %s for fileCatalog=%s, computer=%s', new_state,
      file_catalog_id, host_id)

  file_instances = (
      api.FileInstance.query()
      .filter(api.FileInstance.computer_id == host_id)
      .filter(api.FileInstance.file_catalog_id == file_catalog_id)
      .execute(utils.CONTEXT))

  logging.debug('Got %s matching file instance(s)', len(file_instances))

  if not file_instances:
    # The host client may not have uploaded their fileInstance to Bit9 yet
    # so we should delay resolving the change until everything's up-to-date.
    # However, an inactive host that is in an incomplete sync state is
    # unlikely to be uploading this fileInstance.
    computer = api.Computer.get(host_id, utils.CONTEXT)
    activity_threshold = datetime.datetime.utcnow() - _ACTIVITY_WINDOW
    last_active = computer.last_poll_date
    if computer.sync_percent != 100 and last_active >= activity_threshold:
      logging.warning(
          'Computer %s last synced %s. Forcing retry...', computer.id,
          last_active)
      raise WaitingForSyncError('Client not yet synced.')

    # The host doesn't currently have an instance of the blockable.
    logging.debug('State could not be fulfilled')
    return False
  else:
    for instance in file_instances:
      logging.info('Attempting a state change on instance %s', instance.id)

      # NOTE: Even if the local_state is in the desired state, we
      # should try to update it because the local_state value doesn't
      # necessarily reflect the prescribed state. Changes are only visible on
      # the fileInstance once the host has checked into Bit9.
      instance.local_state = (
          new_state or bit9_constants.APPROVAL_STATE.UNAPPROVED)
      instance.put(utils.CONTEXT)

    return True


def _ChangeLocalStates(blockable, local_rules, new_state):
  if isinstance(blockable, bit9.Bit9Certificate):
    logging.warning('Cannot change local state for certificates in Bit9')
    return

  for local_rule in local_rules:
    logging.debug(
        'Locally marking %s as %s on host %s', blockable.key.id(),
        bit9_constants.APPROVAL_STATE.MAP_TO_STR[new_state], local_rule.host_id)

    was_fulfilled = _ChangeLocalState(
        new_state, int(blockable.file_catalog_id), int(local_rule.host_id))

    # Update the Rule.is_fulfilled to reflect whether the local state change
    # was able to be committed to the database.
    logging.info(
        'Local rule %s fulfilled', 'was' if was_fulfilled else 'was not')
    local_rule.is_fulfilled = was_fulfilled


def _ChangeGlobalState(blockable, new_state):
  logging.debug(
      'Globally marking %s as %s', blockable.key.id(),
      bit9_constants.APPROVAL_STATE.MAP_TO_STR[new_state])

  if isinstance(blockable, bit9.Bit9Certificate):
    certs = (
        api.Certificate.query()
        .filter(api.Certificate.thumbprint == blockable.key.id())
        .execute(utils.CONTEXT))
    assert certs, 'No matching certificates found'
    assert len(certs) == 1, 'Multiple matching certificates found'
    cert = certs[0]
    cert.certificate_state = new_state
    cert.put(utils.CONTEXT)
  else:
    rule = api.FileRule(
        file_catalog_id=int(blockable.file_catalog_id),
        file_state=new_state)
    rule.put(utils.CONTEXT)


def _GetLocalRules(rules):
  return [rule for rule in rules if rule.host_id]


def _GetGlobalRule(rules):
  globals_ = [rule for rule in rules if not rule.host_id]
  assert len(globals_) <= 1
  return globals_[0] if globals_ else None


def _Whitelist(blockable, rules):
  _ChangeLocalStates(
      blockable, _GetLocalRules(rules), bit9_constants.APPROVAL_STATE.APPROVED)

  global_rule = _GetGlobalRule(rules)
  if global_rule is not None:
    _ChangeGlobalState(blockable, bit9_constants.APPROVAL_STATE.APPROVED)


@_WithRetries()
def _Blacklist(blockable, rules):
  global_rule = _GetGlobalRule(rules)
  assert global_rule is not None
  assert not _GetLocalRules(rules)

  _ChangeGlobalState(blockable, bit9_constants.APPROVAL_STATE.BANNED)


@_WithRetries()
def _Remove(blockable, rules):
  _ChangeLocalStates(
      blockable, _GetLocalRules(rules),
      bit9_constants.APPROVAL_STATE.UNAPPROVED)

  global_rule = _GetGlobalRule(rules)
  if global_rule is not None:
    _ChangeGlobalState(blockable, bit9_constants.APPROVAL_STATE.UNAPPROVED)


@_WithRetries()
def _ChangeInstallerState(blockable, rules):
  """Issue the request to Bit9 to change the blockable's installer state."""
  global_rule = _GetGlobalRule(rules)
  assert global_rule is not None

  logging.debug(
      'Changing Installer state of %s to %s', blockable.key.id(),
      global_rule.policy)

  # The Bit9 API forbids creating a FileRule without a 'fileState' column. To
  # avoid overwriting an existing FileRule's state, we need to use that if one
  # exists.
  file_catalog_id = int(blockable.file_catalog_id)
  rules = (api.FileRule.query()
           .filter(api.FileRule.file_catalog_id == file_catalog_id)
           .execute(utils.CONTEXT))
  existing_state = (
      rules[0].file_state
      if rules
      else bit9_constants.APPROVAL_STATE.UNAPPROVED)

  rule = api.FileRule(
      file_catalog_id=file_catalog_id,
      file_state=existing_state,
      force_installer=(
          global_rule.policy == constants.RULE_POLICY.FORCE_INSTALLER),
      force_not_installer=(
          global_rule.policy == constants.RULE_POLICY.FORCE_NOT_INSTALLER))
  rule.put(utils.CONTEXT)


@ndb.transactional
def CommitBlockableChangeSet(blockable_key, tail_defer=True):
  """Attempts to commit and delete the next RuleChangeSet for a blockable.

  NOTE: If tail_defer is True, another commit attempt will only be queued if
  there is another change set available to commit.

  Args:
    blockable_key: Key, The key to the blockable for which a RuleChangeSet
        should be attempted to commit.
    tail_defer: bool, Whether to defer another commit attempt upon the
        successful completion of this commit **IF** there is another change set.
  """
  change_query = bit9.RuleChangeSet.query(
      ancestor=blockable_key).order(bit9.RuleChangeSet.recorded_dt)
  changes = change_query.fetch(limit=2)
  if not changes:
    logging.info('No changes to commit for %s', blockable_key.id())
    return

  # Attempt to commit and then, if successful (i.e. no exception raised) and
  # there is at least one more change set, conditionally trigger another commit
  # attempt for the current blockable.
  CommitChangeSet(changes[0].key)
  if tail_defer and len(changes) > 1:
    DeferCommitBlockableChangeSet(blockable_key)


@ndb.transactional
def CommitChangeSet(change_key):
  """Attempts to commit and delete a given RuleChangeSet."""
  change = change_key.get()
  if change is None:
    logging.info('Change no longer exists. (already committed?)')
    return

  logging.info(
      'Committing a %s change set of %s rules for blockable %s',
      change.change_type, len(change.rule_keys), change.blockable_key.id())

  blockable = change.blockable_key.get()
  rules = ndb.get_multi(change.rule_keys)

  if change.change_type == constants.RULE_POLICY.WHITELIST:
    change_func = _Whitelist
  elif change.change_type == constants.RULE_POLICY.BLACKLIST:
    change_func = _Blacklist
  elif change.change_type == constants.RULE_POLICY.REMOVE:
    change_func = _Remove
  elif change.change_type in constants.RULE_POLICY.SET_INSTALLER:
    change_func = _ChangeInstallerState
  else:
    raise NotImplementedError

  try:
    change_func(blockable, rules)
  except api.RequestError:
    # For normal request errors, rely on the builtin task queue retry settings.
    raise
  except Exception as e:  # pylint: disable=broad-except
    # For all other (likely fatal) errors, make sure the task doesn't retry.
    raise deferred.PermanentTaskFailure(repr(e))
  else:
    for rule in rules:
      rule.is_committed = True
    ndb.put_multi(rules)

    change.key.delete()


def DeferCommitBlockableChangeSet(blockable_key, tail_defer=True):
  deferred.defer(
      CommitBlockableChangeSet, blockable_key, tail_defer=tail_defer,
      _queue=constants.TASK_QUEUE.BIT9_COMMIT_CHANGE)

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
import logging

from google.appengine.ext import deferred
from google.appengine.ext import ndb

from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import cert as cert_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.lib.bit9 import api
from upvote.gae.lib.bit9 import constants as bit9_constants
from upvote.gae.lib.bit9 import monitoring
from upvote.gae.lib.bit9 import utils as bit9_utils
from upvote.gae.utils import user_utils
from upvote.shared import constants

_COMMIT_RETRIES = 3

# The amount of time since last sync for which a Computer is considered active.
_ACTIVITY_WINDOW = datetime.timedelta(days=1)


def ChangeLocalState(blockable, local_rule, new_state):
  """Handles requests for changing local approval state."""

  file_catalog_id = int(blockable.file_catalog_id)
  host_id = int(local_rule.host_id)
  new_state_str = bit9_constants.APPROVAL_STATE.MAP_TO_STR[new_state]

  logging.info(
      'Locally marking %s as %s on host %s', blockable.key.id(), new_state_str,
      local_rule.host_id)

  # Query Bit9 for all matching fileInstances on the given host.
  query = api.FileInstance.query()
  query = query.filter(api.FileInstance.computer_id == host_id)
  query = query.filter(api.FileInstance.file_catalog_id == file_catalog_id)
  file_instances = query.execute(bit9_utils.CONTEXT)
  logging.info('Retrieved %s matching fileInstance(s)', len(file_instances))

  # If none are found, update the Rule and bail.
  if not file_instances:
    monitoring.file_instances_missing.Increment()
    logging.info('Local rule could not be fulfilled')
    local_rule.is_fulfilled = False
    local_rule.put()
    return

  # Make the desired state change on each fileInstance retrieved.
  for instance in file_instances:
    logging.info('Attempting state change on fileInstance %s', instance.id)

    # NOTE: Even if the local_state is in the desired state, we
    # should try to update it because the local_state value doesn't
    # necessarily reflect the prescribed state. Changes are only visible on
    # the fileInstance once the host has checked into Bit9.
    instance.local_state = new_state
    instance.put(bit9_utils.CONTEXT)

    # Update the Rule.is_fulfilled to reflect whether the local state change
    # was successfully propagated to Bit9.
    logging.info('Local rule was successfully fulfilled')
    local_rule.is_fulfilled = True
    local_rule.put()

    # Insert a special BigQuery Rule row indicating when/if this rule ultimately
    # gets fulfilled.
    local_rule.InsertBigQueryRow(comment='Fulfilled in Bit9')


def _ChangeLocalStates(blockable, local_rules, new_state):

  if isinstance(blockable, cert_models.Bit9Certificate):
    logging.warning('Cannot change local state for certificates in Bit9')
    return

  for local_rule in local_rules:
    ChangeLocalState(blockable, local_rule, new_state)


def _ChangeGlobalState(blockable, new_state):
  logging.info(
      'Globally marking %s as %s', blockable.key.id(),
      bit9_constants.APPROVAL_STATE.MAP_TO_STR[new_state])

  if isinstance(blockable, cert_models.Bit9Certificate):
    certs = (
        api.Certificate.query()
        .filter(api.Certificate.thumbprint == blockable.key.id()).execute(
            bit9_utils.CONTEXT))
    assert certs, 'No matching certificates found'
    assert len(certs) == 1, 'Multiple matching certificates found'
    cert = certs[0]
    cert.certificate_state = new_state
    cert.put(bit9_utils.CONTEXT)
  else:
    rule = api.FileRule(
        file_catalog_id=int(blockable.file_catalog_id), file_state=new_state)
    rule.put(bit9_utils.CONTEXT)


def _GetLocalRules(rules):
  return [rule for rule in rules if rule.host_id]


def _GetGlobalRule(rules):
  globals_ = [rule for rule in rules if not rule.host_id]
  if len(globals_) > 1:
    raise deferred.PermanentTaskFailure
  return globals_[0] if globals_ else None


def _Whitelist(blockable, rules):
  _ChangeLocalStates(
      blockable, _GetLocalRules(rules), bit9_constants.APPROVAL_STATE.APPROVED)

  global_rule = _GetGlobalRule(rules)
  if global_rule is not None:
    _ChangeGlobalState(blockable, bit9_constants.APPROVAL_STATE.APPROVED)


def _Blacklist(blockable, rules):
  global_rule = _GetGlobalRule(rules)
  assert global_rule is not None
  if _GetLocalRules(rules):
    raise deferred.PermanentTaskFailure

  _ChangeGlobalState(blockable, bit9_constants.APPROVAL_STATE.BANNED)


def _Remove(blockable, rules):
  _ChangeLocalStates(
      blockable, _GetLocalRules(rules),
      bit9_constants.APPROVAL_STATE.UNAPPROVED)

  global_rule = _GetGlobalRule(rules)
  if global_rule is not None:
    _ChangeGlobalState(blockable, bit9_constants.APPROVAL_STATE.UNAPPROVED)


def _ChangeInstallerState(blockable, rules):
  """Issue the request to Bit9 to change the blockable's installer state."""
  global_rule = _GetGlobalRule(rules)
  assert global_rule is not None

  logging.info(
      'Changing Installer state of %s to %s', blockable.key.id(),
      global_rule.policy)

  # The Bit9 API forbids creating a FileRule without a 'fileState' column. To
  # avoid overwriting an existing FileRule's state, we need to use that if one
  # exists.
  file_catalog_id = int(blockable.file_catalog_id)
  rules = (
      api.FileRule.query()
      .filter(api.FileRule.file_catalog_id == file_catalog_id).execute(
          bit9_utils.CONTEXT))
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
  rule.put(bit9_utils.CONTEXT)


@ndb.transactional(xg=True)
def _CommitBlockableChangeSet(
    blockable_key, tail_defer=True, tail_defer_count=0):
  """Attempts to commit and delete the next RuleChangeSet for a blockable.

  NOTE: If tail_defer is True, another commit attempt will only be queued if
  there is another change set available to commit.

  Args:
    blockable_key: Key, The key to the blockable for which a RuleChangeSet
        should be attempted to commit.
    tail_defer: bool, Whether to defer another commit attempt upon the
        successful completion of this commit **IF** there is another change set.
    tail_defer_count: int, The number of tail defers that have preceded this
        defer.
  """
  change_query = rule_models.RuleChangeSet.query(
      ancestor=blockable_key).order(rule_models.RuleChangeSet.recorded_dt)
  changes = change_query.fetch(limit=2)
  if not changes:
    logging.info('No changes to commit for %s', blockable_key.id())
    return

  # Attempt to commit and then, if successful (i.e. no exception raised) and
  # there is at least one more change set, conditionally trigger another commit
  # attempt for the current blockable.
  _CommitChangeSet(changes[0].key)
  if tail_defer and len(changes) > 1:
    tail_defer_count += 1
    logging.info(
        'Performing tail defer #%d for %s', tail_defer_count,
        blockable_key.id())
    DeferCommitBlockableChangeSet(
        blockable_key, tail_defer=True, tail_defer_count=tail_defer_count)


@ndb.transactional(xg=True)
def _CommitChangeSet(change_key):
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

  # Attempt to perform the change. If something fails, just let the Exception
  # escape and kill the task. A retry will be attempted soon enough via cron.
  change_func(blockable, rules)

  # Clean up if the change went through.
  for rule in rules:
    rule.is_committed = True
  ndb.put_multi(rules)
  change.key.delete()


def DeferCommitBlockableChangeSet(
    blockable_key, tail_defer=True, tail_defer_count=0, countdown=0):
  deferred.defer(
      _CommitBlockableChangeSet, blockable_key, tail_defer=tail_defer,
      tail_defer_count=tail_defer_count,
      _queue=constants.TASK_QUEUE.BIT9_COMMIT_CHANGE, _countdown=countdown)

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

"""Logic associated with voting."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import abc
import logging

import six

from google.appengine.ext import ndb
from upvote.gae import settings
from upvote.gae.bigquery import tables
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import binary as binary_models
from upvote.gae.datastore.models import cert as cert_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import package as package_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.datastore.models import vote as vote_models
from upvote.gae.lib.analysis import metrics
from upvote.gae.lib.bit9 import change_set
from upvote.gae.utils import user_utils
from upvote.shared import constants


class Error(Exception):
  """Base error class for the voting module."""


class BlockableNotFoundError(Error):
  """The SHA256 provided does not correspond to a Blockable entity."""


class UnsupportedClientError(Error):
  """The specified Blockable came from an unsupported client."""


class InvalidVoteWeightError(Error):
  """The provided vote weight is invalid."""


class DuplicateVoteError(Error):
  """Error used when user has already cast a vote for given blockable."""


class OperationNotAllowedError(Error):
  """Error raised when operation not permitted on the given blockable."""


def _CreateOrUpdateVote(blockable, user, was_yes_vote, vote_weight):
  """Creates a new vote or updates an existing one.

  Args:
    blockable: The Blockable being voted for.
    user: The user who cast the vote.
    was_yes_vote: Whether the vote cast was an upvote or downvote.
    vote_weight: The weight of the vote cast.

  Returns:
    The newly-created Vote entity.

  Raises:
    DuplicateVoteError: if the user is attempting to re-cast an identical vote.
  """
  # Retrieve the prior Vote, if one exists.
  vote_key = vote_models.Vote.GetKey(blockable.key, user.key)
  old_vote = vote_key.get()

  # If user has already voted, do one of two things.
  if old_vote:

    # If they're trying to re-vote in the same direction, bail.
    if old_vote.was_yes_vote == was_yes_vote:
      message = 'User %s has already voted for blockable %s' % (
          user.email, blockable.key.id())
      logging.error(message)
      raise DuplicateVoteError(message)

    # Otherwise, archive the previous vote.
    old_vote.key = vote_models.Vote.GetKey(
        blockable.key, user.key, in_effect=False)
    old_vote.put()

  # Create a new Vote entity.
  new_vote = vote_models.Vote(
      key=vote_key,
      user_email=user.email,
      was_yes_vote=was_yes_vote,
      weight=vote_weight,
      candidate_type=blockable.rule_type)
  new_vote.put()

  # Log the vote in BigQuery.
  tables.VOTE.InsertRow(
      sha256=blockable.key.id(),
      timestamp=new_vote.recorded_dt,
      upvote=new_vote.was_yes_vote,
      weight=new_vote.weight,
      platform=blockable.GetPlatformName(),
      target_type=new_vote.candidate_type,
      voter=new_vote.user_email)

  return new_vote


def _CreateRuleChangeSet(blockable, rules_future, new_policy):
  """Creates a RuleChangeSet and trigger an attempted commit."""
  rules = rules_future.get_result()

  # If there are no rules to be created (rare but possible), we can just drop
  # the change set entirely.
  if not rules:
    return

  keys = [rule.key for rule in rules]
  change = rule_models.RuleChangeSet(
      rule_keys=keys, change_type=new_policy, parent=blockable.key)
  change.put()

  # Attempt to commit the change set in a deferred task.
  # NOTE: If we're in a transaction, we should only send out the
  # request to Bit9 once the RuleChangeSet has been successfully created.
  # If we're not in a transaction, this executes immediately.
  key = blockable.key
  callback = lambda: change_set.DeferCommitBlockableChangeSet(key)
  ndb.get_context().call_on_commit(callback)


def _CreateRemovalRules(blockable, existing_rules=None):
  """Creates removal Rules to undo all policy for the given Blockable.

  Args:
    blockable: The Blockable whose Rules need to be reversed.
    existing_rules: The Rules to be reversed. Only applicable for Bit9Binaries.

  Raises:
    UnsupportedClientError: if the specified client is unsupported.
  """
  client = blockable.GetClientName()

  if client == constants.CLIENT.BIT9:

    # Create a REMOVE Rule to counter each existing Rule.
    existing_rules = existing_rules or []
    host_ids = set(rule.host_id for rule in existing_rules)
    removal_rules = []
    for host_id in host_ids:
      removal_rule = _CreateRuleForBlockable(
          blockable, host_id=host_id, policy=constants.RULE_POLICY.REMOVE,
          in_effect=True)
      removal_rules.append(removal_rule)
      removal_rule.InsertBigQueryRow()

    # Persist everything.
    put_futures = ndb.put_multi_async(removal_rules)
    future = datastore_utils.GetMultiFuture(put_futures)
    future.add_callback(
        _CreateRuleChangeSet, blockable,
        datastore_utils.GetNoOpFuture(removal_rules),
        constants.RULE_POLICY.REMOVE)

  elif client == constants.CLIENT.SANTA:
    removal_rule = _CreateRuleForBlockable(
        blockable, policy=constants.RULE_POLICY.REMOVE, in_effect=True)
    removal_rule.put_async()
    removal_rule.InsertBigQueryRow()

  else:
    raise UnsupportedClientError(client)


def _GetBlockable(sha256):
  blockable = binary_models.Blockable.get_by_id(sha256)
  if blockable is None:
    raise BlockableNotFoundError('SHA256: %s' % sha256)
  return blockable


def _GetClient(blockable):
  client = blockable.GetClientName()
  if client not in constants.CLIENT.SET_ALL:
    raise UnsupportedClientError(client)
  return client


def _GetHostIDs(user_key, client):
  """Returns Host IDs for the given user and client.

  Args:
    user_key: Key, The user whose hosts should be fetched.
    client: The client whose hosts should be fetched.

  Returns:
    set<str>, IDs of the retrieved Host entities.

  Raises:
    UnsupportedClientError: if the specified client is unsupported.
  """
  username = user_utils.EmailToUsername(user_key.id())

  if client == constants.CLIENT.BIT9:
    query = host_models.Bit9Host.query(host_models.Bit9Host.users == username)

  elif client == constants.CLIENT.SANTA:
    query = host_models.SantaHost.query(
        host_models.SantaHost.primary_user == username)

  return {host_key.id() for host_key in query.fetch(keys_only=True)}


def _GetUpvoters(blockable):
  # pylint: disable=g-explicit-bool-comparison, singleton-comparison
  upvotes_query = vote_models.Vote.query(
      vote_models.Vote.was_yes_vote == True,
      vote_models.Vote.in_effect == True,
      projection=[vote_models.Vote.user_email],
      ancestor=blockable.key)
  # pylint: enable=g-explicit-bool-comparison, singleton-comparison
  return {ndb.Key(user_models.User, vote.user_email)
          for vote in upvotes_query.fetch()}


def _CheckBlockableFlagStatus(blockable):
  """Check the flagged property of a blockable and fix if needed."""
  change_made = False

  # NOTE: If called within _TransactionalVoting, the returned vote
  # may have been changed within the transaction but the index not yet
  # updated. This means there's a possibility that was_yes_vote is True.
  # pylint: disable=g-explicit-bool-comparison, singleton-comparison
  maybe_down_votes = vote_models.Vote.query(
      vote_models.Vote.was_yes_vote == False,
      vote_models.Vote.in_effect == True,
      ancestor=blockable.key).fetch()
  # pylint: enable=g-explicit-bool-comparison, singleton-comparison
  down_votes_exist = any(not vote.was_yes_vote for vote in maybe_down_votes)

  # If the blockable has any no votes but is not flagged make sure there
  # is a yes vote from someone who can unflag since the last no vote.
  if down_votes_exist and not blockable.flagged:
    # This needs to determine if the blockable should be flagged or not.
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    all_votes = vote_models.Vote.query(
        vote_models.Vote.in_effect == True,
        ancestor=blockable.key).order(-vote_models.Vote.recorded_dt)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    for vote in all_votes:
      if vote.was_yes_vote:
        user = user_models.User.GetById(vote.user_email)
        if user.HasPermission(constants.PERMISSIONS.UNFLAG):
          break
      else:
        logging.info(
            'Blockable %s should have been flagged, but was not.',
            blockable.key.id())
        blockable.flagged = True
        change_made = True
        break

  # If the blockable is flagged, but there are no 'no' votes, unflag it.
  elif not down_votes_exist and blockable.flagged:
    logging.info(
        'Blockable: %s was flagged, but should not be.', blockable.key.id())
    blockable.flagged = False
    change_made = True
  return change_made


def _GetRulesForBlockable(blockable):
  """Queries for all Rules associated with blockable.

  Args:
    blockable: The Blockable whose Rules we want.

  Returns:
    A list of Rules.
  """
  query = rule_models.Rule.query(ancestor=blockable.key)
  # pylint: disable=g-explicit-bool-comparison, singleton-comparison
  query = query.filter(rule_models.Rule.in_effect == True)
  # pylint: enable=g-explicit-bool-comparison, singleton-comparison
  return query.fetch()


def _GetVotingProhibitedReason(blockable_key, current_user=None):
  """Checks if voting is prohibted for the given Blockable.

  Args:
    blockable_key: The NDB Key of the Blockable to check.
    current_user: The optional User whose voting privileges should be
        evaluated against this Blockable. If not provided, the current AppEngine
        user will be used instead.

  Returns:
    One of constants.VOTING_PROHIBITED_REASONS, or None if voting is allowed.

  Raises:
    BlockableNotFoundError: if the given Blockable cannot be found.
  """
  blockable = blockable_key.get()
  if blockable is None:
    raise BlockableNotFoundError('ID: %s' % blockable_key.id())

  # If the user can't vote, just stop right here.
  current_user = current_user or user_models.User.GetOrInsert()
  if not current_user.HasPermission(constants.PERMISSIONS.VOTE):
    return constants.VOTING_PROHIBITED_REASONS.INSUFFICIENT_PERMISSION

  # Checks that are specific to SantaBundles.
  if isinstance(blockable, package_models.SantaBundle):

    # Even admins can't vote on a Bundle that hasn't been uploaded.
    if not blockable.has_been_uploaded:
      return constants.VOTING_PROHIBITED_REASONS.UPLOADING_BUNDLE

    # Only perform flagged binary and cert checks if this is called outside of
    # an NDB transaction. This is due to the fact that HasFlaggedBinary() and
    # HasFlaggedCert() can touch more than 25 entities.
    if not ndb.in_transaction():
      if blockable.HasFlaggedBinary():
        return constants.VOTING_PROHIBITED_REASONS.FLAGGED_BINARY
      elif blockable.HasFlaggedCert():
        return constants.VOTING_PROHIBITED_REASONS.FLAGGED_CERT

  # Checks that are specific to SantaBlockables.
  elif isinstance(blockable, binary_models.SantaBlockable):

    # Voting is not allowed if the binary is signed by a blacklisted cert if the
    # user is not an admin.
    if not current_user.is_admin and blockable.cert_id:
      cert = cert_models.SantaCertificate.get_by_id(blockable.cert_id)
      # pylint: disable=g-explicit-bool-comparison, singleton-comparison
      cert_rules = rule_models.Rule.query(
          rule_models.Rule.in_effect == True,
          rule_models.Rule.policy == constants.RULE_POLICY.BLACKLIST,
          ancestor=cert.key)
      # pylint: enable=g-explicit-bool-comparison, singleton-comparison
      if cert_rules.count() > 0:
        return constants.VOTING_PROHIBITED_REASONS.BLACKLISTED_CERT

  # If the Blockable is in a prohibited state, no one can vote on it.
  if blockable.state in constants.STATE.SET_VOTING_PROHIBITED:
    return constants.VOTING_PROHIBITED_REASONS.PROHIBITED_STATE

  # Only admins are allowed to vote when Blockables are in certain states.
  if blockable.state in constants.STATE.SET_VOTING_ALLOWED_ADMIN_ONLY:
    if current_user.is_admin:
      return None
    else:
      return constants.VOTING_PROHIBITED_REASONS.ADMIN_ONLY

  # Only admins can vote on certs.
  if (isinstance(blockable, cert_models.Certificate)
      and not current_user.is_admin):
    return constants.VOTING_PROHIBITED_REASONS.ADMIN_ONLY

  # The Blockable has to be in a state where voting is allowed.
  if blockable.state not in constants.STATE.SET_VOTING_ALLOWED:
    return constants.VOTING_PROHIBITED_REASONS.PROHIBITED_STATE

  # If all of the above checks pass, there's no reason to prohibit voting.
  return None


def _CreateRuleForBlockable(blockable, **kwargs):
  """Creates a Rule for the given Blockable.

  Args:
    blockable: The Blockable to create a new Rule for.
    **kwargs: Arguments to be passed to the Rule constructor.

  Returns:
    An un-persisted Rule corresponding to the given Blockable.

  Raises:
    UnsupportedClientError: if the specified Blockable came from an unsupported
        client.
  """
  client = blockable.GetClientName()

  if client == constants.CLIENT.BIT9:
    return rule_models.Bit9Rule(
        parent=blockable.key, rule_type=blockable.rule_type, **kwargs)

  elif client == constants.CLIENT.SANTA:
    return rule_models.SantaRule(
        parent=blockable.key, rule_type=blockable.rule_type, **kwargs)

  else:
    raise UnsupportedClientError(client)


def _GetNewScore(initial_score, old_vote=None, new_vote=None):
  """Calculates the expected score of a Blockable.

  Args:
    initial_score: int, The score of the Blockable prior to voting.
    old_vote: The old Vote cast for the Blockable.
    new_vote: The new Vote cast for the Blockable.

  Returns:
    int, The expected score of the Blockable.
  """
  current_score = initial_score
  if old_vote is not None:
    current_score -= old_vote.effective_weight
  if new_vote is not None:
    current_score += new_vote.effective_weight
  return current_score


def IsVotingAllowed(blockable_key, current_user=None):
  """Checks if voting is allowed for the given Blockable.

  Args:
    blockable_key: The NDB Key of the Blockable to check.
    current_user: The optional User whose voting privileges should be
        evaluated against this Blockable. If not provided, the current AppEngine
        user will be used instead.

  Returns:
    A (bool, str) tuple, containing a bool indicating if voting is allowed, and
    one of constants.VOTING_PROHIBITED_REASONS, which will be None if voting is
    allowed.

  Raises:
    BlockableNotFoundError: if the given Blockable cannot be found.
  """
  reason = _GetVotingProhibitedReason(blockable_key, current_user=current_user)
  allowed = reason is None

  logging.info(
      'Voting for %s is %sallowed%s',
      blockable_key.id(),
      '' if allowed else 'not ',
      '' if allowed else ' (%s)' % reason)
  return (allowed, reason)


def Vote(user, sha256, upvote, weight):
  """Casts a vote for the specified Blockable.

  Args:
    user: User entity representing the person casting the vote.
    sha256: The SHA256 of the Blockable being voted on.
    upvote: bool, whether the vote was a 'yes' vote.
    weight: int, The weight with which the vote will be cast. The weight must
        be >= 0 (UNTRUSTED_USERs have vote weight 0).

  Returns:
    The newly-created Vote entity.

  Raises:
    BlockableNotFoundError: if the target blockable ID is not a known Blockable.
    UnsupportedClientError: if the specified Blockable came from an unsupported
        client.
    InvalidVoteWeightError: if the vote weight is less than zero.
  """
  blockable = _GetBlockable(sha256)
  client = _GetClient(blockable)
  if weight < 0:
    raise InvalidVoteWeightError(weight)

  ballot_box = _BALLOT_BOX_MAP[client](sha256)
  ballot_box.Vote(upvote, user, weight)
  return ballot_box.new_vote


def Recount(sha256):
  """Checks votes, state, and rules for the specified Blockable.

  Args:
    sha256: The SHA256 of the Blockable to recount.

  Raises:
    BlockableNotFoundError: if the target blockable ID is not a known Blockable.
    UnsupportedClientError: if the specified Blockable came from an unsupported
        client.
  """
  blockable = _GetBlockable(sha256)
  client = _GetClient(blockable)

  ballot_box = _BALLOT_BOX_MAP[client](sha256)
  ballot_box.Recount()


@ndb.transactional
def Reset(sha256):
  """Resets all policy (i.e. votes, rules, score) for the specified Blockable.

  Args:
    sha256: The SHA256 of the Blockable to recount.

  Raises:
    BlockableNotFoundError: if the target blockable ID is not a known Blockable.
    UnsupportedClientError: if the specified Blockable came from an unsupported
        client.
    OperationNotAllowedError: if a reset is not allowed for some reason.
  """
  blockable = _GetBlockable(sha256)

  # Don't allow SantaBundles to be reset.
  if isinstance(blockable, package_models.SantaBundle):
    raise OperationNotAllowedError('Resetting not supported for Bundles')

  logging.info('Resetting blockable: %s', sha256)
  votes = blockable.GetVotes()

  # Delete existing votes.
  delete_futures = ndb.delete_multi_async(vote.key for vote in votes)

  # Store old vote entities with a different key indicating that they are
  # deactivated so they won't be counted towards the blockable's score.
  archived_votes = votes
  for vote in archived_votes:
    vote.key = vote_models.Vote.GetKey(
        vote.blockable_key, vote.user_key, in_effect=False)
  ndb.put_multi_async(archived_votes)

  # Disable all existing rules.
  existing_rules = _GetRulesForBlockable(blockable)
  for rule in existing_rules:
    rule.MarkDisabled()
  ndb.put_multi_async(existing_rules)

  # Create REMOVE-type rules from the existing blockable rules.
  _CreateRemovalRules(blockable, existing_rules=existing_rules)

  # Ensure past votes are deleted and then reset the blockable score.
  ndb.Future.wait_all(delete_futures)
  blockable.ResetState()


class BallotBox(six.with_metaclass(abc.ABCMeta, object)):
  """Class that modifies the voting state of a given Blockable.

  Args:
    blockable_id: str, The ID of the Blockable entity on which the vote methods
        will operate.
  """

  def __init__(self, blockable_id):
    self.blockable_id = blockable_id

    self._voting_thresholds = settings.VOTING_THRESHOLDS

    self.user = None
    self.blockable = None
    self.old_vote = None
    self.new_vote = None

  def Vote(self, was_yes_vote, user, vote_weight=None):
    """Resolve votes for or against the target blockable.

    Upon successful return, the following attributes on the BallotBox will be
    populated:

      user: The user entity that cast the vote (at the time of the vote).
      blockable: The blockable entity for which the vote was cast with its state
          updated to reflect the new vote.
      old_vote: The vote entity that the new vote replaces. (None if no previous
          vote by the user on this blockable existed).
      new_vote: The vote entity of the newly-cast vote.

    Args:
      was_yes_vote: bool, whether the vote was a 'yes' vote.
      user: User entity representing the person casting the vote.
      vote_weight: int, If provided, the weight with which the vote will be
          cast. The weight must be >= 0 (UNTRUSTED_USERs have vote weight 0).

    Raises:
      BlockableNotFoundError: The target blockable ID is not a known Blockable.
      OperationNotAllowedError: The user may not vote on the blockable. This
          restriction could either be caused by a property of the user (e.g.
          insufficient permissions) or of the blockable (e.g. globally
          whitelisted). The possible causes are enumerated in
          VOTING_PROHIBITED_REASONS.
    """
    self.user = user

    if vote_weight is None:
      vote_weight = self.user.vote_weight

    logging.info(
        'BallotBox.Vote called with '
        '(blockable=%s, was_yes_vote=%s, user=%s, weight=%s',
        self.blockable_id, was_yes_vote, self.user.email, vote_weight)

    self.blockable = _GetBlockable(self.blockable_id)
    initial_score = self.blockable.score
    initial_state = self.blockable.state

    # Check is voting is allowed once before calling _TransactionalVoting() in
    # order to work around the cross-group transaction limitation encountered
    # by larger macOS bundles.
    allowed, reason = IsVotingAllowed(
        self.blockable.key, current_user=self.user)
    if not allowed:
      message = 'Voting is not allowed (%s)' % reason
      raise OperationNotAllowedError(message)

    # Perform the vote.
    self._TransactionalVoting(self.blockable_id, was_yes_vote, vote_weight)

    self.blockable = _GetBlockable(self.blockable_id)
    new_score = self.blockable.score
    new_state = self.blockable.state

    if initial_score != new_score:
      logging.info(
          'Blockable %s changed score from %d to %d',
          self.blockable.key.id(), initial_score, new_score)

      self.blockable.InsertBigQueryRow(
          constants.BLOCK_ACTION.SCORE_CHANGE,
          timestamp=self.blockable.updated_dt)

    if initial_state != new_state:
      logging.info(
          'Blockable %s changed state from %s to %s', self.blockable.key.id(),
          initial_state, new_state)

    # Perform local whitelisting procedures.
    # NOTE: Local whitelisting has to be handled outside the
    # transaction because of its non-ancestor queries on Host entities.
    if new_state == constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING:

      # If it just crossed the local threshold, whitelist for all voters.
      if initial_state != new_state:
        self._LocallyWhitelist().get_result()

      # Otherwise, the voter was just requesting that they be able to run it
      # too, so only whitelist it for them.
      elif was_yes_vote:
        self._LocallyWhitelist(user_keys=[self.user.key]).get_result()

    # NOTE: Blockable.score is not properly updated by puts executed
    # within the transaction as the Vote ancestor query in
    # Blockable._CalculateScore() does not reflect the newly-created Vote
    # entity. As such, we must 'turn the crank' and force a recount.
    ndb.transaction(lambda: self.blockable.key.get().put())
    self.blockable = self.blockable.key.get()

    # Record Lookup Metrics for the vote.
    if not isinstance(self.blockable, package_models.Package):
      reason = (
          constants.ANALYSIS_REASON.UPVOTE
          if was_yes_vote
          else constants.ANALYSIS_REASON.DOWNVOTE)
      metrics.DeferLookupMetric(self.blockable.key.id(), reason)

  @ndb.transactional(xg=True)
  def _TransactionalVoting(self, blockable_id, was_yes_vote, vote_weight):
    """Performs part of the voting that should be handled in a transaction."""

    # To accommodate transaction retries, re-get the Blockable entity at the
    # start of each transaction. This ensures up-to-date state+score values.
    self.blockable = _GetBlockable(blockable_id)

    # Verify that voting is allowed within a transaction, minus the macOS bundle
    # checks which can exceed the cross-group transaction limit.
    allowed, reason = IsVotingAllowed(
        self.blockable.key, current_user=self.user)
    if not allowed:
      message = 'Voting is not allowed (%s)' % reason
      raise OperationNotAllowedError(message)

    if (isinstance(self.blockable, package_models.SantaBundle)
        and not was_yes_vote):
      raise OperationNotAllowedError('Downvoting not supported for Bundles')

    initial_state = self.blockable.state
    logging.info('Initial blockable state: %s', initial_state)

    initial_score = self.blockable.score
    self.new_vote = _CreateOrUpdateVote(
        self.blockable, self.user, was_yes_vote, vote_weight)
    assert self.new_vote is not None

    new_score = _GetNewScore(
        initial_score, old_vote=self.old_vote, new_vote=self.new_vote)
    self._UpdateBlockable(new_score)

    return initial_state

  def _UpdateBlockable(self, new_score):
    """Modifies the blockable according to the updated vote score."""
    if self.new_vote.was_yes_vote:
      # Unflag the blockable on a privileged upvote.
      if self.blockable.flagged:
        if self.user.HasPermission(constants.PERMISSIONS.UNFLAG):
          self.blockable.flagged = False
        else:
          # Double-checks that there's an extant downvote.
          _CheckBlockableFlagStatus(self.blockable)
      # If the blockable is marked SUSPECT, only permit state change if the user
      # is authorized to do so.
      if (self.blockable.state != constants.STATE.SUSPECT or
          self.user.HasPermission(constants.PERMISSIONS.MARK_MALWARE)):
        self._CheckAndSetBlockableState(new_score)
    else:
      self.blockable.flagged = True
      self._CheckAndSetBlockableState(new_score)
      # A downvote from an authorized user marks a blockable as SUSPECT.
      if (self.user.HasPermission(constants.PERMISSIONS.MARK_MALWARE) and
          self.blockable.state not in constants.STATE.SET_BANNED):
        self.blockable.ChangeState(constants.STATE.SUSPECT)

    # NOTE: Blockable.score will not be updated properly for a
    # newly-cast Vote (i.e. not a changed vote) because the new Vote entity
    # won't be created until the transaction has been committed.
    self.blockable.put()

  @ndb.transactional(xg=True)
  def Recount(self):
    """Checks votes, state, and rules for the target blockable."""
    logging.info('Recount for blockable: %s', self.blockable_id)

    self.blockable = binary_models.Blockable.get_by_id(self.blockable_id)

    # Then check to see if the blockable should be flagged and if it is.
    change_made = _CheckBlockableFlagStatus(self.blockable)

    # Check that the blockable's state is set correctly.
    change_made = self._AuditBlockableState() or change_made

    # Finally check that the right rules exist and are in effect.
    # Since this doesn't alter the blockable the change_made flag isn't used.
    self._CheckRules()

    if change_made:
      logging.info(
          'Recount changed blockable %s, putting to datastore',
          self.blockable.key.id())
      self.blockable.put()
      return True
    else:
      return False

  def _CheckAndSetBlockableState(self, score):
    """Checks a blockable's score and changes its state if needed."""

    # Shortened because 50 characters is a bit much for an identifier
    local_whitelisting = constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING

    if score >= self._voting_thresholds[
        constants.STATE.GLOBALLY_WHITELISTED]:
      if self.blockable.state != constants.STATE.GLOBALLY_WHITELISTED:
        logging.info(
            'Setting state for blockable %s to globally whitelisted',
            self.blockable.key.id())
        self.blockable.ChangeState(constants.STATE.GLOBALLY_WHITELISTED)
        self._GloballyWhitelist().get_result()
        return True
    elif (local_whitelisting in self._voting_thresholds and
          score >= self._voting_thresholds[local_whitelisting]):
      if self.blockable.state != local_whitelisting:
        logging.info(
            'Setting state for blockable %s to locally whitelistable.',
            self.blockable.key.id())
        self.blockable.ChangeState(local_whitelisting)
        return True
    elif score <= self._voting_thresholds[constants.STATE.BANNED]:
      if self.blockable.state not in constants.STATE.SET_BANNED:
        logging.info(
            'Setting state for blockable %s to banned.',
            self.blockable.key.id())
        self.blockable.ChangeState(constants.STATE.BANNED)
        self._Blacklist().get_result()
        return True
    elif self.blockable.state != constants.STATE.UNTRUSTED:
      logging.info(
          'Setting state for blockable %s to untrusted.',
          self.blockable.key.id())
      self.blockable.ChangeState(constants.STATE.UNTRUSTED)
      return True
    return False

  @ndb.tasklet
  def _GloballyWhitelist(self):
    """Makes sure there is only one rule and it is the right one."""
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    existing_rules = rule_models.Rule.query(
        rule_models.Rule.rule_type == self.blockable.rule_type,
        rule_models.Rule.in_effect == True,
        ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison

    # Disable all local or blacklisting rules.
    changed_rules = []
    for rule in existing_rules:
      if rule.policy != constants.RULE_POLICY.WHITELIST or rule.host_id:
        rule.MarkDisabled()
        changed_rules.append(rule)

    # Create the new globally whitelist rule.
    whitelist_rule = _CreateRuleForBlockable(
        self.blockable, policy=constants.RULE_POLICY.WHITELIST, in_effect=True)
    whitelist_rule.InsertBigQueryRow()

    # Put all new/modified Rules.
    yield ndb.put_multi_async(changed_rules + [whitelist_rule])
    raise ndb.Return([whitelist_rule])

  @ndb.tasklet
  def _CreateNewLocalWhitelistingRules(self, local_rule_dict):
    """Creates any missing local Rules for a given Blockable.

    Args:
      local_rule_dict: A dict which maps user Keys to lists of host IDs
          belonging to those users. Each (user_key, host_id) pair represents a
          new local whitelisting Rule to be created for a given Blockable (if
          one does not already exist).

    Returns:
      A list of newly-created Rules.
    """
    # Query for all active local whitelisting rules for this blockable.
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    existing_rule_query = rule_models.Rule.query(
        rule_models.Rule.policy == constants.RULE_POLICY.WHITELIST,
        rule_models.Rule.in_effect == True,
        rule_models.Rule.rule_type == self.blockable.rule_type,
        ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    existing_rules = yield existing_rule_query.fetch_async()

    # Create a set of (user_key, host_id) tuples so we can easily determine if a
    # new local rule needs to be created for a given (user_key, host_id) pair.
    existence_set = set((r.user_key, r.host_id) for r in existing_rules)

    new_rules = []

    for user_key, host_ids in six.iteritems(local_rule_dict):

      logging.info(
          'Locally whitelisting %s for %s, on the following hosts: %s',
          self.blockable.key.id(), user_key.id(), host_ids)

      for host_id in host_ids:

        # If a Rule already exists for this user and host, skip it.
        if (user_key, host_id) in existence_set:
          logging.info(
              'Rule already exists for %s on %s', user_key.id(), host_id)

        # Otherwise, create a new Rule to persist.
        else:
          logging.info('Creating new Rule for %s on %s', user_key.id(), host_id)
          new_rule = _CreateRuleForBlockable(
              self.blockable, policy=constants.RULE_POLICY.WHITELIST,
              in_effect=True, host_id=host_id, user_key=user_key)
          new_rule.InsertBigQueryRow()
          new_rules.append(new_rule)

    # Once we've accumulated all the new Rules needed for this Blockable,
    # persist them all at once.
    logging.info(
        'Creating %d new Rules for %s', len(new_rules), self.blockable.key.id())
    yield ndb.put_multi_async(new_rules)
    raise ndb.Return(new_rules)

  def _LocallyWhitelist(self, user_keys=None):
    """Locally whitelists a Blockable for the provided users.

    Args:
      user_keys: list<Key>, A list of users for whom the Blockable should be
          locally whitelisted. If not provided, defaults to all prior voters.

    Returns:
      A Future corresponding to the newly-persisted Rules.
    """
    # If no users are specified, default to the voters.
    if not user_keys:
      user_keys = _GetUpvoters(self.blockable)
    logging.info(
        'Locally whitelisting %s for the following users: %s',
        self.blockable.key.id(),
        sorted([user_key.id() for user_key in user_keys]))

    # For each user, retrieve a list of associated host_ids. Compose a dict
    # which maps the user to their host_ids. This has to be done outside of the
    # upcoming transaction, otherwise it would become cross-group.
    client = _GetClient(self.blockable)
    local_rule_dict = {
        user_key: sorted(list(_GetHostIDs(user_key, client)))
        for user_key in user_keys}

    # Initiate a transaction to retrieve any existing local whitelisting rules
    # for this blockable, and create any that are missing.
    return ndb.transaction_async(
        lambda: self._CreateNewLocalWhitelistingRules(local_rule_dict))

  @ndb.tasklet
  def _Blacklist(self):
    """Creates a global blacklist rule and disables all whitelist rules."""
    # Remove all active whitelist rules.
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    rule_query = rule_models.Rule.query(
        rule_models.Rule.policy == constants.RULE_POLICY.WHITELIST,
        rule_models.Rule.in_effect == True,
        ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    existing_rules = rule_query.fetch()

    changed_rules = []
    for rule in existing_rules:
      rule.MarkDisabled()
      changed_rules.append(rule)

    # Create global blacklist rule.
    blacklist_rule = _CreateRuleForBlockable(
        self.blockable, policy=constants.RULE_POLICY.BLACKLIST, in_effect=True)
    blacklist_rule.InsertBigQueryRow()

    # Put all new/modified Rules.
    yield ndb.put_multi_async(changed_rules + [blacklist_rule])
    raise ndb.Return([blacklist_rule])

  def _AuditBlockableState(self):
    """Audit the state of a blockable against past voting."""
    if self.blockable.state == constants.STATE.SUSPECT:
      # If the current state is Suspect, make sure there was a no vote from
      # a qualified user. This does not check to see if a blockable that
      # is not suspect should be.
      change_made = False
      sorted_votes = reversed(sorted(
          self.blockable.GetVotes(), key=lambda vote: vote.recorded_dt))
      for vote in sorted_votes:
        user = user_models.User.GetById(vote.user_email)
        if user.HasPermission(constants.PERMISSIONS.MARK_MALWARE):
          if vote.was_yes_vote:
            logging.info(
                'Blockable %s was suspect, but should not be because there was '
                'a subsequent authoritative yes vote.',
                self.blockable.key.id())
            change_made = self._CheckAndSetBlockableState(
                self.blockable.score)
          break
      else:
        logging.info(
            'Blockable %s was suspect, but should not be because no '
            'authoritative no vote was found.',
            self.blockable.key.id())
        change_made = self._CheckAndSetBlockableState(self.blockable.score)
    # If the blockable is not suspect, just check and set state.
    else:
      change_made = self._CheckAndSetBlockableState(self.blockable.score)
    return change_made

  def _CheckRules(self):
    """Checks that only appropriate rules exist for a blockable."""
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    all_rules = rule_models.Rule.query(
        rule_models.Rule.in_effect == True, ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    global_whitelist_rule_exists = False
    blacklist_rule_exists = False
    modified_rules = []
    for rule in all_rules:
      # Check to make sure none of the rules that exist are inappropriate.
      if self.blockable.rule_type != rule.rule_type:
        # Make sure the rule is for the right sort of blockable.
        rule.MarkDisabled()
        modified_rules.append(rule)
      elif self.blockable.state == constants.STATE.UNTRUSTED:
        # Untrusted blockables might be locally whitelisted if they were
        # whitelisted when in a different state. They cannot be blacklisted or
        # globally whitelisted.
        if not rule.host_id:
          logging.info('Rule %s for blockable %s in state %s found '
                       'and marked not in effect.', rule.key.id(),
                       self.blockable.key.id(), self.blockable.state)
          rule.MarkDisabled()
          modified_rules.append(rule)
      elif rule.policy == constants.RULE_POLICY.WHITELIST:
        if self.blockable.state in constants.STATE.SET_WHITELISTABLE:
          if not rule.host_id:
            global_whitelist_rule_exists = True
        else:
          logging.info('Whitelist rule %s for blockable %s in state %s found '
                       'and marked not in effect.', rule.key.id(),
                       self.blockable.key.id(), self.blockable.state)
          rule.MarkDisabled()
          modified_rules.append(rule)
      else:
        if self.blockable.state in constants.STATE.SET_BANNED:
          blacklist_rule_exists = True
        else:
          logging.info('Blacklist rule %s for blockable %s in state %s found '
                       'and marked not in effect.', rule.key.id(),
                       self.blockable.key.id(), self.blockable.state)
          rule.MarkDisabled()
          modified_rules.append(rule)
    ndb.put_multi(modified_rules)

    # Check to make sure there is at least one appropriate rule created.
    if (self.blockable.state == constants.STATE.GLOBALLY_WHITELISTED and
        not global_whitelist_rule_exists):
      logging.info('No global whitelist rule for blockable %s in '
                   'state %s.', self.blockable.key.id(), self.blockable.state)
      self._GloballyWhitelist().get_result()
    elif (self.blockable.state == constants.STATE.BANNED and
          not blacklist_rule_exists):
      logging.info('No blacklist rule for blockable %s in state %s.',
                   self.blockable.key.id(), self.blockable.state)
      self._Blacklist().get_result()


class SantaBallotBox(BallotBox):
  """Class that modifies the voting state of a SantaBlockable."""

  def _LocallyWhitelist(self, user_keys=None):
    future = super(SantaBallotBox, self)._LocallyWhitelist(user_keys=user_keys)
    return future


class Bit9BallotBox(BallotBox):
  """Class that modifies the voting state of a Bit9Blockable."""

  def _GloballyWhitelist(self):
    future = super(Bit9BallotBox, self)._GloballyWhitelist()
    future.add_callback(
        _CreateRuleChangeSet, self.blockable, future,
        constants.RULE_POLICY.WHITELIST)
    return future

  def _LocallyWhitelist(self, user_keys=None):
    future = super(Bit9BallotBox, self)._LocallyWhitelist(user_keys=user_keys)
    future.add_callback(
        _CreateRuleChangeSet, self.blockable, future,
        constants.RULE_POLICY.WHITELIST)
    return future

  def _Blacklist(self):
    future = super(Bit9BallotBox, self)._Blacklist()
    future.add_callback(
        _CreateRuleChangeSet, self.blockable, future,
        constants.RULE_POLICY.BLACKLIST)
    return future


_BALLOT_BOX_MAP = {
    constants.CLIENT.SANTA: SantaBallotBox,
    constants.CLIENT.BIT9: Bit9BallotBox,
}

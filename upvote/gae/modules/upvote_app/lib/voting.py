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

import abc
import httplib
import logging

from google.appengine.api import urlfetch
from google.appengine.ext import ndb

from upvote.gae.datastore import utils as model_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bigquery
from upvote.gae.datastore.models import bit9
from upvote.gae.datastore.models import santa
from upvote.gae.shared.binary_health import metrics
from upvote.gae.shared.common import intermodule
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import taskqueue_utils
from upvote.gae.shared.common import user_map
from upvote.shared import constants


class Error(Exception):
  """Base error class for the voting module."""


class BlockableNotFound(Error):
  """The blockable ID provided does not correspond to a Blockable entity."""


class DuplicateVoteError(Error):
  """Error used when user has already cast a vote for given blockable."""


class OperationNotAllowed(Error):
  """Error raised when operation not permitted on the given blockable."""


class UnsupportedBlockableType(Error):
  """Error raised when BallotBox does not support the blockable type."""


def GetBallotBox(blockable_id):
  """Instantiates a BallotBox object corresponding to the blockable type.

  This allows users who don't know/care about the type of blockable they're
  operating on to instantiate the correct BallotBox subclass.

  Args:
    blockable_id: str, The ID of the blockable to modify the voting state.

  Returns:
    A BallotBox subclass instance that supports voting on the given Blockable.

  Raises:
    BlockableNotFound: No blockable was found with the provided ID.
    UnsupportedBlockableType: There is no BallotBox type that supports the
        provided Blockable's type.
  """
  blockable = base.Blockable.get_by_id(blockable_id)
  if blockable is None:
    raise BlockableNotFound('Blockable does not exist: %s' % blockable_id)
  elif isinstance(blockable, SantaBallotBox.BLOCKABLE_CLASSES):
    return SantaBallotBox(blockable_id)
  elif isinstance(blockable, Bit9BallotBox.BLOCKABLE_CLASSES):
    return Bit9BallotBox(blockable_id)
  else:
    raise UnsupportedBlockableType(
        'No BallotBox class associated with Blockable type: %s' % (
            blockable.__class__))


class BallotBox(object):
  """Class that modifies the voting state of a given Blockable.

  Args:
    blockable_id: str, The ID of the Blockable entity on which the vote methods
        will operate.
  """

  __metaclass__ = abc.ABCMeta

  BLOCKABLE_CLASSES = (base.Blockable,)

  def __init__(self, blockable_id):
    self.blockable_id = blockable_id

    self._voting_thresholds = settings.VOTING_THRESHOLDS

    self.user = None
    self.blockable = None
    self.old_vote = None
    self.new_vote = None

  def _ValidateBlockable(self):
    if self.blockable is None:
      raise BlockableNotFound(
          'Blockable with hash {} not found'.format(self.blockable_id))
    elif not isinstance(self.blockable, self.BLOCKABLE_CLASSES):
      raise UnsupportedBlockableType(
          '{} may not operate on blockables of type {}'.format(
              self.__class__.__name__, self.blockable.__class__.__name__))

  def _CheckVotingAllowed(self):
    """Check whether the voting on the blockable is permitted.

    **NOTE** This method is a noop outside of a transaction (i.e. outside of
    _TransactionalVoting).

    Raises:
      OperationNotAllowed: The user may not vote on the blockable due to one of
          the VOTING_PROHIBITED_REASONS.
    """
    if not ndb.in_transaction():
      return

    allowed, reason = self.blockable.IsVotingAllowed(current_user=self.user)
    if not allowed:
      message = 'Voting on this Blockable is not allowed (%s)' % reason
      logging.warning(message)
      raise OperationNotAllowed(message)

  def ResolveVote(self, was_yes_vote, user, vote_weight=None):
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
      BlockableNotFound: The target blockable ID is not a known Blockable.
      OperationNotAllowed: The user may not vote on the blockable. This
          restriction could either be caused by a property of the user (e.g.
          insufficient permissions) or of the blockable (e.g. globally
          whitelisted). The possible causes are enumerated in
          VOTING_PROHIBITED_REASONS.
      ValueError: vote_weight is negative.
    """
    self.user = user

    if vote_weight is None: vote_weight = self.user.vote_weight
    if vote_weight < 0:
      raise ValueError('Invalid vote_weight: %d' % vote_weight)

    logging.debug(
        'BallotBox.ResolveVote called with '
        '(blockable=%s, was_yes_vote=%s, user=%s, weight=%s',
        self.blockable_id, was_yes_vote, self.user.email, vote_weight)

    # NOTE: This check only has an effect for SantaBundles. The logic
    # is explained further in SantaBallotBox._CheckVotingAllowed docstring but
    # suffice it to say that this checks whether the bundle has flagged binaries
    # or certs (this check can't be run from the transaction).
    self._CheckVotingAllowed()

    # Perform the vote.
    initial_state = self._TransactionalVoting(
        self.blockable_id, was_yes_vote, vote_weight)
    assert self.blockable is not None

    if initial_state != self.blockable.state:
      logging.info(
          'Blockable %s changed state from %s to %s', self.blockable.key.id(),
          initial_state, self.blockable.state)

    # Perform local whitelisting procedures.
    # NOTE: Local whitelisting has to be handled outside the
    # transaction because of its non-ancestor queries on Host entities.
    if self.blockable.state == constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING:
      if initial_state != self.blockable.state:
        self._LocallyWhitelistForAllVoters().get_result()
      elif was_yes_vote:
        self._LocallyWhitelistForCurrentVoter().get_result()

    # NOTE: Blockable.score is not properly updated by puts executed
    # within the transaction as the Vote ancestor query in
    # Blockable._CalculateScore() does not reflect the newly-created Vote
    # entity. As such, we must 'turn the crank' and force a recount.
    ndb.transaction(lambda: self.blockable.key.get().put())
    self.blockable = self.blockable.key.get()

    # Record Lookup Metrics for the vote.
    if not isinstance(self.blockable, base.Package):
      reason = (
          constants.ANALYSIS_REASON.UPVOTE
          if was_yes_vote
          else constants.ANALYSIS_REASON.DOWNVOTE)
      metrics.DeferLookupMetric(self.blockable.key.id(), reason)

  @ndb.transactional(xg=True)
  @taskqueue_utils.GroupTransactionalDefers
  def _TransactionalVoting(self, blockable_id, was_yes_vote, vote_weight):
    """Performs part of the voting that should be handled in a transaction."""

    # To accommodate transaction retries, re-get the Blockable entity at the
    # start of each transaction. This ensures up-to-date state+score values.
    self.blockable = base.Blockable.get_by_id(blockable_id)
    self._ValidateBlockable()
    self._CheckVotingAllowed()

    if isinstance(self.blockable, santa.SantaBundle) and not was_yes_vote:
      raise OperationNotAllowed('Downvoting not supported for Bundles')

    initial_state = self.blockable.state
    logging.debug('Initial blockable state: %s', initial_state)

    initial_score = self.blockable.score
    self._CreateOrUpdateVote(was_yes_vote, vote_weight)
    assert self.new_vote is not None

    new_score = self._GetNewScore(initial_score)

    logging.debug(
        'Score for Blockable %s changing from %d to %d',
        self.blockable.key.id(), initial_score, new_score)

    self._UpdateBlockable(new_score)

    # Persist the new score change.
    self.blockable.PersistRow(
        constants.BLOCK_ACTION.SCORE_CHANGE,
        self.blockable.updated_dt)

    return initial_state

  def _CreateOrUpdateVote(self, was_yes_vote, vote_weight):
    """Creates a new vote or updates an existing one."""
    vote_key = base.Vote.GetKey(self.blockable.key, self.user.key)
    self.old_vote = vote_key.get()

    # If user has already voted, archive the previous vote.
    if self.old_vote is not None:
      if self.old_vote.was_yes_vote == was_yes_vote:
        raise DuplicateVoteError(
            'The user %s has already cast a %s vote for blockable %s' % (
                self.user.email, was_yes_vote, self.blockable.key.id()))

      # Archive the previous vote.
      self.old_vote.key = base.Vote.GetKey(
          self.blockable.key, self.user.key, in_effect=False)
      self.old_vote.put()

    self.new_vote = base.Vote(
        key=vote_key,
        user_email=self.user.email,
        was_yes_vote=was_yes_vote,
        weight=vote_weight,
        candidate_type=self.blockable.rule_type)
    self.new_vote.put()

    bigquery.VoteRow.DeferCreate(
        sha256=self.blockable.key.id(),
        timestamp=self.new_vote.recorded_dt,
        upvote=self.new_vote.was_yes_vote,
        weight=self.new_vote.weight,
        platform=self.blockable.GetPlatformName(),
        target_type=self.new_vote.candidate_type,
        voter=self.new_vote.user_email)

  def _GetNewScore(self, initial_score):
    """Calculates the expected score of the blockable.

    Args:
      initial_score: int, The score of the blockable prior to voting.

    Returns:
      int, The expected score of the blockable.
    """
    current_score = initial_score
    if self.old_vote is not None:
      current_score -= self.old_vote.effective_weight
    if self.new_vote is not None:
      current_score += self.new_vote.effective_weight
    return current_score

  def _UpdateBlockable(self, new_score):
    """Modifies the blockable according to the updated vote score."""
    if self.new_vote.was_yes_vote:
      # Unflag the blockable on a privileged upvote.
      if self.blockable.flagged:
        if self.user.HasPermissionTo(constants.PERMISSIONS.UNFLAG):
          self.blockable.flagged = False
        else:
          # Double-checks that there's an extant downvote.
          self._CheckBlockableFlagStatus()
      # If the blockable is marked SUSPECT, only permit state change if the user
      # is authorized to do so.
      if (self.blockable.state != constants.STATE.SUSPECT or
          self.user.HasPermissionTo(constants.PERMISSIONS.MARK_MALWARE)):
        self._CheckAndSetBlockableState(new_score)
    else:
      self.blockable.flagged = True
      self._CheckAndSetBlockableState(new_score)
      # A downvote from an authorized user marks a blockable as SUSPECT.
      if (self.user.HasPermissionTo(constants.PERMISSIONS.MARK_MALWARE) and
          self.blockable.state not in constants.STATE.SET_BANNED):
        self.blockable.ChangeState(constants.STATE.SUSPECT)

    # NOTE: Blockable.score will not be updated properly for a
    # newly-cast Vote (i.e. not a changed vote) because the new Vote entity
    # won't be created until the transaction has been committed.
    self.blockable.put()

  @abc.abstractmethod
  def _GenerateRule(self, **kwargs):
    """Generate the rule for the blockable being voted on.

    Args:
      **kwargs: Arguments to be passed to the Rule constructor for all returned
          rules.
    Returns:
      An un-persisted Rule corresponding to the blockable being voted on.
    """

  @ndb.transactional(xg=True)
  @taskqueue_utils.GroupTransactionalDefers
  def Recount(self):
    """Checks votes, state, and rules for the target blockable."""
    logging.debug('Recount for blockable: %s', self.blockable_id)

    self.blockable = base.Blockable.get_by_id(self.blockable_id)
    if self.blockable is None:
      self._ValidateBlockable()

    # Then check to see if the blockable should be flagged and if it is.
    change_made = self._CheckBlockableFlagStatus()

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

  @abc.abstractmethod
  def _GenerateRemoveRules(self, existing_rules):
    """Creates removal rules to undo all policy for the target blockable."""

  @ndb.transactional
  @taskqueue_utils.GroupTransactionalDefers
  def Reset(self, user):
    """Resets all policy (i.e. votes, rules, score) for the target blockable.

    Args:
      user: The user performing the vote reset.

    Raises:
      BlockableNotFound: The target blockable ID is not a known Blockable.
    """
    logging.info('Resetting blockable: %s', self.blockable_id)

    self.blockable = base.Blockable.get_by_id(self.blockable_id)
    if self.blockable is None:
      self._ValidateBlockable()

    # Record an audit log entry for each vote to be deactivated.
    votes = self.blockable.GetVotes()
    for vote in votes:
      message = 'Deleting vote because blockable was reset. %s for %s' % (
          vote.user_email, vote.key.parent().id())
      base.AuditLog.Create(vote, message, user=user.email)

    # Delete existing votes.
    delete_futures = ndb.delete_multi_async(vote.key for vote in votes)

    # Store old vote entities with a different key indicating that they are
    # deactivated so they won't be counted towards the blockable's score.
    archived_votes = votes
    for vote in archived_votes:
      vote.key = base.Vote.GetKey(
          vote.blockable_key, vote.user_key, in_effect=False)
    ndb.put_multi_async(archived_votes)

    # Disable all existing rules.
    existing_rules = self.blockable.GetRules()
    for rule in existing_rules:
      rule.MarkDisabled()
    ndb.put_multi_async(existing_rules)

    # Create REMOVE-type rules from the existing blockable rules.
    self._GenerateRemoveRules(existing_rules)

    # Ensure past votes are deleted and then reset the blockable score.
    ndb.Future.wait_all(delete_futures)
    self.blockable.ResetState()

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
    # pylint: disable=g-explicit-bool-comparison
    existing_rules = base.Rule.query(
        base.Rule.rule_type == self.blockable.rule_type,
        base.Rule.in_effect == True,
        ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison

    # Disable all local or blacklisting rules.
    changed_rules = []
    for rule in existing_rules:
      if rule.policy != constants.RULE_POLICY.WHITELIST or rule.host_id:
        rule.MarkDisabled()
        changed_rules.append(rule)

    # Create the new globally whitelist rule.
    whitelist_rule = self._GenerateRule(
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True)

    # Put all new/modified Rules.
    yield ndb.put_multi_async(changed_rules + [whitelist_rule])
    raise ndb.Return([whitelist_rule])

  @ndb.tasklet
  def _LocallyWhitelist(self, user_key, host_ids):
    """Locally whitelists the blockable on the provided hosts.

    Args:
      user_key: Key, The user for which local whitelist rules should be created.
      host_ids: list<str>, The list of host IDs for which local whitelist rules
          should be created if they don't already exist.

    Returns:
      The list of rules that were created.
    """
    logging.debug(
        'Locally whitelisting %s for %s, on the following hosts: %s',
        self.blockable.key.id(), user_key.id(), host_ids)
    new_rules = []
    for host_id in host_ids:
      # Check for exisiting rule.
      # pylint: disable=g-explicit-bool-comparison
      existing_rule_query = base.Rule.query(
          base.Rule.policy == constants.RULE_POLICY.WHITELIST,
          base.Rule.in_effect == True,
          base.Rule.rule_type == self.blockable.rule_type,
          base.Rule.host_id == host_id,
          base.Rule.user_key == user_key,
          ancestor=self.blockable.key)
      # pylint: enable=g-explicit-bool-comparison
      # If there isn't one, make one, increment count and put rule.
      rule_exists = yield existing_rule_query.count_async(limit=1)
      if rule_exists:
        logging.debug('Rule already exists for host %s, skipping...', host_id)
      else:
        logging.debug('Creating Rule for host %s', host_id)
        rule = self._GenerateRule(
            policy=constants.RULE_POLICY.WHITELIST,
            in_effect=True,
            host_id=host_id,
            user_key=user_key)
        new_rules.append(rule)
    logging.debug('Creating %d new Rules for %s', len(new_rules), user_key.id())
    yield ndb.put_multi_async(new_rules)
    raise ndb.Return(new_rules)

  @abc.abstractmethod
  def _GetHostsToWhitelist(self, user_key):
    """Returns hosts for which whitelist rules should be created for a user.

    Args:
      user_key: Key, The user for whom hosts to whitelist should be fetched.

    Returns:
      set<str>, IDs of Hosts for which whitelist rules should be created.
    """

  def _GetUpvoters(self):
    # pylint: disable=g-explicit-bool-comparison
    upvotes_query = base.Vote.query(
        base.Vote.was_yes_vote == True,
        base.Vote.in_effect == True,
        projection=[base.Vote.user_email],
        ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison
    return {ndb.Key(base.User, vote.user_email)
            for vote in upvotes_query.fetch()}

  def _LocallyWhitelistForVoter(self, user_key):
    """Creates whitelist rules for a voter."""
    host_ids = sorted(list(self._GetHostsToWhitelist(user_key)))
    return ndb.transaction_async(
        lambda: self._LocallyWhitelist(user_key, host_ids))

  def _LocallyWhitelistForAllVoters(self):
    upvoter_keys = self._GetUpvoters()
    logging.debug(
        'Locally whitelisting %s for all voters: %s', self.blockable.key.id(),
        sorted(key.id() for key in upvoter_keys))
    return model_utils.GetChainingMultiFuture(
        self._LocallyWhitelistForVoter(key) for key in upvoter_keys)

  def _LocallyWhitelistForCurrentVoter(self):
    return self._LocallyWhitelistForVoter(self.user.key)

  @ndb.tasklet
  def _Blacklist(self):
    """Creates a global blacklist rule and disables all whitelist rules."""
    # Remove all active whitelist rules.
    # pylint: disable=g-explicit-bool-comparison
    rule_query = base.Rule.query(
        base.Rule.policy == constants.RULE_POLICY.WHITELIST,
        base.Rule.in_effect == True,
        ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison
    existing_rules = rule_query.fetch()

    changed_rules = []
    audit_logs = []
    for rule in existing_rules:
      rule.MarkDisabled()
      changed_rules.append(rule)

      message = 'Disabling whitelist rule because blockable is now banned.'
      audit_logs.append(base.AuditLog.New(rule, message))

    # Create global blacklist rule.
    blacklist_rule = self._GenerateRule(
        policy=constants.RULE_POLICY.BLACKLIST,
        in_effect=True)

    # Put all new/modified Rules and AuditLogs.
    yield ndb.put_multi_async(changed_rules + [blacklist_rule] + audit_logs)
    raise ndb.Return([blacklist_rule])

  def _CheckBlockableFlagStatus(self):
    """Check the flagged property of a blockable and fix if needed."""
    change_made = False

    # NOTE: If called within _TransactionalVoting, the returned vote
    # may have been changed within the transaction but the index not yet
    # updated. This means there's a possibility that was_yes_vote is True.
    # pylint: disable=g-explicit-bool-comparison
    maybe_down_votes = base.Vote.query(
        base.Vote.was_yes_vote == False,
        base.Vote.in_effect == True,
        ancestor=self.blockable.key).fetch()
    # pylint: enable=g-explicit-bool-comparison
    down_votes_exist = any(not vote.was_yes_vote for vote in maybe_down_votes)

    # If the blockable has any no votes but is not flagged make sure there
    # is a yes vote from someone who can unflag since the last no vote.
    if down_votes_exist and not self.blockable.flagged:
      # This needs to determine if the blockable should be flagged or not.
      # pylint: disable=g-explicit-bool-comparison
      all_votes = base.Vote.query(
          base.Vote.in_effect == True,
          ancestor=self.blockable.key).order(-base.Vote.recorded_dt)
      # pylint: enable=g-explicit-bool-comparison
      for vote in all_votes:
        if vote.was_yes_vote:
          user = base.User.GetById(vote.user_email)
          if user.HasPermissionTo(constants.PERMISSIONS.UNFLAG):
            break
        else:
          logging.info(
              'Blockable %s should have been flagged, but was not.',
              self.blockable.key.id())
          self.blockable.flagged = True
          change_made = True
          break
    # If the blockable is flagged, but there are no 'no' votes, unflag it.
    elif not down_votes_exist and self.blockable.flagged:
      logging.info('Blockable: %s was flagged, but should not be.',
                   self.blockable.key.id())
      self.blockable.flagged = False
      change_made = True
    return change_made

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
        user = base.User.GetById(vote.user_email)
        if user.HasPermissionTo(constants.PERMISSIONS.MARK_MALWARE):
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
    # pylint: disable=g-explicit-bool-comparison
    all_rules = base.Rule.query(
        base.Rule.in_effect == True, ancestor=self.blockable.key)
    # pylint: enable=g-explicit-bool-comparison
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

  BLOCKABLE_CLASSES = (
      santa.SantaBlockable, santa.SantaCertificate, santa.SantaBundle)

  def _CheckVotingAllowed(self):
    """Check whether the voting on the blockable is permitted.

    **NOTE** This method is a noop outside of a transaction (i.e. outside of
    _TransactionalVoting) EXCEPT for SantaBundles. This behavior is intended to
    accomodate the SantaBundle._HasFlagged* checks which can touch more than 25
    entities.

    For SantaBundles, IsVotingAllowed is run once in its entirety prior to
    voting and again in each attempt of _TransactionalVoting method without the
    _HasFlagged* checks.

    Raises:
      OperationNotAllowed: The user may not vote on the blockable due to one of
          the VOTING_PROHIBITED_REASONS.
    """
    if isinstance(self.blockable, santa.SantaBundle):
      allowed, reason = self.blockable.IsVotingAllowed(
          current_user=self.user,
          enable_flagged_checks=not ndb.in_transaction())
      if not allowed:
        message = 'Voting on this Blockable is not allowed (%s)' % reason
        logging.warning(message)
        raise OperationNotAllowed(message)
    else:
      super(SantaBallotBox, self)._CheckVotingAllowed()

  def _GetPackageBinaryKeys(self):
    """Lazy load the keys for the binaries associated with current blockable."""
    assert isinstance(self.blockable, base.Package)

    if self._package_binary_keys is None:
      child_binary_query = base.Binary.query(ancestor=self.blockable.key)
      self._package_binary_keys = child_binary_query.fetch(keys_only=True)
    return self._package_binary_keys

  def _GenerateRule(self, **kwargs):
    """Generate the rule for the blockable being voted on.

    Args:
      **kwargs: Arguments to be passed to the SantaRule constructor for all
          returned rules.
    Returns:
      An un-persisted SantaRule corresponding to the blockable being voted on.
    """
    return santa.SantaRule(
        parent=self.blockable.key,
        rule_type=self.blockable.rule_type,
        **kwargs)

  def _GetHostsToWhitelist(self, user_key):
    """Returns hosts for which whitelist rules should be created for a user.

    The current policy is to only whitelist on Hosts where the User is listed as
    the primary_user.

    Args:
      user_key: Key, The user for whom hosts to whitelist should be fetched.

    Returns:
      set<str>, IDs of Hosts for which whitelist rules should be created.
    """
    username = user_map.EmailToUsername(user_key.id())
    query = santa.SantaHost.query(santa.SantaHost.primary_user == username)
    return {host_key.id() for host_key in query.fetch(keys_only=True)}

  def _LocallyWhitelistForVoter(self, user_key):
    future = super(SantaBallotBox, self)._LocallyWhitelistForVoter(user_key)  # pylint: disable=line-too-long
    return future

  def _GenerateRemoveRules(self, unused_existing_rules):
    removal_rule = self._GenerateRule(
        policy=constants.RULE_POLICY.REMOVE,
        in_effect=True)
    removal_rule.put_async()

  @ndb.transactional
  def Reset(self, user):
    self.blockable = base.Blockable.get_by_id(self.blockable_id)
    if isinstance(self.blockable, santa.SantaBundle):
      raise OperationNotAllowed('Resetting not supported for Bundles')

    super(SantaBallotBox, self).Reset(user)


class Bit9BallotBox(BallotBox):
  """Class that modifies the voting state of a Bit9Blockable."""

  BLOCKABLE_CLASSES = (bit9.Bit9Binary, bit9.Bit9Certificate)

  def _CreateRuleChangeSet(self, rules_future, new_policy):
    """Creates a RuleChangeSet and trigger an attempted commit."""
    rules = rules_future.get_result()
    # If there are no rules to be created (rare but possible), we can just drop
    # the change set entirely.
    if not rules:
      return

    keys = [rule.key for rule in rules]
    change = bit9.RuleChangeSet(
        rule_keys=keys, change_type=new_policy, parent=self.blockable.key)
    change.put()

    # Attempt to commit the change set in a deferred task.
    # NOTE: If we're in a transaction, we should only send out the
    # request to Bit9 once the RuleChangeSet has been successfully created.
    # If we're not in a transaction, this executes immediately.
    ndb.get_context().call_on_commit(self._TriggerCommit)

  def _TriggerCommit(self):
    # If any errors occur in the process of the attempted commit, just log an
    # error. The RuleChangeSet commit should be retried by the cron.
    try:
      response = intermodule.SubmitIntermoduleRequest(
          'bit9-api',
          '/api/bit9/commit-change-set/%s' % self.blockable.key.id())
    except urlfetch.Error as e:
      logging.warning(
          'Failed to commit RuleChangeSet: URLFetch error (%s)', e)
    else:
      if response.status_code != httplib.OK:
        logging.warning(
            'Failed to commit RuleChangeSet: HTTP %s', response.status_code)

  def _GenerateRule(self, **kwargs):
    """Generate the rule for the blockable being voted on.

    Args:
      **kwargs: Arguments to be passed to the Bit9Rule constructor.
    Returns:
      An un-persisted Bit9Rule corresponding to the blockable being voted on.
    """
    return bit9.Bit9Rule(
        parent=self.blockable.key,
        rule_type=self.blockable.rule_type,
        **kwargs)

  def _GloballyWhitelist(self):
    future = super(Bit9BallotBox, self)._GloballyWhitelist()
    future.add_callback(
        self._CreateRuleChangeSet, future, constants.RULE_POLICY.WHITELIST)
    return future

  def _GetHostsToWhitelist(self, user_key):
    """Returns hosts for which whitelist rules should be created for a user.

    The current policy is to whitelist on Bit9Hosts where the User is listed in
    the users field.

    Args:
      user_key: Key, The user for whom hosts to whitelist should be fetched.

    Returns:
      set<str>, IDs of Hosts for which whitelist rules should be created.
    """
    username = user_map.EmailToUsername(user_key.id())
    query = bit9.Bit9Host.query(bit9.Bit9Host.users == username)
    return {host_key.id() for host_key in query.fetch(keys_only=True)}

  def _LocallyWhitelistForAllVoters(self):
    future = super(Bit9BallotBox, self)._LocallyWhitelistForAllVoters()
    future.add_callback(
        self._CreateRuleChangeSet, future, constants.RULE_POLICY.WHITELIST)
    return future

  def _LocallyWhitelistForCurrentVoter(self):
    future = super(Bit9BallotBox, self)._LocallyWhitelistForCurrentVoter()
    future.add_callback(
        self._CreateRuleChangeSet, future, constants.RULE_POLICY.WHITELIST)
    return future

  def _Blacklist(self):
    future = super(Bit9BallotBox, self)._Blacklist()
    future.add_callback(
        self._CreateRuleChangeSet, future, constants.RULE_POLICY.BLACKLIST)
    return future

  def _GenerateRemoveRules(self, existing_rules):
    # Create removal rules on each host for which a rule exists.
    host_ids = set(rule.host_id for rule in existing_rules)
    removal_rules = []
    for host_id in host_ids:
      removal_rules.append(
          self._GenerateRule(
              host_id=host_id,
              policy=constants.RULE_POLICY.REMOVE,
              in_effect=True))
    put_futures = ndb.put_multi_async(removal_rules)
    future = model_utils.GetMultiFuture(put_futures)
    future.add_callback(
        self._CreateRuleChangeSet, model_utils.GetNoOpFuture(removal_rules),
        constants.RULE_POLICY.REMOVE)

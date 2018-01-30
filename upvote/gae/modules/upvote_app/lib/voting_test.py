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

"""Tests for voting logic."""

import httplib
import mock

from google.appengine.ext import ndb

from upvote.gae.modules.upvote_app.lib import voting
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import intermodule
from upvote.gae.shared.common import settings
from upvote.gae.shared.models import base
from upvote.gae.shared.models import bigquery
from upvote.gae.shared.models import bit9
from upvote.gae.shared.models import santa
from upvote.gae.shared.models import test_utils
from upvote.gae.shared.models import utils
from upvote.shared import constants


def CreateEvent(blockable, host, user):
  return test_utils.CreateSantaEvent(
      blockable, host_id=host.key.id(), executing_user=user.nickname,
      parent=utils.ConcatenateKeys(user.key, host.key, blockable.key))


class VotingTest(basetest.UpvoteTestCase):
  """Test BallotBox ResolveVote and private functions."""

  def setUp(self):
    super(VotingTest, self).setUp()

    self.santa_blockable1 = test_utils.CreateSantaBlockable(
        id='aaaabbbbccccddddeeeeffffgggg')

    self.santa_blockable3 = test_utils.CreateSantaBlockable()
    self.santa_blockable4 = test_utils.CreateSantaBlockable()
    self.santa_bundle_blockables = (
        self.santa_blockable3, self.santa_blockable4)
    self.santa_bundle = test_utils.CreateSantaBundle(
        bundle_binaries=self.santa_bundle_blockables)

    self.local_threshold = settings.VOTING_THRESHOLDS[
        constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING]

  def testGetBallotBox(self):
    ballot_box = voting.GetBallotBox(self.santa_blockable1.key.id())
    self.assertIsInstance(ballot_box, voting.SantaBallotBox)

    bit9_binary = test_utils.CreateBit9Binary()
    ballot_box = voting.GetBallotBox(bit9_binary.key.id())
    self.assertIsInstance(ballot_box, voting.Bit9BallotBox)

  def testGetBallotBox_BadBlockable(self):
    with self.assertRaises(voting.BlockableNotFound):
      voting.GetBallotBox('doesnt_exist')

  def testGetBallotBox_UnknownBlockableType(self):
    blockable = test_utils.CreateBlockable()
    with self.assertRaises(voting.UnsupportedBlockableType):
      voting.GetBallotBox(blockable.key.id())

  @mock.patch.object(intermodule, 'SubmitIntermoduleRequest')
  def testResolveVote_RowPersistence_Bit9(self, mock_intermodule):
    binary = test_utils.CreateBit9Binary()

    mock_intermodule.return_value.status_code = httplib.OK

    ballot_box = voting.Bit9BallotBox(binary.key.id())
    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(True, user, vote_weight=self.local_threshold)

    # 1 VoteRow, 1 Binary Row for Score Change, 1 Binary Row for State Change
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.VoteRow, 1)
    self.assertEntityCount(bigquery.BinaryRow, 2)

  def testResolveVote_RowPersistence_Santa(self):
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(True, user, vote_weight=self.local_threshold)

    # 1 VoteRow, 1 Binary Row for Score Change, 1 Binary Row for State Change
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.VoteRow, 1)
    self.assertEntityCount(bigquery.BinaryRow, 2)

  @mock.patch.object(intermodule, 'SubmitIntermoduleRequest')
  def testResolveVote_Bit9(self, mock_intermodule):
    binary = test_utils.CreateBit9Binary()
    user = test_utils.CreateUser()
    host = test_utils.CreateBit9Host(users=[user.nickname])

    mock_intermodule.return_value.status_code = httplib.OK

    ballot_box = voting.Bit9BallotBox(binary.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user, vote_weight=self.local_threshold)

    self.assertEqual(self.local_threshold, binary.score)

    rules = binary.GetRules()
    self.assertEqual(1, len(rules))
    self.assertFalse(rules[0].is_committed)
    self.assertTrue(rules[0].in_effect)
    self.assertEqual(user.key, rules[0].user_key)
    self.assertEqual(host.key.id(), rules[0].host_id)

    changes = bit9.RuleChangeSet.query().fetch()
    self.assertEqual(1, len(changes))
    self.assertSameElements([rules[0].key], changes[0].rule_keys)
    self.assertEqual(constants.RULE_POLICY.WHITELIST, changes[0].change_type)
    self.assertTrue(utils.KeyHasAncestor(changes[0].key, binary.key))

    self.assertTrue(mock_intermodule.called)

  @mock.patch.object(intermodule, 'SubmitIntermoduleRequest')
  def testResolveVote_Bit9_NoRules(self, mock_intermodule):
    binary = test_utils.CreateBit9Binary()

    mock_intermodule.return_value.status_code = httplib.OK

    ballot_box = voting.Bit9BallotBox(binary.key.id())
    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(True, user, vote_weight=self.local_threshold)

    self.assertEqual(self.local_threshold, binary.score)
    self.assertEqual(0, len(binary.GetRules()))
    self.assertEqual(0, bit9.RuleChangeSet.query().count())

    self.assertFalse(mock_intermodule.called)

  @mock.patch.object(
      intermodule, 'SubmitIntermoduleRequest',
      side_effect=intermodule.urlfetch.Error)
  def testResolveVote_Bit9_IntermoduleFail(self, mock_intermodule):
    binary = test_utils.CreateBit9Binary()
    user = test_utils.CreateUser()
    test_utils.CreateBit9Host(users=[user.nickname])

    mock_intermodule.return_value.status_code = httplib.OK

    ballot_box = voting.Bit9BallotBox(binary.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user, vote_weight=self.local_threshold)

    # Ensure voting and RuleChangeSet creation were still successful.
    self.assertEqual(self.local_threshold, binary.score)
    self.assertEqual(1, bit9.RuleChangeSet.query().count())

    self.assertTrue(mock_intermodule.called)

  def testResolveVote_Bit9_WrongBlockableType(self):
    ballot_box = voting.Bit9BallotBox(self.santa_blockable1.key.id())
    with self.assertRaises(voting.UnsupportedBlockableType):
      with self.LoggedInUser() as user:
        ballot_box.ResolveVote(True, user)

  def testResolveVote_YesVote_FromUser(self):
    """Normal vote on normal blockable."""

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(True, user)

    blockable = self.santa_blockable1.key.get()

    self.assertEqual(blockable.score, 1)

  def testResolveVote_NoVote_FromUser(self):
    """Normal no vote on normal blockable."""

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(False, user)

      blockable = self.santa_blockable1.key.get()

      expectations = {
          'score': -user.vote_weight,
          'flagged': True}
      self.assertDictContainsSubset(expectations, blockable.to_dict())

  def testResolve_NoVote_SantaBundle(self):
    """Restrict no vote for bundles."""

    ballot_box = voting.SantaBallotBox(self.santa_bundle.key.id())
    with self.assertRaises(voting.OperationNotAllowed):
      with self.LoggedInUser() as user:
        ballot_box.ResolveVote(False, user)

  def testResolveVote_FromUser_WithCert(self):
    """Normal vote on signed blockable."""

    cert = test_utils.CreateSantaCertificate()
    self.santa_blockable1.cert_key = cert.key
    self.santa_blockable1.put()
    user = test_utils.CreateUser()

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user)

    blockable = self.santa_blockable1.key.get()

    self.assertEqual(user.vote_weight, blockable.score)

  def testResolveVote_FromUser_VoteWeight(self):
    """Normal vote on normal blockable with different vote weight."""

    user = test_utils.CreateUser()
    new_weight = user.vote_weight + 1
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user, vote_weight=new_weight)

    blockable = self.santa_blockable1.key.get()

    self.assertEqual(blockable.score, new_weight)

  def testResolveVote_FromUser_VoteWeight_Invalid(self):
    """Normal vote on normal blockable with bad vote weight."""

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.assertRaises(ValueError):
      with self.LoggedInUser() as user:
        ballot_box.ResolveVote(False, user, vote_weight=-1)

  def testResolveVote_FromUser_VoteWeight_Zero(self):
    """Normal vote on normal blockable with 0 vote weight."""

    new_weight = 0
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(True, user, vote_weight=new_weight)

    blockable = self.santa_blockable1.key.get()

    self.assertEqual(blockable.score, new_weight)

  def testResolveVote_ChangingVotes(self):
    """Normal vote on normal blockable."""

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(True, user)
      ballot_box.ResolveVote(False, user)
      ballot_box.ResolveVote(True, user)

    blockable = self.santa_blockable1.key.get()

    self.assertEqual(blockable.score, 1)

  def testResolveVote_FromUser_ArchivedVotes(self):
    """Normal vote on normal blockable with old votes."""

    user = test_utils.CreateUser()

    # Create an active no vote.
    vote = test_utils.CreateVote(
        self.santa_blockable1, user_email=user.email, was_yes_vote=False)
    vote.key.delete()

    # Create several inactive yes votes.
    vote.was_yes_vote = True
    for _ in xrange(10):
      vote.key = base.Vote.GetKey(
          self.santa_blockable1.key, user.key, in_effect=False)
      vote.put()

    # Attempt to change in effect vote to yes.
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user)

    blockable = self.santa_blockable1.key.get()

    self.assertEqual(blockable.score, 1)

  def testResolveVote_FromUser_ArchivedVote_NewVoteWeight(self):
    """Normal vote on normal blockable with old votes."""

    user = test_utils.CreateUser()

    # Create an active no vote.
    test_utils.CreateVote(
        self.santa_blockable1, user_email=user.email, was_yes_vote=False)

    # Attempt to change in effect vote to yes.
    new_weight = user.vote_weight + 1
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user, vote_weight=new_weight)

    blockable = self.santa_blockable1.key.get()

    self.assertEqual(blockable.score, new_weight)

    votes = base.Vote.query(ancestor=self.santa_blockable1.key).fetch()
    self.assertEqual(2, len(votes))

    old_vote = next(vote for vote in votes if not vote.in_effect)
    self.assertNotEqual(new_weight, old_vote.weight)

    new_vote = next(vote for vote in votes if vote.in_effect)
    self.assertEqual(new_weight, new_vote.weight)

  def testResolveVote_NonexistentBlockable(self):
    """Voting on a blockable that doesn't exist in the datastore."""
    ballot_box = voting.SantaBallotBox('bbbbllllfffftttt')
    with self.assertRaises(voting.BlockableNotFound):
      with self.LoggedInUser() as user:
        ballot_box.ResolveVote(True, user)

  def testResolveVote_YesVote_FromAdmin_FlaggedBlockable(self):
    """Admin voting yes on flagged blockable."""

    user = test_utils.CreateUser()
    admin = test_utils.CreateUser(admin=True)

    self.santa_blockable1 = test_utils.CreateSantaBlockable()
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(False, user)
    self.assertTrue(self.santa_blockable1.key.get().flagged)

    with self.LoggedInUser(user=admin):
      ballot_box.ResolveVote(True, admin)

      expectations = {
          'score': -user.vote_weight + admin.vote_weight,
          'flagged': False}
      self.assertDictContainsSubset(
          expectations, self.santa_blockable1.key.get().to_dict())

  def testResolveVote_YesVote_FromUser_FlaggedBlockable_PreviousNoVote(self):
    """A normal user changing their vote from no to yes on flagged blockable."""

    with self.LoggedInUser() as user:
      self.santa_blockable1 = test_utils.CreateSantaBlockable()
      ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
      ballot_box.ResolveVote(False, user)
      self.assertTrue(self.santa_blockable1.key.get().flagged)
      ballot_box.ResolveVote(True, user)

      expectations = {
          'score': user.vote_weight,
          'flagged': False}
      self.assertDictContainsSubset(
          expectations, self.santa_blockable1.key.get().to_dict())

  def testResolveVote_NoVote_FromAdmin_SuspectBlockable(self):
    """Admin votes no on suspect blockable."""

    suspect_blockable = test_utils.CreateSantaBlockable(
        state=constants.STATE.SUSPECT)

    ballot_box = voting.SantaBallotBox(suspect_blockable.key.id())
    with self.LoggedInUser(admin=True) as admin:
      ballot_box.ResolveVote(False, admin)

      expectations = {
          'score': -admin.vote_weight,
          'flagged': True}
      self.assertDictContainsSubset(
          expectations, suspect_blockable.key.get().to_dict())

  def testResolveVote_YesVote_FromAdmin_SuspectBlockable(self):
    """Admin votes yes on suspect blockable."""

    suspect_blockable = test_utils.CreateSantaBlockable(
        state=constants.STATE.SUSPECT)
    with self.LoggedInUser(admin=True) as admin:

      ballot_box = voting.SantaBallotBox(suspect_blockable.key.id())
      ballot_box.ResolveVote(True, admin)

      expectations = {
          'score': admin.vote_weight,
          'flagged': False}
      self.assertDictContainsSubset(
          expectations, suspect_blockable.key.get().to_dict())

  def testResolveVote_GlobalWhitelist(self):
    """2 admins' votes make a blockable globally whitelisted."""

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    ballot_box.blockable = self.santa_blockable1

    for admin_user in test_utils.CreateUsers(2, admin=True):
      ballot_box.ResolveVote(True, admin_user)

    self.assertEqual(
        self.santa_blockable1.key.get().state,
        constants.STATE.GLOBALLY_WHITELISTED)

  def testResolveVote_GlobalWhitelist_Bundle(self):
    """2 admins' votes make a bundle globally whitelisted."""

    ballot_box = voting.SantaBallotBox(self.santa_bundle.key.id())

    for admin_user in test_utils.CreateUsers(2, admin=True):
      ballot_box.ResolveVote(True, admin_user)

    # Verify that global whitelist rule was created for the bundle.
    rules = santa.SantaRule.query(ancestor=self.santa_bundle.key).fetch()
    self.assertEqual(1, len(rules))
    self.assertEqual(constants.RULE_TYPE.PACKAGE, rules[0].rule_type)
    self.assertEqual(constants.RULE_POLICY.WHITELIST, rules[0].policy)

    self.assertEqual(
        self.santa_bundle.key.get().state,
        constants.STATE.GLOBALLY_WHITELISTED)

  def testResolveVote_LocalWhitelist(self):
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())

    for user in test_utils.CreateUsers(self.local_threshold):
      test_utils.CreateSantaHost(primary_user=user.nickname)
      ballot_box.ResolveVote(True, user)

    self.assertEqual(
        self.santa_blockable1.key.get().state,
        constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING)

  def testResolveVote_LocalWhitelist_Bundle(self):
    ballot_box = voting.SantaBallotBox(self.santa_bundle.key.id())

    with mock.patch.object(
        ballot_box, '_GetHostsToWhitelist', return_value={'a_host'}):
      for user in test_utils.CreateUsers(self.local_threshold):
        ballot_box.ResolveVote(True, user)

    # Verify that local whitelist rules were created for the bundle.
    rules = santa.SantaRule.query(ancestor=self.santa_bundle.key).fetch()
    self.assertEqual(self.local_threshold, len(rules))
    self.assertEqual(constants.RULE_TYPE.PACKAGE, rules[0].rule_type)
    self.assertEqual(constants.RULE_POLICY.WHITELIST, rules[0].policy)

    # Verify that votes were only applied to the bundle and not the members.
    bundle = self.santa_bundle.key.get()
    self.assertEqual(
        bundle.state, constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING)

    for blockable in self.santa_bundle_blockables:
      self.assertEqual(blockable.key.get().state, constants.STATE.UNTRUSTED)

  def testResolveVote_AlreadyLocallyWhitelisted(self):
    """Test voting when locally whitelistable, without actual state change."""
    # Simulate a Blockable which has been voted to the point where it is
    # available for local whitelisting.
    sha = test_utils.RandomSHA256()
    blockable = test_utils.CreateSantaBlockable(
        id=sha, state=constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING)

    # Create Users
    users = test_utils.CreateUsers(self.local_threshold)
    admin = test_utils.CreateUser(
        roles=[constants.USER_ROLE.ADMINISTRATOR])
    users.append(admin)

    # Create the Votes.
    for user in users[:-1]:
      test_utils.CreateVote(blockable, user_email=user.email, weight=1)

    # Create the Hosts, Events, and Rules (all but the last one).
    for user in users:
      host = test_utils.CreateSantaHost(primary_user=user.nickname)
      if user != users[-1]:
        test_utils.CreateSantaRule(
            blockable.key, host_id=host.key.id(),
            policy=constants.RULE_POLICY.WHITELIST, user_key=user.key)

    # Verify all the entities.
    self.assertIsNotNone(base.Blockable.get_by_id(sha))
    self.assertEqual(len(users) - 1, len(blockable.GetVotes()))
    self.assertEqual(len(users), base.Host.query().count())
    self.assertEqual(len(users) - 1, len(blockable.GetRules()))

    # Ensure that even with a yes vote, the voter can't globally whitelist the
    # Blockable, i.e. can't trigger a state change.
    self.assertTrue(blockable.score + users[-1].vote_weight < 50)

    # The new voter casts a yes vote.
    ballot_box = voting.SantaBallotBox(sha)
    ballot_box.ResolveVote(True, users[-1])

    # Verify the Blockable, Votes, and Rules.
    blockable = base.Blockable.get_by_id(sha)
    self.assertEqual(
        constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING, blockable.state)
    self.assertLess(blockable.score, 50)
    self.assertEqual(len(users), len(blockable.GetVotes()))
    self.assertEqual(len(users), len(blockable.GetRules()))

  def testResolveVote_ToSuspect_ByAdmin(self):
    """Test changing state to untrusted."""
    blockable = test_utils.CreateSantaBlockable(
        state=constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING)

    ballot_box = voting.SantaBallotBox(blockable.key.id())
    with self.LoggedInUser(admin=True) as admin:
      ballot_box.ResolveVote(False, admin)

    self.assertEqual(blockable.key.get().state, constants.STATE.BANNED)

  def testResolveVote_GloballyWhitelist_RuleNoRules(self):
    """Change a blockable state to Globally whitelisted."""
    self.rule1 = base.Rule(
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.BLACKLIST,
        in_effect=True,
        parent=self.santa_blockable1.key,
    )

    self.rule1.put()

    blockable = santa.SantaBlockable(
        id=self.santa_blockable1.key.id(),
        id_type=constants.ID_TYPE.SHA256,
        file_name='ginger spider 2',
        flagged=False,
        state=constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING
    )
    blockable.put()
    test_utils.CreateVote(blockable)
    test_utils.CreateVote(blockable)

    ballot_box = voting.SantaBallotBox(blockable.key.id())
    ballot_box.blockable = blockable

    ballot_box._GloballyWhitelist().get_result()

    rule_query = base.Rule.query(ancestor=self.santa_blockable1.key)

    self.assertEqual(rule_query.count(), 2)

    # pylint: disable=g-explicit-bool-comparison
    rule_query = rule_query.filter(base.Rule.in_effect == True)
    # pylint: enable=g-explicit-bool-comparison

    self.assertEqual(rule_query.count(), 1)

    rule = rule_query.get()

    self.assertEqual(rule.policy, constants.RULE_POLICY.WHITELIST)

  def testResolveVote_LocallyWhitelist_RulesForAllVoters(self):
    """Create rules for users who voted earlier."""

    user = test_utils.CreateUser()
    other_users = [
        test_utils.CreateUser() for _ in xrange(self.local_threshold - 1)]

    blockable = test_utils.CreateSantaBlockable()
    test_utils.CreateSantaHost(primary_user=user.nickname)

    ballot_box = voting.SantaBallotBox(blockable.key.id())
    for other_user in other_users:
      with self.LoggedInUser(user=other_user):
        test_utils.CreateSantaHost(primary_user=other_user.nickname)
        ballot_box.ResolveVote(True, other_user)

    self.assertEqual(self.local_threshold - 1, len(blockable.GetVotes()))
    self.assertEqual(constants.STATE.UNTRUSTED, blockable.state)

    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user)

    self.assertEqual(self.local_threshold, len(blockable.GetVotes()))

    rules = base.Rule.query().fetch()
    self.assertEqual(self.local_threshold, len(rules))
    self.assertEqual(
        set([other.key for other in other_users] + [user.key]),
        set(rule.user_key for rule in rules))

  def testResolveVote_LocallyWhitelist_OnlyRulesForCurrentVoter(self):
    """Create rules for users who voted earlier."""

    user = test_utils.CreateUser()
    other_users = [
        test_utils.CreateUser() for _ in xrange(self.local_threshold)]

    blockable = test_utils.CreateSantaBlockable()
    test_utils.CreateSantaHost(primary_user=user.nickname)

    ballot_box = voting.SantaBallotBox(blockable.key.id())
    for other_user in other_users:
      with self.LoggedInUser(user=other_user):
        test_utils.CreateSantaHost(primary_user=other_user.nickname)
        ballot_box.ResolveVote(True, other_user)

    blockable = blockable.key.get()

    self.assertEqual(self.local_threshold, len(blockable.GetVotes()))
    self.assertEqual(self.local_threshold, blockable.score)
    self.assertEqual(
        constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING, blockable.state)

    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user)

    self.assertEqual(self.local_threshold + 1, len(blockable.GetVotes()))

    rules = base.Rule.query().fetch()
    self.assertEqual(self.local_threshold + 1, len(rules))
    self.assertEqual(
        set([other.key for other in other_users] + [user.key]),
        set(rule.user_key for rule in rules))

  def testResolveVote_LocalWhitelist_OnlyCreateNewRules(self):
    """Add local rules where a couple already exist."""
    blockable = test_utils.CreateSantaBlockable()
    user = test_utils.CreateUser()
    hosts = test_utils.CreateSantaHosts(3, primary_user=user.nickname)

    # Create rules for the first two hosts
    for host in hosts[:2]:
      test_utils.CreateSantaRule(
          blockable.key,
          policy=constants.RULE_POLICY.WHITELIST,
          in_effect=True,
          rule_type=constants.RULE_TYPE.BINARY,
          user_key=user.key,
          host_id=host.key.id())

    rule_query = base.Rule.query(ancestor=blockable.key)

    self.assertEqual(len(hosts) - 1, rule_query.count())

    # Create users not associated with any host.
    other_users = test_utils.CreateUsers(self.local_threshold - 1)

    ballot_box = voting.SantaBallotBox(blockable.key.id())
    for other_user in other_users:
      with self.LoggedInUser(user=other_user):
        ballot_box.ResolveVote(True, other_user)

    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user)

    # Ensure a new rule was created for the existing user's host.
    self.assertEqual(rule_query.count(), len(hosts))

    rules = rule_query.fetch()
    for rule in rules:
      self.assertEqual(rule.policy, constants.RULE_POLICY.WHITELIST)
      self.assertTrue(rule.in_effect)
      self.assertEqual(rule.rule_type, constants.RULE_TYPE.BINARY)

    self.assertSameElements(
        [host.key.id() for host in hosts],
        [rule.host_id for rule in rules])

  def testResolveVote_KeyStructure(self):
    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())

    self.assertEqual(0, len(self.santa_blockable1.GetVotes()))

    with self.LoggedInUser() as user:
      ballot_box.ResolveVote(True, user)

      # Use Blockable.GetVotes to ensure our vote counts towards the blockable's
      # score.
      votes = self.santa_blockable1.GetVotes()
      self.assertEqual(1, len(votes))
      new_vote = votes[0]

      # Verify that the key is in the expected structure.
      expected_key = ndb.Key(
          base.Blockable, self.santa_blockable1.key.id(), base.User,
          user.email, base.Vote, base.Vote._IN_EFFECT_KEY_NAME)
      self.assertEqual(new_vote, expected_key.get())

  def testResolveVote_DuplicateVote(self):
    user = test_utils.CreateUser()

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    ballot_box.ResolveVote(True, user)

    with self.assertRaises(voting.DuplicateVoteError):
      ballot_box.ResolveVote(True, user)

  def testResolveVote_ChangeVote(self):
    user = test_utils.CreateUser()

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())

    # The user upvotes the blockable.
    ballot_box.ResolveVote(True, user)

    orig_score = self.santa_blockable1.key.get().score

    # The user changes their vote on the blockable.
    ballot_box.ResolveVote(False, user)

    votes = base.Vote.query(ancestor=self.santa_blockable1.key).fetch()
    self.assertTrue(any(vote for vote in votes if vote.in_effect))
    self.assertTrue(any(vote for vote in votes if not vote.in_effect))
    self.assertEqual(len(votes), 2)

    old_vote = [vote for vote in votes if not vote.in_effect][0]
    new_vote = [vote for vote in votes if vote.in_effect][0]
    new_score = self.santa_blockable1.key.get().score

    self.assertNotEqual(base.Vote._IN_EFFECT_KEY_NAME, old_vote.key.id())
    self.assertEqual(base.Vote._IN_EFFECT_KEY_NAME, new_vote.key.id())
    self.assertGreater(new_vote.recorded_dt, old_vote.recorded_dt)
    self.assertEqual(new_score, -1 * orig_score)
    self.assertIsNotNone(new_vote.key.id())

  def testResolveVote_ArchiveAllVote(self):
    user = test_utils.CreateUser()

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())

    existing_count = base.Vote.query().count()

    # The user upvotes the blockable.
    ballot_box.ResolveVote(True, user)

    num_created = base.Vote.query().count() - existing_count

    # New Vote = 1 created
    self.assertEqual(1, num_created)

    # The user changes their vote on the blockable.
    ballot_box.ResolveVote(False, user)

    num_created = base.Vote.query().count() - existing_count

    # New Vote + Saved old Vote = 2 created
    self.assertEqual(2, num_created)

  def testResolveVote_LookupMetric_WhenBinary(self):
    self.PatchSetting('ENABLE_BINARY_ANALYSIS_PRECACHING', True)

    user = test_utils.CreateUser()

    ballot_box = voting.SantaBallotBox(self.santa_blockable1.key.id())
    ballot_box.ResolveVote(False, user)

    self.assertTaskCount(constants.TASK_QUEUE.METRICS, 1)

  def testResolveVote_LookupMetric_SkipWhenBundle(self):
    self.PatchSetting('ENABLE_BINARY_ANALYSIS_PRECACHING', True)

    user = test_utils.CreateUser()

    ballot_box = voting.SantaBallotBox(self.santa_bundle.key.id())
    ballot_box.ResolveVote(True, user)

    self.assertTaskCount(constants.TASK_QUEUE.METRICS, 0)

  def testRecountScore(self):
    """Check that if score is out of sync it actually gets recalculated."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.put()
    user = test_utils.CreateUser()
    test_utils.CreateVote(
        santa_blockable, user_email=user.email, was_yes_vote=True)
    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.Recount()
    santa_blockable = santa_blockable.key.get()
    self.assertEqual(santa_blockable.score, 1)

  def testFlaggedWithNegativeVote(self):
    """A blockable that is not marked as flagged, but should be."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.flagged = True
    santa_blockable.put()

    with self.LoggedInUser() as user:
      original_blockable_dict = santa_blockable.to_dict()
      test_utils.CreateVote(
          santa_blockable, user_email=user.email, was_yes_vote=False)
      ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
      ballot_box.blockable = santa_blockable

      change_made = ballot_box._CheckBlockableFlagStatus()

      self.assertFalse(change_made)
      # Don't compare score because it should be lower due to new vote.
      santa_blockable_dict = santa_blockable.to_dict()
      del original_blockable_dict['score']
      del santa_blockable_dict['score']
      self.assertEqual(original_blockable_dict, santa_blockable_dict)
      self.assertEqual(-1, santa_blockable.score)

  def testUnflaggedWithNegativeVote(self):
    """A blockable that is not marked as flagged, but should be."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.flagged = False
    santa_blockable.put()
    user = test_utils.CreateUser()
    test_utils.CreateVote(
        santa_blockable, user_email=user.email, was_yes_vote=False)
    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    change_made = ballot_box._CheckBlockableFlagStatus()

    self.assertTrue(change_made)
    self.assertTrue(santa_blockable.flagged)

  def testFlaggedWithYesVote(self):
    """A blockable that is flagged, but shouldn't be."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.flagged = True
    santa_blockable.put()
    user = test_utils.CreateUser()
    test_utils.CreateVote(
        santa_blockable, user_email=user.email, was_yes_vote=True)
    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    change_made = ballot_box._CheckBlockableFlagStatus()

    self.assertFalse(santa_blockable.flagged)
    self.assertTrue(change_made)

  def testFlaggedWithYesVote_ArchivedVotes(self):
    """A blockable that is flagged, but shouldn't be with archived votes."""

    # Create an active vote.
    santa_blockable = test_utils.CreateSantaBlockable(flagged=True)
    user = test_utils.CreateUser()
    test_utils.CreateVote(
        santa_blockable, user_email=user.email, was_yes_vote=True)

    # Create archived votes.
    archived_vote = test_utils.CreateVote(
        santa_blockable, user_email=user.email, was_yes_vote=False)
    archived_vote.key.delete()
    for _ in xrange(4):
      archived_vote.key = base.Vote.GetKey(
          santa_blockable.key, user.key, in_effect=False)
      archived_vote.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    change_made = ballot_box._CheckBlockableFlagStatus()

    self.assertFalse(santa_blockable.flagged)
    self.assertTrue(change_made)

  def testSuspectWithNegativeVote(self):
    """A blockable properly marked as suspect."""

    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.SUSPECT
    santa_blockable.put()

    admin = test_utils.CreateUser(admin=True)
    test_utils.CreateVote(
        santa_blockable, user_email=admin.email, was_yes_vote=False)

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    change_made = ballot_box._AuditBlockableState()

    self.assertEqual(base.Vote.query().count(), 1)
    self.assertFalse(change_made)

  def testSuspectWithoutNoVote(self):
    """A blockable improperly marked as suspect."""

    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.SUSPECT
    santa_blockable.put()

    admin1 = test_utils.CreateUser(admin=True)
    admin2 = test_utils.CreateUser(admin=True)

    test_utils.CreateVote(
        santa_blockable, user_email=admin1.email, was_yes_vote=False)
    test_utils.CreateVote(
        santa_blockable, user_email=admin2.email, was_yes_vote=True)

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    with mock.patch.object(ballot_box, '_CheckAndSetBlockableState',
                           return_value=True, autospec=True):
      change_made = ballot_box._AuditBlockableState()

    self.assertEqual(base.Vote.query().count(), 2)
    self.assertTrue(change_made)

  def testSuspectWithoutNoVoteFromAppropriateUser(self):
    """A blockable improperly marked as suspect."""
    santa_blockable = test_utils.CreateSantaBlockable()

    user = test_utils.CreateUser()
    test_utils.CreateVote(
        santa_blockable, user_email=user.email, was_yes_vote=False)

    santa_blockable.state = constants.STATE.SUSPECT
    santa_blockable.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    with mock.patch.object(ballot_box, '_CheckAndSetBlockableState',
                           return_value='True', autospec=True):
      change_made = ballot_box._AuditBlockableState()
      ballot_box._CheckAndSetBlockableState.assert_called_once_with(-1)

    self.assertEqual(base.Vote.query().count(), 1)
    self.assertTrue(change_made)

  def testBlockableWithLocalWhitelistRulesUntrusted(self):
    """A blockable in untrusted with local whitelist rules."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.UNTRUSTED
    santa_blockable.put()

    test_rule1 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='aaaaa-1111-bbbbbbbbbb')
    test_rule2 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='bbbbb-2222-ccccccccc')
    test_rule3 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='ccccc-1111-dddddddd')
    test_rule1.put()
    test_rule2.put()
    test_rule3.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()

    self.assertEqual(rule_query.count(), 3)

    all_in_effect = True
    for rule in rule_query:
      all_in_effect = all_in_effect and rule.in_effect

    self.assertTrue(all_in_effect)

  def testBlockableWithProperLocalWhitelistRules(self):
    """A blockable with correct state and local whitelist rules."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.APPROVED_FOR_LOCAL_WHITELISTING
    santa_blockable.put()

    test_rule1 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='aaaaa-1111-bbbbbbbbbb')
    test_rule2 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='bbbbb-2222-ccccccccc')
    test_rule3 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='ccccc-1111-dddddddd')
    test_rule1.put()
    test_rule2.put()
    test_rule3.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()

    self.assertEqual(rule_query.count(), 3)

    all_in_effect = True
    for rule in rule_query:
      all_in_effect = all_in_effect and rule.in_effect

    self.assertTrue(all_in_effect)

  def testBlockableWithProperGlobalWhitelistRules(self):
    """A blockable with correct state and global whitelist rule."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.GLOBALLY_WHITELISTED
    santa_blockable.put()

    test_rule = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True)
    test_rule.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()

    self.assertEqual(rule_query.count(), 1)

    rule = rule_query.get()

    self.assertEqual(rule, test_rule)

  def testBlockableWithProperBlacklistRules(self):
    """A blockable with correct state and blacklist rule."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.BANNED
    santa_blockable.put()

    test_rule = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.BLACKLIST,
        in_effect=True)
    test_rule.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()

    self.assertEqual(rule_query.count(), 1)

    rule = rule_query.get()

    self.assertEqual(rule, test_rule)

  def testUntrustedBlockableWithImproperGlobalWhitelistRules(self):
    """A blockable with local whitelist rules that should not have them."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.UNTRUSTED
    santa_blockable.put()

    test_rule = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True)
    test_rule.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()

    self.assertEqual(rule_query.count(), 1)

    rule = rule_query.get()

    self.assertFalse(rule.in_effect)

  def testBlockableWithImproperLocalWhitelistRules(self):
    """A blockable with local whitelist rules that should not have them."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.BANNED
    santa_blockable.put()

    test_rule1 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='aaaaa-1111-bbbbbbbbbb')
    test_rule2 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='bbbbb-2222-ccccccccc')
    test_rule3 = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True,
        host_id='ccccc-1111-dddddddd')
    test_rule1.put()
    test_rule2.put()
    test_rule3.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()
    self.assertEqual(4, rule_query.count())
    # Exacly one rule (the blacklist one) should be in effect.
    self.assertEqual(1, sum(rule.in_effect for rule in rule_query))

  def testBlockableWithImproperGlobalWhitelistRule(self):
    """A blockable with a global whitelist rule it shouldn't have."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.UNTRUSTED
    santa_blockable.put()

    test_rule = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST,
        in_effect=True)
    test_rule.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()

    self.assertEqual(rule_query.count(), 1)

    rule = rule_query.get()

    self.assertFalse(rule.in_effect)

  def testBlockableWithImproperBlacklistRule(self):
    """A blockable with a blacklist rule it doesn't deserve."""
    santa_blockable = test_utils.CreateSantaBlockable()
    santa_blockable.state = constants.STATE.UNTRUSTED
    santa_blockable.put()

    test_rule = santa.SantaRule(
        parent=santa_blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.BLACKLIST,
        in_effect=True)
    test_rule.put()

    ballot_box = voting.SantaBallotBox(santa_blockable.key.id())
    ballot_box.blockable = santa_blockable

    ballot_box._CheckRules()

    rule_query = santa.SantaRule.query()

    self.assertEqual(rule_query.count(), 1)

    rule = rule_query.get()

    self.assertFalse(rule.in_effect)

  def testResetBlockable(self):
    """Test resetting a blockable with some votes."""
    user = test_utils.CreateUser()
    blockable = test_utils.CreateSantaBlockable(state=constants.STATE.SUSPECT)
    test_utils.CreateSantaRule(blockable.key)
    test_utils.CreateVotes(blockable, 11)

    ballot_box = voting.SantaBallotBox(blockable.key.id())
    ballot_box.Reset(user)

    self.assertEqual(constants.STATE.UNTRUSTED, blockable.key.get().state)

    total_votes = base.Vote.query()
    retrieved_logs = base.AuditLog.query(base.AuditLog.user == user.email)
    retrieved_rules = base.Rule.query(ancestor=blockable.key)
    # pylint: disable=g-explicit-bool-comparison
    retrieved_in_effect_rules = base.Rule.query(
        base.Rule.in_effect == True, ancestor=blockable.key)
    # pylint: enable=g-explicit-bool-comparison

    self.assertEqual(total_votes.count(), 11)
    self.assertEqual(len(blockable.GetVotes()), 0)
    self.assertEqual(retrieved_logs.count(), 11)
    self.assertEqual(retrieved_rules.count(), 2)
    self.assertEqual(retrieved_in_effect_rules.count(), 1)

  def testResetBlockable_Bundles_NotAllowed(self):
    """Test resetting a blockable with some votes."""

    user = test_utils.CreateUser()

    ballot_box = voting.SantaBallotBox(self.santa_bundle.key.id())
    with self.assertRaises(voting.OperationNotAllowed):
      ballot_box.Reset(user)

  @mock.patch.object(intermodule, 'SubmitIntermoduleRequest')
  def testResetBlockable_Bit9(self, mock_intermodule):
    binary = test_utils.CreateBit9Binary()
    user = test_utils.CreateUser()
    test_utils.CreateBit9Host(users=[user.nickname])

    mock_intermodule.return_value.status_code = httplib.OK

    ballot_box = voting.Bit9BallotBox(binary.key.id())
    with self.LoggedInUser(user=user):
      ballot_box.ResolveVote(True, user, vote_weight=self.local_threshold)

    self.assertEqual(self.local_threshold, binary.score)
    self.assertEntityCount(bit9.Bit9Rule, 1)
    self.assertEntityCount(bit9.RuleChangeSet, 1)

    ballot_box.Reset(user)

    self.assertEqual(0, binary.score)

    self.assertEntityCount(bit9.Bit9Rule, 2)
    self.assertEntityCount(bit9.RuleChangeSet, 2)

    rules = binary.GetRules()
    self.assertEqual(1, len(rules))
    self.assertFalse(rules[0].is_committed)
    self.assertTrue(rules[0].in_effect)
    self.assertEqual(constants.RULE_POLICY.REMOVE, rules[0].policy)

    changes = bit9.RuleChangeSet.query().fetch()
    types = [change.change_type for change in changes]
    self.assertSameElements(
        [constants.RULE_POLICY.WHITELIST, constants.RULE_POLICY.REMOVE], types)

    self.assertTrue(mock_intermodule.called)


if __name__ == '__main__':
  basetest.main()

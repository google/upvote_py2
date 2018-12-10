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

"""Unit tests for base.py."""

import datetime

import mock

from google.appengine.ext import ndb

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import utils as model_utils
from upvote.gae.datastore.models import vote as vote_models
from upvote.gae.lib.testing import basetest
from upvote.gae.shared.common import user_map
from upvote.shared import constants


_TEST_EMAIL = user_map.UsernameToEmail('testemail')


class EventTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(EventTest, self).setUp()

    self.earlier = datetime.datetime.utcnow()
    self.middle = self.earlier + datetime.timedelta(seconds=1)
    self.later = self.earlier + datetime.timedelta(seconds=2)

    self.blockable = test_utils.CreateBlockable()
    self.user = test_utils.CreateUser()
    self.other_user = test_utils.CreateUser()
    self.event_1 = test_utils.CreateEvent(
        self.blockable, first_blocked_dt=self.earlier,
        last_blocked_dt=self.earlier, executing_user=self.user.nickname)
    self.event_2 = test_utils.CreateEvent(
        self.blockable, first_blocked_dt=self.later, last_blocked_dt=self.later,
        executing_user=self.other_user.nickname)

    self.PatchSetting('EVENT_CREATION', constants.EVENT_CREATION.EXECUTING_USER)

  def testRunByLocalAdmin(self):
    self.assertFalse(self.event_1.run_by_local_admin)

  def testUserKey(self):
    keys = model_utils.GetEventKeysToInsert(self.event_1, [], [])
    self.event_1.key = keys[0]
    self.event_1.put()

    self.assertEqual(self.user.key, self.event_1.user_key)

  def testUserKey_BadKey(self):
    self.event_1.key = None
    self.assertIsNone(self.event_1.user_key)

  def testDedupe_Later(self):
    self.event_1.Dedupe(self.event_2)

    self.assertEqual(self.earlier, self.event_1.first_blocked_dt)
    self.assertEqual(self.later, self.event_1.last_blocked_dt)
    self.assertEqual(self.event_2.executing_user, self.event_1.executing_user)
    self.assertEqual(2, self.event_1.count)

  def testDedupe_Earlier(self):
    self.event_2.Dedupe(self.event_1)

    self.assertEqual(self.earlier, self.event_2.first_blocked_dt)
    self.assertEqual(self.later, self.event_2.last_blocked_dt)
    self.assertNotEqual(
        self.event_2.executing_user, self.event_1.executing_user)
    self.assertEqual(2, self.event_2.count)

  def testDedupe_Both(self):
    self.event_1.first_blocked_dt = self.middle
    self.event_1.last_blocked_dt = self.middle
    self.event_1.put()

    self.event_2.first_blocked_dt = self.earlier
    self.event_2.last_blocked_dt = self.later
    self.event_2.put()

    self.event_1.Dedupe(self.event_2)

    self.assertEqual(self.earlier, self.event_1.first_blocked_dt)
    self.assertEqual(self.later, self.event_1.last_blocked_dt)
    self.assertEqual(self.event_2.executing_user, self.event_1.executing_user)
    self.assertEqual(2, self.event_1.count)

  def testDedupe_NoCount(self):
    datastore_utils.DeleteProperty(self.event_2, 'count')

    self.event_1.Dedupe(self.event_2)

    self.assertEqual(2, self.event_1.count)

  def testDedupeMultiple(self):
    keys = model_utils.GetEventKeysToInsert(self.event_1, ['foo'], [])
    event1 = datastore_utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.middle,
        last_blocked_dt=self.middle)
    event2 = datastore_utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.earlier,
        last_blocked_dt=self.later)
    event3 = datastore_utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.middle,
        last_blocked_dt=self.later)

    events = base.Event.DedupeMultiple([event1, event2, event3])

    self.assertLen(events, 1)

    self.assertEqual(self.earlier, events[0].first_blocked_dt)
    self.assertEqual(self.later, events[0].last_blocked_dt)
    self.assertEqual(3, events[0].count)


class NoteTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(NoteTest, self).setUp()
    self.blockable = test_utils.CreateBlockable()

  def tearDown(self):
    self.testbed.deactivate()

  def testGenerateKey(self):
    key = base.Note.GenerateKey('fake_message', self.blockable.key)
    self.assertEqual(key.parent(), self.blockable.key)
    self.assertLen(key.id(), 64)


class BlockableTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BlockableTest, self).setUp()

    self.blockable_1 = test_utils.CreateBlockable()
    self.blockable_2 = test_utils.CreateBlockable()

    self.user = test_utils.CreateUser(email=_TEST_EMAIL)
    self.Login(self.user.email)

  def testAvoidInitialScoreCalculation(self):
    b = base.Blockable(id_type='SHA256')
    with mock.patch.object(b, 'GetVotes', return_value=[]) as get_votes_mock:
      # First put should just set the score to be 0 and avoid the Vote query.
      b.put()
      self.assertFalse(get_votes_mock.called)

      # Now that b has a score value, it should do the Vote query to update it.
      b.put()
      self.assertTrue(get_votes_mock.called)

  def testGetVotes(self):
    self.assertLen(self.blockable_1.GetVotes(), 0)
    self.assertLen(self.blockable_2.GetVotes(), 0)

    test_utils.CreateVotes(self.blockable_1, 3)
    test_utils.CreateVotes(self.blockable_2, 2)

    self.assertLen(self.blockable_1.GetVotes(), 3)
    self.assertLen(self.blockable_2.GetVotes(), 2)

  def testGetVotes_Inactive(self):
    self.assertLen(self.blockable_1.GetVotes(), 0)

    test_utils.CreateVotes(self.blockable_1, 2)

    self.assertLen(self.blockable_1.GetVotes(), 2)

    votes = vote_models.Vote.query().fetch()
    new_votes = []
    for vote in votes:
      new_key = ndb.Key(flat=vote.key.flat()[:-1] + (None,))
      new_votes.append(datastore_utils.CopyEntity(vote, new_key=new_key))
    ndb.delete_multi(vote.key for vote in votes)
    ndb.put_multi(new_votes)

    self.assertLen(self.blockable_1.GetVotes(), 0)

  def testGetRules(self):
    self.assertLen(self.blockable_1.GetRules(), 0)
    self.assertLen(self.blockable_2.GetRules(), 0)

    test_utils.CreateSantaRule(self.blockable_1.key)
    test_utils.CreateSantaRule(self.blockable_1.key)
    test_utils.CreateSantaRule(self.blockable_1.key, **{'in_effect': False})
    test_utils.CreateSantaRule(self.blockable_2.key)
    test_utils.CreateSantaRule(self.blockable_2.key)
    test_utils.CreateSantaRule(self.blockable_2.key)
    test_utils.CreateSantaRule(self.blockable_2.key, **{'in_effect': False})

    self.assertLen(self.blockable_1.GetRules(), 2)
    self.assertLen(self.blockable_2.GetRules(), 3)
    self.assertLen(self.blockable_1.GetRules(in_effect=False), 3)
    self.assertLen(self.blockable_2.GetRules(in_effect=False), 4)

  def testGetStrongestVote_Upvote(self):

    self.assertIsNone(self.blockable_1.GetStrongestVote())

    for weight in [-1, -1, 1, 2, 6]:
      test_utils.CreateVote(self.blockable_1, weight=weight)

    vote = self.blockable_1.GetStrongestVote()
    self.assertIsNotNone(vote)
    self.assertEqual(6, vote.weight)

  def testGetStrongestVote_Downvote(self):

    self.assertIsNone(self.blockable_1.GetStrongestVote())

    for weight in [-6, -1, -1, 1, 2]:
      test_utils.CreateVote(self.blockable_1, weight=weight)

    vote = self.blockable_1.GetStrongestVote()
    self.assertIsNotNone(vote)
    self.assertEqual(-6, vote.weight)

  def testGetEvents(self):
    self.assertLen(self.blockable_1.GetEvents(), 0)
    test_utils.CreateEvents(self.blockable_1, 5)
    self.assertLen(self.blockable_1.GetEvents(), 5)

  def testIsVotingAllowed_Allowed(self):
    for state in constants.STATE.SET_VOTING_ALLOWED:
      blockable = test_utils.CreateBlockable(state=state)
      allowed, reason = blockable.IsVotingAllowed()
      self.assertTrue(allowed)
      self.assertIsNone(reason)

  def testIsVotingAllowed_Prohibited(self):
    for state in constants.STATE.SET_VOTING_PROHIBITED:
      blockable = test_utils.CreateBlockable(state=state)
      allowed, reason = blockable.IsVotingAllowed()
      self.assertFalse(allowed)
      self.assertIsNotNone(reason)

  def testIsVotingAllowed_AdminOnly(self):
    user = test_utils.CreateUser()
    admin = test_utils.CreateUser(admin=True)

    for state in constants.STATE.SET_VOTING_ALLOWED_ADMIN_ONLY:
      blockable = test_utils.CreateBlockable(state=state)

      # Test for a regular user.
      allowed, reason = blockable.IsVotingAllowed(current_user=user)
      self.assertFalse(allowed)
      self.assertIsNotNone(reason)

      # Test for an admin.
      allowed, reason = blockable.IsVotingAllowed(current_user=admin)
      self.assertTrue(allowed)
      self.assertIsNone(reason)

  def testIsVotingAllowed_Cert(self):
    user = test_utils.CreateUser()
    admin = test_utils.CreateUser(admin=True)

    cert = test_utils.CreateSantaCertificate()

    # Test for a regular user.
    allowed, reason = cert.IsVotingAllowed(current_user=user)
    self.assertFalse(allowed)
    self.assertIsNotNone(reason)

    # Test for an admin.
    allowed, reason = cert.IsVotingAllowed(current_user=admin)
    self.assertTrue(allowed)
    self.assertIsNone(reason)

  def testToDict_Score(self):
    blockable = test_utils.CreateBlockable()
    test_utils.CreateVote(blockable)
    # Recalculate the 'score' property
    blockable.put()

    # Mock out the blockable's _CalculateScore function.
    with mock.patch.object(
        blockable._properties['score'], '_func') as calc_mock:  # pylint: disable=protected-access
      blockable_dict = blockable.to_dict()
      self.assertFalse(calc_mock.called)
      self.assertIn('score', blockable_dict)
      self.assertEqual(1, blockable_dict['score'])

  def testToDict_VotingAllowed(self):
    for state in constants.STATE.SET_VOTING_ALLOWED:
      blockable = test_utils.CreateBlockable(state=state)
      blockable_dict = blockable.to_dict()
      self.assertIn('is_voting_allowed', blockable_dict)
      self.assertTrue(blockable_dict['is_voting_allowed'])
      self.assertIn('voting_prohibited_reason', blockable_dict)

  def testToDict_VotingAllowedAdminOnly_User(self):
    for state in constants.STATE.SET_VOTING_ALLOWED_ADMIN_ONLY:
      blockable = test_utils.CreateBlockable(state=state)
      blockable_dict = blockable.to_dict()
      self.assertIn('is_voting_allowed', blockable_dict)
      self.assertFalse(blockable_dict['is_voting_allowed'])
      self.assertIn('voting_prohibited_reason', blockable_dict)

  def testToDict_VotingAllowedAdminOnly_Admin(self):
    admin_user = test_utils.CreateUser(admin=True)
    self.Logout()
    self.Login(admin_user.email)
    for state in constants.STATE.SET_VOTING_ALLOWED_ADMIN_ONLY:
      blockable = test_utils.CreateBlockable(state=state)
      blockable_dict = blockable.to_dict()
      self.assertIn('is_voting_allowed', blockable_dict)
      self.assertTrue(blockable_dict['is_voting_allowed'])
      self.assertIn('voting_prohibited_reason', blockable_dict)

  def testToDict_VotingProhibited(self):
    for state in constants.STATE.SET_VOTING_PROHIBITED:
      blockable = test_utils.CreateBlockable(state=state)
      blockable_dict = blockable.to_dict()
      self.assertIn('is_voting_allowed', blockable_dict)
      self.assertFalse(blockable_dict['is_voting_allowed'])
      self.assertIn('voting_prohibited_reason', blockable_dict)

  def testGetById(self):
    blockable = test_utils.CreateBlockable()
    sha256 = blockable.key.id()
    self.assertIsNotNone(base.Blockable.get_by_id(sha256.lower()))
    self.assertIsNotNone(base.Blockable.get_by_id(sha256.upper()))


class BinaryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BinaryTest, self).setUp()

    self.blockable = test_utils.CreateBlockableEntity(base.Binary)

    self.user = test_utils.CreateUser(email=_TEST_EMAIL)
    self.Login(self.user.email)

  def testCertId(self):
    cert = test_utils.CreateBlockableEntity(base.Certificate)
    self.blockable.cert_key = cert.key
    self.blockable.put()

    self.assertEqual(cert.key.id(), self.blockable.cert_id)

  def testCertId_Empty(self):
    # Blockable with no cert_key should have no cert_id.
    self.assertIsNone(self.blockable.cert_id)

  def testTranslatePropertyQuery_CertId(self):
    field, val = 'cert_id', 'bar'

    new_field, new_val = base.Binary.TranslatePropertyQuery(field, val)

    self.assertEqual(val, ndb.Key(urlsafe=new_val).id())
    self.assertEqual('cert_key', new_field)

  def testTranslatePropertyQuery_CertId_NoQueryValue(self):
    field, val = 'cert_id', None

    new_field, new_val = base.Binary.TranslatePropertyQuery(field, val)

    self.assertIsNone(new_val)
    self.assertEqual('cert_key', new_field)

  def testTranslatePropertyQuery_NotCertId(self):
    pair = ('foo', 'bar')
    self.assertEqual(pair, base.Binary.TranslatePropertyQuery(*pair))

  def testToDict(self):
    self.assertIn('cert_id', self.blockable.to_dict())


class RuleTest(basetest.UpvoteTestCase):

  def testInsertBigQueryRow_LocalRule_UserKeyMissing(self):
    """Verifies that a LOCAL row is inserted, even if user_key is missing.

    The host_id and user_key columns have to be NULLABLE in order to support
    GLOBAL rows (which will lack values for both of these columns). If user_key
    is mistakenly omitted, we should still insert a LOCAL row with the values
    we have.
    """
    blockable_key = test_utils.CreateSantaBlockable().key
    local_rule = test_utils.CreateSantaRule(blockable_key, host_id='12345')
    local_rule.InsertBigQueryRow()

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.RULE], reset_mock=False)

    calls = self.GetBigQueryCalls()
    self.assertLen(calls, 1)
    self.assertEqual(constants.RULE_SCOPE.LOCAL, calls[0][1].get('scope'))

  def testInsertBigQueryRow_LocalRule_HostIdMissing(self):
    """Verifies that a LOCAL row is inserted, even if host_id is missing.

    The host_id and user_key columns have to be NULLABLE in order to support
    GLOBAL rows (which will lack values for both of these columns). If host_id
    is mistakenly omitted, we should still insert a LOCAL row with the values
    we have.
    """
    blockable_key = test_utils.CreateSantaBlockable().key
    user_key = test_utils.CreateUser().key
    local_rule = test_utils.CreateSantaRule(blockable_key, user_key=user_key)
    local_rule.InsertBigQueryRow()

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.RULE], reset_mock=False)

    calls = self.GetBigQueryCalls()
    self.assertLen(calls, 1)
    self.assertEqual(constants.RULE_SCOPE.LOCAL, calls[0][1].get('scope'))

  def testInsertBigQueryRow_GlobalRule(self):

    blockable_key = test_utils.CreateSantaBlockable().key
    global_rule = test_utils.CreateSantaRule(blockable_key)
    global_rule.InsertBigQueryRow()

    self.assertBigQueryInsertions(
        [constants.BIGQUERY_TABLE.RULE], reset_mock=False)

    calls = self.GetBigQueryCalls()
    self.assertLen(calls, 1)
    self.assertEqual(constants.RULE_SCOPE.GLOBAL, calls[0][1].get('scope'))


if __name__ == '__main__':
  basetest.main()

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
from google.appengine.ext import testbed

from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bigquery
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import user_map
from upvote.shared import constants


_TEST_EMAIL = user_map.UsernameToEmail('testemail')


class TestModel(base.BaseModelMixin, ndb.Model):
  int_prop = ndb.IntegerProperty()


class TestPlatformModel(base.BaseModelMixin, ndb.Model):
  int_prop = ndb.IntegerProperty()

  def GetPlatformName(self):
    return 'some_platform'


class BaseModelMixinTest(basetest.UpvoteTestCase):

  def testToDict_Put(self):
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {
        'int_prop': 111,
        'id': test_model.key.id(),
        'key': test_model.key.urlsafe()}
    self.assertDictEqual(expected, test_model.to_dict())

  def testToDict_NotPut(self):
    test_model = TestModel(int_prop=111)
    expected = {'int_prop': 111}
    self.assertDictEqual(expected, test_model.to_dict())

  def testToDict_WithPlatformName(self):
    test_model = TestPlatformModel(int_prop=111)
    expected = {
        'int_prop': 111,
        'operating_system_family': 'some_platform'}
    self.assertDictEqual(expected, test_model.to_dict())

  def testToDict_ExcludeId(self):

    # Verify that the ID shows up without 'exclude'.
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {
        'int_prop': 111,
        'id': test_model.key.id(),
        'key': test_model.key.urlsafe()}
    self.assertDictEqual(expected, test_model.to_dict())

    # Verify that the ID shows up with an irrelevant 'exclude'.
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {
        'int_prop': 111,
        'id': test_model.key.id(),
        'key': test_model.key.urlsafe()}
    self.assertDictEqual(expected, test_model.to_dict(exclude=['blah']))

    # Now verify that it doesn't with 'exclude'.
    test_model = TestModel(int_prop=111)
    test_model.put()
    expected = {'int_prop': 111}
    self.assertDictEqual(expected, test_model.to_dict(exclude=['id']))

  def testToDict_ExcludePlatformName(self):
    test_model = TestPlatformModel(int_prop=111)
    expected = {'int_prop': 111}
    self.assertDictEqual(expected, test_model.to_dict(
        exclude=['operating_system_family']))


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
    keys = self.event_1.GetKeysToInsert([], [])
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
    utils.DeleteProperty(self.event_2, 'count')

    self.event_1.Dedupe(self.event_2)

    self.assertEqual(2, self.event_1.count)

  def testGetKeysToInsert(self):
    keys = self.event_1.GetKeysToInsert(['foo', 'bar'], [])

    self.assertEqual(1, len(keys))
    expected_email = user_map.UsernameToEmail(self.event_1.executing_user)
    self.assertEqual(expected_email, keys[0].pairs()[0][1])

  def testGetKeysToInsert_Admin(self):
    usernames = ['foo', 'bar']
    with mock.patch.object(
        base.Event, 'run_by_local_admin', return_value=True):
      event = utils.CopyEntity(self.event_1)
      keys = event.GetKeysToInsert(usernames, [])

    self.assertEqual(2, len(keys))
    key_usernames = [user_map.EmailToUsername(key.flat()[1]) for key in keys]
    self.assertSameElements(usernames, key_usernames)

  def testGetKeysToInsert_BlockableKey(self):
    old_key = self.event_1.blockable_key
    self.event_1.blockable_key = ndb.Key(
        'bar', 'baz', parent=old_key)
    keys = self.event_1.GetKeysToInsert(['foo', 'bar'], [])

    self.assertEqual(5, len(keys[0].pairs()))
    self.assertEqual(old_key.pairs()[0], keys[0].pairs()[2])
    self.assertEqual(('bar', 'baz'), keys[0].pairs()[3])

  def testGetKeysToInsert_RelatedBinary(self):
    self.event_1.executing_user = None
    keys = self.event_1.GetKeysToInsert([], [])

    self.assertEqual([], keys)

  def testGetKeysToInsert_HostOwner(self):
    self.PatchSetting('EVENT_CREATION', constants.EVENT_CREATION.HOST_OWNER)
    keys = self.event_1.GetKeysToInsert([], ['foo'])

    self.assertEqual(1, len(keys))
    key_usernames = [user_map.EmailToUsername(key.flat()[1]) for key in keys]
    self.assertSameElements(['foo'], key_usernames)

  def testDedupeMultiple(self):
    keys = self.event_1.GetKeysToInsert(['foo'], [])
    event1 = utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.middle,
        last_blocked_dt=self.middle)
    event2 = utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.earlier,
        last_blocked_dt=self.later)
    event3 = utils.CopyEntity(
        self.event_1,
        new_key=keys[0],
        first_blocked_dt=self.middle,
        last_blocked_dt=self.later)

    events = base.Event.DedupeMultiple([event1, event2, event3])

    self.assertEqual(1, len(events))

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
    self.assertEqual(64, len(key.id()))


class BlockableTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BlockableTest, self).setUp()

    self.blockable_1 = test_utils.CreateBlockable()
    self.blockable_2 = test_utils.CreateBlockable()

    self.user = test_utils.CreateUser(email=_TEST_EMAIL)
    self.Login(self.user.email)

  def testChangeState(self):

    # Verify the Blockable is in the default state of UNTRUSTED.
    blockable_hash = self.blockable_1.blockable_hash
    blockable = base.Blockable.get_by_id(blockable_hash)
    self.assertIsNotNone(blockable)
    self.assertEqual(constants.STATE.UNTRUSTED, blockable.state)

    # Verify it has no AuditLogs.
    audit_logs = base.AuditLog.GetAll(blockable)
    self.assertEqual(0, len(audit_logs))

    # Note the state change timestamp.
    old_state_change_dt = blockable.state_change_dt

    # Change the state.
    blockable.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    blockable = base.Blockable.get_by_id(blockable_hash)
    self.assertIsNotNone(blockable)
    self.assertEqual(constants.STATE.BANNED, blockable.state)

    # Should have a single AuditLog now.
    audit_logs = base.AuditLog.GetAll(blockable)
    self.assertEqual(1, len(audit_logs))

    # And the state change timestamp should be increased.
    self.assertTrue(blockable.state_change_dt > old_state_change_dt)

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
    self.assertEqual(0, len(self.blockable_1.GetVotes()))
    self.assertEqual(0, len(self.blockable_2.GetVotes()))

    test_utils.CreateVotes(self.blockable_1, 3)
    test_utils.CreateVotes(self.blockable_2, 2)

    self.assertEqual(3, len(self.blockable_1.GetVotes()))
    self.assertEqual(2, len(self.blockable_2.GetVotes()))

  def testGetVotes_Inactive(self):
    self.assertEqual(0, len(self.blockable_1.GetVotes()))

    test_utils.CreateVotes(self.blockable_1, 2)

    self.assertEqual(2, len(self.blockable_1.GetVotes()))

    votes = base.Vote.query().fetch()
    new_votes = []
    for vote in votes:
      new_key = ndb.Key(flat=vote.key.flat()[:-1] + (None,))
      new_votes.append(utils.CopyEntity(vote, new_key=new_key))
    ndb.delete_multi(vote.key for vote in votes)
    ndb.put_multi(new_votes)

    self.assertEqual(0, len(self.blockable_1.GetVotes()))

  def testGetRules(self):
    self.assertEqual(0, len(self.blockable_1.GetRules()))
    self.assertEqual(0, len(self.blockable_2.GetRules()))

    test_utils.CreateSantaRule(self.blockable_1.key)
    test_utils.CreateSantaRule(self.blockable_1.key)
    test_utils.CreateSantaRule(self.blockable_1.key, **{'in_effect': False})
    test_utils.CreateSantaRule(self.blockable_2.key)
    test_utils.CreateSantaRule(self.blockable_2.key)
    test_utils.CreateSantaRule(self.blockable_2.key)
    test_utils.CreateSantaRule(self.blockable_2.key, **{'in_effect': False})

    self.assertEqual(2, len(self.blockable_1.GetRules()))
    self.assertEqual(3, len(self.blockable_2.GetRules()))
    self.assertEqual(3, len(self.blockable_1.GetRules(in_effect=False)))
    self.assertEqual(4, len(self.blockable_2.GetRules(in_effect=False)))

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
    self.assertEqual(0, len(self.blockable_1.GetEvents()))
    test_utils.CreateEvents(self.blockable_1, 5)
    self.assertEqual(5, len(self.blockable_1.GetEvents()))

  def testAddAuditLog(self):
    logs = base.AuditLog.GetAll(self.blockable_1)
    self.assertEqual(0, len(logs))
    base.AuditLog.Create(self.blockable_1, 'blah blah blah')
    logs = base.AuditLog.GetAll(self.blockable_1)
    self.assertEqual(1, len(logs))

    self.assertEqual(self.blockable_1.key, logs[0].target_object_key)
    self.assertEqual(logs[0].key.parent(), logs[0].target_object_key)

  def testAuditLogs_GetAll(self):

    # Create some interleaved AuditLogs for different Blockables.
    base.AuditLog.Create(self.blockable_1, 'message1', user='user')
    base.AuditLog.Create(self.blockable_2, 'message2', user='user')
    base.AuditLog.Create(self.blockable_1, 'message3', user='user')

    # Verify the AuditLogs for the first Blockable (ascending).
    blockable_1_logs = base.AuditLog.GetAll(self.blockable_1, ascending=True)
    self.assertEqual(2, len(blockable_1_logs))
    self.assertEqual('message1', blockable_1_logs[0].log_event)
    self.assertEqual('message3', blockable_1_logs[1].log_event)
    self.assertTrue(
        blockable_1_logs[0].recorded_dt < blockable_1_logs[1].recorded_dt)

    # Verify the AuditLogs for the second Blockable.
    blockable_2_logs = base.AuditLog.GetAll(self.blockable_2, ascending=True)
    self.assertEqual(1, len(blockable_2_logs))
    self.assertEqual('message2', blockable_2_logs[0].log_event)

    # Verify the AuditLogs for the first Blockable (descending).
    blockable_1_logs = base.AuditLog.GetAll(self.blockable_1, ascending=False)
    self.assertEqual(2, len(blockable_1_logs))
    self.assertEqual('message3', blockable_1_logs[0].log_event)
    self.assertEqual('message1', blockable_1_logs[1].log_event)
    self.assertTrue(
        blockable_1_logs[0].recorded_dt > blockable_1_logs[1].recorded_dt)

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

  def testResetState(self):
    blockable = test_utils.CreateBlockable(
        state=constants.STATE.BANNED, flagged=True)
    blockable.ResetState()

    retrieved_blockable = blockable.key.get()

    self.assertEqual(retrieved_blockable.state, constants.STATE.UNTRUSTED)
    self.assertFalse(retrieved_blockable.flagged)

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


class BlacklistTest(basetest.UpvoteTestCase):

  def setUp(self):

    self.testbed = testbed.Testbed()

    self.testbed.activate()
    self.testbed.init_datastore_v3_stub()
    self.testbed.init_memcache_stub()

    regexes = [
        r'.*7-Zip GUI.*',
        r'.*Firefox.*',
        r'.*Windows PowerShell.*',
        r'.*WinZip 17\.5 Setup.*',
        r'.*\.dll.*']

    for regex in regexes:
      base.Blacklist(regex=regex).put()

  def tearDown(self):
    self.testbed.deactivate()

  def testGetBlacklist(self):
    blacklist = base.Blacklist.GetBlacklist()
    self.assertEqual(5, len(blacklist))

  def testIsBlacklisted(self):
    self.assertTrue(base.Blacklist.IsBlacklisted('7-Zip GUI 2.0'))
    self.assertTrue(base.Blacklist.IsBlacklisted('Something Firefox Something'))
    self.assertTrue(base.Blacklist.IsBlacklisted('Fancy Windows PowerShell'))
    self.assertTrue(base.Blacklist.IsBlacklisted('WinZip 17.5 Setup Thing'))
    self.assertTrue(base.Blacklist.IsBlacklisted('not_malware.dll'))
    self.assertFalse(base.Blacklist.IsBlacklisted('Not Malware For Real'))


# Done for the sake of brevity.
USER = constants.USER_ROLE.USER
TRUSTED_USER = constants.USER_ROLE.TRUSTED_USER
ADMINISTRATOR = constants.USER_ROLE.ADMINISTRATOR


class UserTest(basetest.UpvoteTestCase):
  """Test User model."""

  def setUp(self):
    super(UserTest, self).setUp()
    self._voting_weights = settings.VOTING_WEIGHTS

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testGetOrInsert_ExistingUser_EmailAddr(self):

    base.User.get_or_insert(_TEST_EMAIL)
    self.assertEntityCount(base.User, 1)

    user = base.User.GetOrInsert(email_addr=_TEST_EMAIL)

    self.assertIsNotNone(user)
    self.assertEntityCount(base.User, 1)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testGetOrInsert_ExistingUser_AppEngineUser(self):

    base.User.get_or_insert(_TEST_EMAIL)
    self.assertEntityCount(base.User, 1)

    appengine_user = test_utils.CreateAppEngineUser(email=_TEST_EMAIL)

    user = base.User.GetOrInsert(appengine_user=appengine_user)

    self.assertIsNotNone(user)
    self.assertEntityCount(base.User, 1)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testGetOrInsert_NewUser_EmailAddr(self):

    self.assertEntityCount(base.User, 0)
    self.assertEntityCount(bigquery.UserRow, 0)

    user = base.User.GetOrInsert(email_addr=_TEST_EMAIL)

    self.assertIsNotNone(user)
    self.assertEntityCount(base.User, 1)
    self.assertEntityCount(bigquery.UserRow, 0)

    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertSetEqual(constants.PERMISSIONS.SET_USER, user.permissions)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.UserRow, 1)

  def testGetOrInsert_NewUser_EmailAddr_Lowercase(self):

    user = base.User.GetOrInsert(email_addr='UPPER@case.addr')
    self.assertIsNotNone(user)
    self.assertEqual('upper@case.addr', user.email)
    self.assertEqual('upper', user.nickname)

  def testGetOrInsert_NewUser_AppEngineUser(self):

    self.assertEntityCount(base.User, 0)
    self.assertEntityCount(bigquery.UserRow, 0)

    appengine_user = test_utils.CreateAppEngineUser(email=_TEST_EMAIL)
    user = base.User.GetOrInsert(appengine_user=appengine_user)

    self.assertIsNotNone(user)
    self.assertEntityCount(base.User, 1)
    self.assertEntityCount(bigquery.UserRow, 0)

    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertSetEqual(constants.PERMISSIONS.SET_USER, user.permissions)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.UserRow, 1)

  def testGetOrInsert_UnknownUserError(self):

    self.Patch(base.users, 'get_current_user', return_value=None)

    with self.assertRaises(base.UnknownUserError):
      base.User.GetOrInsert()

  def testPrePutHook(self):
    user = base.User.GetOrInsert(email_addr=_TEST_EMAIL)
    user.roles = [USER] * 100
    self.assertEqual(100, len(user.roles))
    user.put()
    self.assertEqual(1, len(user.roles))
    self.assertEquals([USER], user.roles)

  def testSetRoles_RemoveAll(self):
    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)

      email_addr = user.email
      base.User.SetRoles(email_addr, [])
      user = base.User.GetOrInsert(email_addr=email_addr)
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testSetRoles_InvalidUserRole(self):
    with self.LoggedInUser() as user:
      with self.assertRaises(base.InvalidUserRoleError):
        base.User.SetRoles(user.email, ['INVALID_ROLE'])

  def testSetRoles_NoChanges(self):

    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)
      old_vote_weight = user.vote_weight

    base.User.SetRoles(user.email, [constants.USER_ROLE.USER])
    user = base.User.GetOrInsert(email_addr=user.email)

    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertEqual(user.vote_weight, old_vote_weight)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)

  def testSetRoles_AddRole(self):

    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)
      self.assertEqual(
          self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    new_roles = [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER]
    base.User.SetRoles(user.email, new_roles)
    user = base.User.GetOrInsert(email_addr=user.email)

    self.assertListEqual(new_roles, user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.UserRow, 1)

  def testSetRoles_RemoveRole(self):

    old_roles = [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER]
    user = test_utils.CreateUser(email=_TEST_EMAIL, roles=old_roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    new_roles = [constants.USER_ROLE.USER]
    base.User.SetRoles(_TEST_EMAIL, new_roles)
    user = base.User.GetOrInsert(email_addr=_TEST_EMAIL)
    self.assertListEqual(new_roles, user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.UserRow, 1)

  def testUpdateRoles_AddRole(self):

    with self.LoggedInUser() as user:
      self.assertListEqual([constants.USER_ROLE.USER], user.roles)
      self.assertEqual(
          self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    base.User.UpdateRoles(user.email, add=[constants.USER_ROLE.SUPERUSER])
    user = base.User.GetOrInsert(email_addr=user.email)
    self.assertListEqual(
        [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER], user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.UserRow, 1)

  def testUpdateRoles_RemoveRole(self):

    old_roles = [constants.USER_ROLE.SUPERUSER, constants.USER_ROLE.USER]
    user = test_utils.CreateUser(email=_TEST_EMAIL, roles=old_roles)
    with self.LoggedInUser(user=user):
      self.assertEqual(
          self._voting_weights[constants.USER_ROLE.SUPERUSER], user.vote_weight)

    base.User.UpdateRoles(
        _TEST_EMAIL, remove=[constants.USER_ROLE.SUPERUSER])
    user = base.User.GetOrInsert(email_addr=_TEST_EMAIL)
    self.assertListEqual([constants.USER_ROLE.USER], user.roles)
    self.assertEqual(
        self._voting_weights[constants.USER_ROLE.USER], user.vote_weight)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 1)
    self.DrainTaskQueue(constants.TASK_QUEUE.BQ_PERSISTENCE)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_PERSISTENCE, 0)
    self.assertEntityCount(bigquery.UserRow, 1)

  def testIsAdmin_Nope(self):
    lowly_peon = test_utils.CreateUser(roles=[constants.USER_ROLE.USER])
    self.assertFalse(lowly_peon.is_admin)

  def testIsAdmin_HasAdminRole(self):
    fancy_admin = test_utils.CreateUser(
        roles=[constants.USER_ROLE.ADMINISTRATOR])
    self.assertTrue(fancy_admin.is_admin)

  def testIsAdmin_IsFailsafe(self):
    self.PatchSetting('FAILSAFE_ADMINISTRATORS', [_TEST_EMAIL])

    mr_failsafe = test_utils.CreateUser(
        email=_TEST_EMAIL, roles=[constants.USER_ROLE.USER])
    self.assertTrue(mr_failsafe.is_admin)

  def testPermissions_Admin(self):
    admin = test_utils.CreateUser(admin=True)
    self.assertSetEqual(constants.PERMISSIONS.SET_ALL, admin.permissions)

  def testPermissions_User(self):
    user = test_utils.CreateUser()
    self.assertSetEqual(constants.PERMISSIONS.SET_USER, user.permissions)


class HostTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(HostTest, self).setUp()
    self.host = base.Host(id='bar', hostname='foo')
    self.blockable = test_utils.CreateBlockable()
    self.user1 = test_utils.CreateUser()
    self.user2 = test_utils.CreateUser()

  def testGetAssociatedHostIds(self):
    with self.assertRaises(NotImplementedError):
      base.Host.GetAssociatedHostIds(self.user1)

  def testIsAssociatedWithUser(self):
    with self.assertRaises(NotImplementedError):
      self.host.IsAssociatedWithUser(self.user1)

  def testGetUserBlockRate(self):
    test_utils.CreateEvent(
        self.blockable, last_blocked_dt=datetime.datetime.utcnow(),
        parent=utils.ConcatenateKeys(self.user1.key, self.host.key))

    was_max, block_rate = self.host.GetUserBlockRate(
        self.user1, duration_to_fetch=datetime.timedelta(days=7))

    self.assertFalse(was_max)
    self.assertEqual(1. / 5, block_rate)

  def testGetUserBlockRate_WasMax(self):
    test_utils.CreateEvent(
        self.blockable, last_blocked_dt=datetime.datetime.utcnow(),
        parent=utils.ConcatenateKeys(self.user1.key, self.host.key))

    was_max, _ = self.host.GetUserBlockRate(
        self.user1, max_events_to_fetch=1)

    self.assertTrue(was_max)

  def testGetUserBlockRate_InvalidArgument(self):
    with self.assertRaises(base.InvalidArgumentError):
      self.host.GetUserBlockRate(
          self.user1, duration_to_fetch=datetime.timedelta(seconds=1))
    with self.assertRaises(base.InvalidArgumentError):
      self.host.GetUserBlockRate(self.user1, max_events_to_fetch=0)


class VoteTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(VoteTest, self).setUp()
    self.blockable = test_utils.CreateBlockable()
    self.user = test_utils.CreateUser()

  def testSetKey(self):
    expected_key = ndb.Key(flat=(
        self.blockable.key.flat() + self.user.key.flat() +
        ('Vote', base.Vote._IN_EFFECT_KEY_NAME)))
    key = base.Vote.GetKey(self.blockable.key, self.user.key)
    self.assertEqual(expected_key, key)

  def testSetKey_NotInEffect(self):
    expected_key = ndb.Key(flat=(
        self.blockable.key.flat() + self.user.key.flat() +
        ('Vote', None)))
    key = base.Vote.GetKey(
        self.blockable.key, self.user.key, in_effect=False)
    self.assertEqual(expected_key, key)

    # Putting the vote results in a random ID being generated.
    vote = test_utils.CreateVote(self.blockable)
    vote.key = key
    vote.put()
    self.assertIsNotNone(vote.key.id())

  def testBlockableKey(self):
    vote = test_utils.CreateVote(
        self.blockable, user_email=self.user.email)
    vote.key = base.Vote.GetKey(self.blockable.key, self.user.key)
    self.assertEqual(self.blockable.key, vote.blockable_key)

  def testBlockableKey_MultiPartKey(self):
    vote = test_utils.CreateVote(
        self.blockable, user_email=self.user.email)
    # Add another test_blockable key to simulate a length-two blockable key.
    vote.key = utils.ConcatenateKeys(
        self.blockable.key,
        base.Vote.GetKey(self.blockable.key, self.user.key))

    self.assertIsNotNone(vote.blockable_key)
    self.assertEqual(2, len(vote.blockable_key.pairs()))
    self.assertEqual(self.blockable.key, vote.blockable_key.parent())

  def testBlockableKey_NoKey(self):
    vote = test_utils.CreateVote(
        self.blockable, user_email=self.user.email)
    vote.key = None
    self.assertIsNone(vote.blockable_key)

  def testBlockableKey_BadKey(self):
    vote = test_utils.CreateVote(
        self.blockable, user_email=self.user.email)
    # Take out User key section.
    vote.key = utils.ConcatenateKeys(
        self.blockable.key, ndb.Key(base.Vote, vote.key.id()))
    self.assertIsNone(vote.blockable_key)

  def testUserKey(self):
    vote = test_utils.CreateVote(
        self.blockable, user_email=self.user.email)
    self.assertEqual(self.user.key, vote.user_key)

  def testInEffect(self):
    vote = test_utils.CreateVote(self.blockable)
    self.assertTrue(vote.in_effect)
    vote.key = None
    self.assertFalse(vote.in_effect)


if __name__ == '__main__':
  basetest.main()

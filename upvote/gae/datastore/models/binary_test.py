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

import mock

from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import binary as binary_models
from upvote.gae.datastore.models import cert as cert_models
from upvote.gae.datastore.models import vote as vote_models
from upvote.gae.lib.testing import basetest
from upvote.gae.utils import user_utils
from upvote.shared import constants


_TEST_EMAIL = user_utils.UsernameToEmail('testemail')


class BlockableTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BlockableTest, self).setUp()

    self.blockable_1 = test_utils.CreateBlockable()
    self.blockable_2 = test_utils.CreateBlockable()

    self.user = test_utils.CreateUser(email=_TEST_EMAIL)
    self.Login(self.user.email)

  def testAvoidInitialScoreCalculation(self):
    b = binary_models.Blockable(id_type='SHA256')
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

  def testGetEvents(self):
    self.assertLen(self.blockable_1.GetEvents(), 0)
    test_utils.CreateEvents(self.blockable_1, 5)
    self.assertLen(self.blockable_1.GetEvents(), 5)

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

  def testGetById(self):
    blockable = test_utils.CreateBlockable()
    sha256 = blockable.key.id()
    self.assertIsNotNone(binary_models.Blockable.get_by_id(sha256.lower()))
    self.assertIsNotNone(binary_models.Blockable.get_by_id(sha256.upper()))

  def testIsInstance(self):
    blockable = test_utils.CreateBlockable()
    self.assertTrue(blockable.IsInstance('Blockable'))
    self.assertTrue(blockable.IsInstance('blockable'))
    self.assertTrue(blockable.IsInstance('BLOCKABLE'))
    self.assertFalse(blockable.IsInstance('SomethingElse'))


class BinaryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(BinaryTest, self).setUp()

    self.blockable = test_utils.CreateBlockableEntity(binary_models.Binary)

    self.user = test_utils.CreateUser(email=_TEST_EMAIL)
    self.Login(self.user.email)

  def testCertId(self):
    cert = test_utils.CreateBlockableEntity(cert_models.Certificate)
    self.blockable.cert_key = cert.key
    self.blockable.put()

    self.assertEqual(cert.key.id(), self.blockable.cert_id)

  def testCertId_Empty(self):
    # Blockable with no cert_key should have no cert_id.
    self.assertIsNone(self.blockable.cert_id)

  def testTranslatePropertyQuery_CertId(self):
    field, val = 'cert_id', 'bar'

    new_field, new_val = binary_models.Binary.TranslatePropertyQuery(field, val)

    self.assertEqual(val, ndb.Key(urlsafe=new_val).id())
    self.assertEqual('cert_key', new_field)

  def testTranslatePropertyQuery_CertId_NoQueryValue(self):
    field, val = 'cert_id', None

    new_field, new_val = binary_models.Binary.TranslatePropertyQuery(field, val)

    self.assertIsNone(new_val)
    self.assertEqual('cert_key', new_field)

  def testTranslatePropertyQuery_NotCertId(self):
    pair = ('foo', 'bar')
    self.assertEqual(pair, binary_models.Binary.TranslatePropertyQuery(*pair))

  def testToDict(self):
    self.assertIn('cert_id', self.blockable.to_dict())

  def testIsInstance(self):
    binary = test_utils.CreateBlockableEntity(binary_models.Binary)
    self.assertTrue(binary.IsInstance('Blockable'))
    self.assertTrue(binary.IsInstance('Binary'))
    self.assertFalse(binary.IsInstance('SomethingElse'))


class Bit9BinaryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9BinaryTest, self).setUp()
    self.bit9_binary = test_utils.CreateBit9Binary()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testCalculateInstallerState(self):
    self.bit9_binary.detected_installer = False
    self.bit9_binary.put()
    test_utils.CreateBit9Rule(
        self.bit9_binary.key,
        in_effect=True,
        policy=constants.RULE_POLICY.FORCE_INSTALLER)

    self.assertTrue(self.bit9_binary.CalculateInstallerState())

  def testCalculateInstallerState_ForcedNot(self):
    self.bit9_binary.detected_installer = True
    self.bit9_binary.put()
    test_utils.CreateBit9Rule(
        self.bit9_binary.key,
        in_effect=True,
        policy=constants.RULE_POLICY.FORCE_NOT_INSTALLER)

    self.assertFalse(self.bit9_binary.CalculateInstallerState())

  def testCalculateInstallerState_NoInstallerRule_DefaultToDetected(self):
    unput_binary = binary_models.Bit9Binary(
        id='foo', detected_installer=True, is_installer=False)
    self.assertTrue(unput_binary.CalculateInstallerState())

  def testToDict_ContainsOs(self):
    with self.LoggedInUser():
      the_dict = self.bit9_binary.to_dict()
      self.assertEqual(
          constants.PLATFORM.WINDOWS,
          the_dict.get('operating_system_family', None))

  def testChangeState(self):

    # Verify the Bit9Binary is in the default state of UNTRUSTED.
    binary = test_utils.CreateBit9Binary()
    blockable_hash = binary.blockable_hash
    binary = binary_models.Bit9Binary.get_by_id(blockable_hash)
    self.assertIsNotNone(binary)
    self.assertEqual(constants.STATE.UNTRUSTED, binary.state)

    # Note the state change timestamp.
    old_state_change_dt = binary.state_change_dt

    # Change the state.
    binary.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    binary = binary_models.Bit9Binary.get_by_id(blockable_hash)
    self.assertIsNotNone(binary)
    self.assertEqual(constants.STATE.BANNED, binary.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

    # And the state change timestamp should be increased.
    self.assertGreater(binary.state_change_dt, old_state_change_dt)

  def testResetState(self):
    binary = test_utils.CreateBit9Binary(
        state=constants.STATE.BANNED, flagged=True)
    binary.ResetState()

    reset_binary = binary.key.get()

    self.assertEqual(reset_binary.state, constants.STATE.UNTRUSTED)
    self.assertFalse(reset_binary.flagged)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

  def testIsInstance(self):
    binary = test_utils.CreateBit9Binary()
    self.assertTrue(binary.IsInstance('Blockable'))
    self.assertTrue(binary.IsInstance('Binary'))
    self.assertTrue(binary.IsInstance('Bit9Binary'))
    self.assertFalse(binary.IsInstance('SomethingElse'))


class SantaModelTest(basetest.UpvoteTestCase):
  """Test Santa Models."""

  def setUp(self):

    super(SantaModelTest, self).setUp()

    self.santa_blockable = binary_models.SantaBlockable(
        id='aaaabbbbccccdddd',
        id_type=constants.ID_TYPE.SHA256,
        blockable_hash='aaaabbbbccccdddd',
        file_name='Mac.app',
        publisher='Arple',
        product_name='New Shiny',
        version='2.0')

    self.santa_certificate = cert_models.SantaCertificate(
        id='mmmmnnnnoooopppp',
        id_type=constants.ID_TYPE.SHA256,
        blockable_hash='mmmmnnnnoooopppp',
        file_name='MagicCert',
        publisher='Total Legit CA',
        version='7.0',
        common_name='Trustee',
        organization='Big Lucky',
        organizational_unit='The Unit')

    self.santa_blockable.put()
    self.santa_certificate.put()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)


class SantaBlockableTest(SantaModelTest):

  def testToDict_ContainsOs(self):
    with self.LoggedInUser():
      the_dict = self.santa_blockable.to_dict()
      self.assertEqual(
          constants.PLATFORM.MACOS,
          the_dict.get('operating_system_family', None))

  def testChangeState_Success(self):

    # Verify the SantaBlockable is in the default state of UNTRUSTED.
    blockable = test_utils.CreateSantaBlockable()
    blockable_hash = blockable.blockable_hash
    blockable = binary_models.SantaBlockable.get_by_id(blockable_hash)
    self.assertIsNotNone(blockable)
    self.assertEqual(constants.STATE.UNTRUSTED, blockable.state)

    # Note the state change timestamp.
    old_state_change_dt = blockable.state_change_dt

    # Change the state.
    blockable.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    blockable = binary_models.SantaBlockable.get_by_id(blockable_hash)
    self.assertIsNotNone(blockable)
    self.assertEqual(constants.STATE.BANNED, blockable.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

    # And the state change timestamp should be increased.
    self.assertGreater(blockable.state_change_dt, old_state_change_dt)

  def testChangeState_BinaryRowCreation_NoBlockableHash(self):

    hashless_santa_blockable = binary_models.SantaBlockable(
        id='aaaabbbbccccdddd',
        id_type=constants.ID_TYPE.SHA256,
        file_name='Whatever.app')
    hashless_santa_blockable.ChangeState(constants.STATE.SUSPECT)

    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

  def testResetState(self):
    blockable = test_utils.CreateSantaBlockable(
        state=constants.STATE.BANNED, flagged=True)
    blockable.ResetState()

    actual_binary = blockable.key.get()

    self.assertEqual(actual_binary.state, constants.STATE.UNTRUSTED)
    self.assertFalse(actual_binary.flagged)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

  def testIsInstance(self):
    blockable = test_utils.CreateSantaBlockable()
    self.assertTrue(blockable.IsInstance('Blockable'))
    self.assertTrue(blockable.IsInstance('Binary'))
    self.assertTrue(blockable.IsInstance('SantaBlockable'))
    self.assertFalse(blockable.IsInstance('SomethingElse'))


if __name__ == '__main__':
  basetest.main()

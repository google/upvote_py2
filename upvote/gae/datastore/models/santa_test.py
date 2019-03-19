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

"""Unit tests for santa.py."""

import mock

from google.appengine.ext import db
from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import santa
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


class SantaModelTest(basetest.UpvoteTestCase):
  """Test Santa Models."""

  def setUp(self):

    super(SantaModelTest, self).setUp()

    self.santa_blockable = santa.SantaBlockable(
        id='aaaabbbbccccdddd',
        id_type=constants.ID_TYPE.SHA256,
        blockable_hash='aaaabbbbccccdddd',
        file_name='Mac.app',
        publisher='Arple',
        product_name='New Shiny',
        version='2.0')

    self.santa_certificate = santa.SantaCertificate(
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

  def testToDict_ContainsIsVotingAllowed(self):
    blockable = test_utils.CreateBlockable()
    with self.LoggedInUser():
      self.assertIn('is_voting_allowed', blockable.to_dict())

  def testIsVotingAllowed_CertIsBlacklisted(self):
    """IsVotingAllowed() called on blockable signed by a blacklisted cert."""
    blockable_cert = test_utils.CreateSantaBlockable()
    blockable = test_utils.CreateSantaBlockable(cert_key=blockable_cert.key)
    test_utils.CreateSantaRule(
        blockable_cert.key,
        rule_type=constants.RULE_TYPE.CERTIFICATE,
        policy=constants.RULE_POLICY.BLACKLIST)

    with self.LoggedInUser():
      allowed, reason = blockable.IsVotingAllowed()

    self.assertFalse(allowed)
    self.assertIsNotNone(reason)

  def testIsVotingAllowed_Admin_CertIsBlacklisted(self):
    """IsVotingAllowed() called on blockable signed by a blacklisted cert."""
    blockable_cert = test_utils.CreateSantaBlockable()
    blockable = test_utils.CreateSantaBlockable(cert_key=blockable_cert.key)
    test_utils.CreateSantaRule(
        blockable_cert.key,
        rule_type=constants.RULE_TYPE.CERTIFICATE,
        policy=constants.RULE_POLICY.BLACKLIST)

    with self.LoggedInUser(admin=True):
      _, reason = blockable.IsVotingAllowed()

      # Ensure voting isn't disabled because of the blacklisted cert.
      self.assertNotEqual(
          constants.VOTING_PROHIBITED_REASONS.BLACKLISTED_CERT, reason)

  def testIsVotingAllowed_CallTheSuper(self):
    santa_blockable = test_utils.CreateSantaBlockable()
    with self.LoggedInUser():
      with mock.patch.object(
          santa.base.Blockable, 'IsVotingAllowed') as mock_method:
        santa_blockable.IsVotingAllowed()
        self.assertTrue(mock_method.called)

  def testChangeState_Success(self):

    # Verify the SantaBlockable is in the default state of UNTRUSTED.
    blockable = test_utils.CreateSantaBlockable()
    blockable_hash = blockable.blockable_hash
    blockable = santa.SantaBlockable.get_by_id(blockable_hash)
    self.assertIsNotNone(blockable)
    self.assertEqual(constants.STATE.UNTRUSTED, blockable.state)

    # Note the state change timestamp.
    old_state_change_dt = blockable.state_change_dt

    # Change the state.
    blockable.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    blockable = santa.SantaBlockable.get_by_id(blockable_hash)
    self.assertIsNotNone(blockable)
    self.assertEqual(constants.STATE.BANNED, blockable.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

    # And the state change timestamp should be increased.
    self.assertTrue(blockable.state_change_dt > old_state_change_dt)

  def testChangeState_BinaryRowCreation_NoBlockableHash(self):

    hashless_santa_blockable = santa.SantaBlockable(
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


class SantaCertificateTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(SantaCertificateTest, self).setUp()
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testChangeState(self):

    # Verify the SantaCertificate is in the default state of UNTRUSTED.
    cert = test_utils.CreateSantaCertificate()
    blockable_hash = cert.blockable_hash
    cert = santa.SantaCertificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.UNTRUSTED, cert.state)

    # Note the state change timestamp.
    old_state_change_dt = cert.state_change_dt

    # Change the state.
    cert.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    cert = santa.SantaCertificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.BANNED, cert.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)

    # And the state change timestamp should be increased.
    self.assertTrue(cert.state_change_dt > old_state_change_dt)

  def testResetState(self):
    cert = test_utils.CreateSantaCertificate(
        state=constants.STATE.BANNED, flagged=True)
    cert.ResetState()

    actual_cert = cert.key.get()

    self.assertEqual(actual_cert.state, constants.STATE.UNTRUSTED)
    self.assertFalse(actual_cert.flagged)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)

  def testIsInstance(self):
    cert = test_utils.CreateSantaCertificate()
    self.assertTrue(cert.IsInstance('Blockable'))
    self.assertTrue(cert.IsInstance('Certificate'))
    self.assertTrue(cert.IsInstance('SantaCertificate'))
    self.assertFalse(cert.IsInstance('SomethingElse'))



class SantaBundleTest(SantaModelTest):

  def testIgnoreCalculateScoreBeforeUpload(self):
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)
    test_utils.CreateVote(bundle)

    # Trigger the SantaBundle.score ComputedProperty calculation.
    bundle.put()

    # The score should have not reflected the real score until the bundle is
    # uploaded.
    self.assertEqual(0, bundle.key.get().score)

  def testIsVotingAllowed_BundleUpload(self):
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)
    self.assertFalse(bundle.has_been_uploaded)

    allowed, reason = bundle.IsVotingAllowed()

    self.assertFalse(allowed)
    self.assertEqual(
        constants.VOTING_PROHIBITED_REASONS.UPLOADING_BUNDLE, reason)

  def testIsVotingAllowed_HasFlaggedBinary(self):
    # First, create two unflagged binaries.
    blockables = test_utils.CreateSantaBlockables(2)
    bundle = test_utils.CreateSantaBundle(bundle_binaries=blockables)

    with self.LoggedInUser():
      allowed, reason = bundle.IsVotingAllowed()
      self.assertTrue(allowed)

      # Now flag one of the binaries.
      blockables[0].flagged = True
      blockables[0].put()

      allowed, reason = bundle.IsVotingAllowed()
      self.assertFalse(allowed)
      self.assertEqual(
          constants.VOTING_PROHIBITED_REASONS.FLAGGED_BINARY, reason)

  def testIsVotingAllowed_HasFlaggedCert(self):
    blockable = test_utils.CreateSantaBlockable(
        cert_key=self.santa_certificate.key)
    bundle = test_utils.CreateSantaBundle(bundle_binaries=[blockable])

    with self.LoggedInUser():
      allowed, reason = bundle.IsVotingAllowed()
      self.assertTrue(allowed)

      self.santa_certificate.flagged = True
      self.santa_certificate.put()

      allowed, reason = bundle.IsVotingAllowed()
      self.assertFalse(allowed)
      self.assertEqual(constants.VOTING_PROHIBITED_REASONS.FLAGGED_CERT, reason)

  def testIsVotingAllowed_DisableHasFlaggedChecks(self):
    blockables = test_utils.CreateSantaBlockables(26)
    bundle = test_utils.CreateSantaBundle(bundle_binaries=blockables)

    # Flag one of the binaries.
    blockables[0].flagged = True
    blockables[0].put()

    with self.LoggedInUser():
      # Ensure that the normal call succeeds in finding the flagged binary.
      allowed, reason = bundle.IsVotingAllowed()
      self.assertFalse(allowed)
      self.assertEqual(
          constants.VOTING_PROHIBITED_REASONS.FLAGGED_BINARY, reason)

      # In a transaction, the 26 searched blockables should exceed the allowed
      # limit of 25.
      with self.assertRaises(db.BadRequestError):
        ndb.transaction(
            lambda: bundle.IsVotingAllowed(enable_flagged_checks=True), xg=True)

      # With the checks disabled, IsVotingAllowed shouldn't raise an exception.
      def Test():
        allowed, reason = bundle.IsVotingAllowed(enable_flagged_checks=False)
        self.assertTrue(allowed)
        self.assertIsNone(reason)

      ndb.transaction(Test, xg=True)

  def testIsVotingAllowed_CallTheSuper(self):
    bundle = test_utils.CreateSantaBundle()
    with self.LoggedInUser():
      with mock.patch.object(
          santa.base.Blockable, 'IsVotingAllowed') as mock_method:
        bundle.IsVotingAllowed()
        self.assertTrue(mock_method.called)

  def testToDict(self):
    bundle = test_utils.CreateSantaBundle()
    with self.LoggedInUser():
      dict_ = bundle.to_dict()
    self.assertTrue(dict_['has_been_uploaded'])
    self.assertIsNone(dict_['cert_id'])

  def testToDict_CertId(self):
    blockable = test_utils.CreateSantaBlockable(
        cert_key=self.santa_certificate.key)
    bundle = test_utils.CreateSantaBundle(
        main_cert_key=self.santa_certificate.key,
        bundle_binaries=[blockable])
    with self.LoggedInUser():
      dict_ = bundle.to_dict()
    self.assertTrue(dict_['has_been_uploaded'])
    self.assertEqual(self.santa_certificate.key.id(), dict_['cert_id'])

  def testPersistsStateChange(self):
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)
    bundle.ChangeState(constants.STATE.SUSPECT)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BUNDLE)

  def testResetsState(self):
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)
    bundle.ResetState()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BUNDLE)


if __name__ == '__main__':
  basetest.main()

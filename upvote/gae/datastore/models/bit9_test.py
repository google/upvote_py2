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

"""Unit tests for bit9.py."""

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import bit9
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


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
    unput_binary = bit9.Bit9Binary(
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
    binary = bit9.Bit9Binary.get_by_id(blockable_hash)
    self.assertIsNotNone(binary)
    self.assertEqual(constants.STATE.UNTRUSTED, binary.state)

    # Note the state change timestamp.
    old_state_change_dt = binary.state_change_dt

    # Change the state.
    binary.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    binary = bit9.Bit9Binary.get_by_id(blockable_hash)
    self.assertIsNotNone(binary)
    self.assertEqual(constants.STATE.BANNED, binary.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.BINARY)

    # And the state change timestamp should be increased.
    self.assertTrue(binary.state_change_dt > old_state_change_dt)

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


class Bit9CertificateTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9CertificateTest, self).setUp()
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testChangeState(self):

    # Verify the Bit9Certificate is in the default state of UNTRUSTED.
    cert = test_utils.CreateBit9Certificate()
    blockable_hash = cert.blockable_hash
    cert = bit9.Bit9Certificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.UNTRUSTED, cert.state)

    # Note the state change timestamp.
    old_state_change_dt = cert.state_change_dt

    # Change the state.
    cert.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    cert = bit9.Bit9Certificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.BANNED, cert.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)

    # And the state change timestamp should be increased.
    self.assertTrue(cert.state_change_dt > old_state_change_dt)

  def testResetState(self):
    cert = test_utils.CreateBit9Certificate(
        state=constants.STATE.BANNED, flagged=True)
    cert.ResetState()

    reset_cert = cert.key.get()

    self.assertEqual(reset_cert.state, constants.STATE.UNTRUSTED)
    self.assertFalse(reset_cert.flagged)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)

  def testIsInstance(self):
    cert = test_utils.CreateBit9Certificate()
    self.assertTrue(cert.IsInstance('Blockable'))
    self.assertTrue(cert.IsInstance('Certificate'))
    self.assertTrue(cert.IsInstance('Bit9Certificate'))
    self.assertFalse(cert.IsInstance('SomethingElse'))


if __name__ == '__main__':
  basetest.main()

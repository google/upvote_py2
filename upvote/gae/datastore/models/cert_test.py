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

"""Unit tests for cert.py."""

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import cert as cert_models
from upvote.gae.lib.testing import basetest
from upvote.shared import constants


class Bit9CertificateTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(Bit9CertificateTest, self).setUp()
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testChangeState(self):

    # Verify the Bit9Certificate is in the default state of UNTRUSTED.
    cert = test_utils.CreateBit9Certificate()
    blockable_hash = cert.blockable_hash
    cert = cert_models.Bit9Certificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.UNTRUSTED, cert.state)

    # Note the state change timestamp.
    old_state_change_dt = cert.state_change_dt

    # Change the state.
    cert.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    cert = cert_models.Bit9Certificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.BANNED, cert.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)

    # And the state change timestamp should be increased.
    self.assertGreater(cert.state_change_dt, old_state_change_dt)

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


class SantaCertificateTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(SantaCertificateTest, self).setUp()
    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testChangeState(self):

    # Verify the SantaCertificate is in the default state of UNTRUSTED.
    cert = test_utils.CreateSantaCertificate()
    blockable_hash = cert.blockable_hash
    cert = cert_models.SantaCertificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.UNTRUSTED, cert.state)

    # Note the state change timestamp.
    old_state_change_dt = cert.state_change_dt

    # Change the state.
    cert.ChangeState(constants.STATE.BANNED)

    # Reload, and verify the state change.
    cert = cert_models.SantaCertificate.get_by_id(blockable_hash)
    self.assertIsNotNone(cert)
    self.assertEqual(constants.STATE.BANNED, cert.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.CERTIFICATE)

    # And the state change timestamp should be increased.
    self.assertGreater(cert.state_change_dt, old_state_change_dt)

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



if __name__ == '__main__':
  basetest.main()

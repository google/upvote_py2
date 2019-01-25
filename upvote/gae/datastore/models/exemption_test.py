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

"""Tests for exemption models."""

import datetime
import mock

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import exemption
from upvote.gae.datastore.models import host as host_models
from upvote.gae.lib.testing import basetest

from upvote.shared import constants


class MysteryHost(host_models.Host):
  """A Host Model which doesn't implement GetPlatformName()."""


class ExemptionTest(basetest.UpvoteTestCase):

  def testCanChangeToState(self):
    exm = test_utils.CreateExemption('aaa').get()  # Initial state is REQUESTED
    self.assertTrue(exm.CanChangeToState(constants.EXEMPTION_STATE.PENDING))
    self.assertFalse(exm.CanChangeToState(constants.EXEMPTION_STATE.APPROVED))

  def testGet(self):
    host_id = '12345'
    self.assertIsNone(exemption.Exemption.Get(host_id))
    test_utils.CreateExemption(host_id)
    self.assertIsNotNone(exemption.Exemption.Get(host_id))

  def testExists(self):
    host_id = '12345'
    self.assertFalse(exemption.Exemption.Exists(host_id))
    test_utils.CreateExemption(host_id)
    self.assertTrue(exemption.Exemption.Exists(host_id))

  def testGetPlatform_Unknown(self):

    host_id = MysteryHost().put().id()
    exm_key = test_utils.CreateExemption(host_id)
    with self.assertRaises(exemption.UnknownPlatformError):
      exemption.Exemption.GetPlatform(exm_key)

  def testGetPlatform_Success(self):

    host_id = test_utils.CreateSantaHost().key.id()
    exm_key = test_utils.CreateExemption(host_id)
    self.assertEqual(
        constants.PLATFORM.MACOS, exemption.Exemption.GetPlatform(exm_key))

    host_id = test_utils.CreateBit9Host().key.id()
    exm_key = test_utils.CreateExemption(host_id)
    self.assertEqual(
        constants.PLATFORM.WINDOWS, exemption.Exemption.GetPlatform(exm_key))

  def testGetHostId(self):
    expected_host_id = test_utils.CreateSantaHost().key.id()
    exm_key = test_utils.CreateExemption(expected_host_id)
    actual_host_id = exemption.Exemption.GetHostId(exm_key)
    self.assertEqual(expected_host_id, actual_host_id)

  @mock.patch.object(exemption.monitoring, 'state_changes')
  def testInsert_Success(self, mock_metric):

    self.assertEntityCount(exemption.Exemption, 0)

    host_id = 'valid_host_id'
    actual_key = exemption.Exemption.Insert(
        host_id, datetime.datetime.utcnow(),
        constants.EXEMPTION_REASON.DEVELOPER_MACOS)

    expected_key = exemption.Exemption.CreateKey(host_id)
    self.assertEqual(expected_key, actual_key)

    self.assertEntityCount(exemption.Exemption, 1)
    self.assertIsNotNone(expected_key.get())
    mock_metric.Increment.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

  @mock.patch.object(exemption.monitoring, 'state_changes')
  def testInsert_AlreadyExistsError(self, mock_metric):

    self.assertEntityCount(exemption.Exemption, 0)

    host_id = 'valid_host_id'
    exemption.Exemption.Insert(
        host_id, datetime.datetime.utcnow(),
        constants.EXEMPTION_REASON.DEVELOPER_MACOS)

    self.assertEntityCount(exemption.Exemption, 1)
    mock_metric.Increment.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

    # Attempt a duplicate insertion.
    with self.assertRaises(exemption.AlreadyExistsError):
      exemption.Exemption.Insert(
          host_id, datetime.datetime.utcnow(),
          constants.EXEMPTION_REASON.DEVELOPER_MACOS)

  @mock.patch.object(exemption.monitoring, 'state_changes')
  def testChangeState_InvalidExemptionError(self, mock_metric):
    exm_key = exemption.Exemption.CreateKey('invalid_host_id')
    with self.assertRaises(exemption.InvalidExemptionError):
      exemption.Exemption.ChangeState(
          exm_key, constants.EXEMPTION_STATE.APPROVED)
    mock_metric.Increment.assert_not_called()

  @mock.patch.object(exemption.monitoring, 'state_changes')
  def testChangeState_InvalidStateChangeError(self, mock_metric):

    host_id = 'valid_host_id'
    exm_key = exemption.Exemption.Insert(
        host_id, datetime.datetime.utcnow(),
        constants.EXEMPTION_REASON.DEVELOPER_MACOS)

    mock_metric.Increment.assert_called_once()
    mock_metric.reset_mock()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

    with self.assertRaises(exemption.InvalidStateChangeError):
      exemption.Exemption.ChangeState(
          exm_key, constants.EXEMPTION_STATE.APPROVED)
    mock_metric.Increment.assert_not_called()

  @mock.patch.object(exemption.monitoring, 'state_changes')
  def testChangeState_InvalidDetailsError(self, mock_metric):

    self.assertEntityCount(exemption.Exemption, 0)

    host_id = 'valid_host_id'
    exm_key = exemption.Exemption.Insert(
        host_id,
        datetime.datetime.utcnow(),
        constants.EXEMPTION_REASON.OTHER,
        other_text='Test')

    self.assertEntityCount(exemption.Exemption, 1)
    mock_metric.Increment.assert_called_once()
    mock_metric.reset_mock()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

    bad_details = ['aaa', None, 'bbb']
    with self.assertRaises(exemption.InvalidDetailsError):
      exemption.Exemption.ChangeState(
          exm_key, constants.EXEMPTION_STATE.PENDING, details=bad_details)
    exm = exm_key.get()

    self.assertEqual(constants.EXEMPTION_STATE.REQUESTED, exm.state)
    self.assertEntityCount(exemption.Exemption, 1)
    mock_metric.Increment.assert_not_called()

  @mock.patch.object(exemption.monitoring, 'state_changes')
  def testChangeState_Success(self, mock_metric):

    self.assertEntityCount(exemption.Exemption, 0)

    host_id = 'valid_host_id'
    exm_key = exemption.Exemption.Insert(
        host_id,
        datetime.datetime.utcnow(),
        constants.EXEMPTION_REASON.OTHER,
        other_text='Test')

    self.assertEntityCount(exemption.Exemption, 1)
    mock_metric.Increment.assert_called_once()
    mock_metric.reset_mock()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

    exemption.Exemption.ChangeState(
        exm_key, constants.EXEMPTION_STATE.PENDING)
    exm = exm_key.get()

    self.assertEqual(constants.EXEMPTION_STATE.PENDING, exm.state)
    self.assertEntityCount(exemption.Exemption, 1)
    mock_metric.Increment.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)


if __name__ == '__main__':
  basetest.main()

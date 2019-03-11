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

"""Unit tests for api.py."""

import datetime
import mock

from google.appengine.ext import ndb
from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.lib.bit9 import api as bit9_api
from upvote.gae.lib.exemption import api
from upvote.gae.lib.exemption import checks
from upvote.gae.lib.testing import basetest
from upvote.gae.lib.testing import bit9test
from upvote.shared import constants


# Done for brevity.
_STATE = constants.EXEMPTION_STATE
_BIT9_LEVEL = constants.BIT9_ENFORCEMENT_LEVEL
_SANTA_MODE = constants.CLIENT_MODE
_REASON = constants.EXEMPTION_REASON
_DURATION = constants.EXEMPTION_DURATION


class MysteryHost(host_models.Host):
  """A Host Model which doesn't implement GetPlatformName()."""


class UnsupportedHost(host_models.Host):
  """A Host Model which has an unsupported platform."""

  def GetPlatformName(self):
    return 'Windows 95'


class ChangeEnforcementInBit9Test(bit9test.Bit9TestCase):

  @mock.patch.object(api.monitoring, 'enforcement_errors')
  def testUnknownHostError(self, mock_metric):
    with self.assertRaises(api.UnknownHostError):
      api._ChangeEnforcementInBit9('invalid_host_id', _BIT9_LEVEL.MONITOR)
    mock_metric.Increment.assert_called_once()

  @mock.patch.object(api.monitoring, 'enforcement_errors')
  def testInvalidEnforcementLevelError(self, mock_metric):
    host_id = test_utils.CreateBit9Host().key.id()
    with self.assertRaises(api.InvalidEnforcementLevelError):
      api._ChangeEnforcementInBit9(host_id, 'WHATEVER')
    mock_metric.Increment.assert_called_once()


class ChangeEnforcementInSantaTest(basetest.UpvoteTestCase):

  @mock.patch.object(api.monitoring, 'enforcement_errors')
  def testUnknownHostError(self, mock_metric):
    with self.assertRaises(api.UnknownHostError):
      api._ChangeEnforcementInSanta('invalid_host_id', _SANTA_MODE.MONITOR)
    mock_metric.Increment.assert_called_once()

  @mock.patch.object(api.monitoring, 'enforcement_errors')
  def testInvalidClientModeError(self, mock_metric):
    host_id = test_utils.CreateSantaHost().key.id()
    with self.assertRaises(api.InvalidClientModeError):
      api._ChangeEnforcementInSanta(host_id, 'WHATEVER')
    mock_metric.Increment.assert_called_once()

  def testLockdown(self):
    host_key = test_utils.CreateSantaHost(
        client_mode=_SANTA_MODE.MONITOR,
        last_postflight_dt=datetime.datetime.now(),
        primary_user='aaaa').key
    api._ChangeEnforcementInSanta(host_key.id(), _SANTA_MODE.LOCKDOWN)
    self.assertEqual(_SANTA_MODE.LOCKDOWN, host_key.get().client_mode)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)

  @mock.patch.object(api, 'ChangeTransitiveWhitelisting')
  def testMonitor_TransitiveDisabled(self, mock_change_tw):
    host_key = test_utils.CreateSantaHost(
        client_mode=_SANTA_MODE.LOCKDOWN,
        last_postflight_dt=datetime.datetime.now(),
        primary_user='aaaa',
        transitive_whitelisting_enabled=False).key
    api._ChangeEnforcementInSanta(host_key.id(), _SANTA_MODE.MONITOR)
    self.assertEqual(_SANTA_MODE.MONITOR, host_key.get().client_mode)
    mock_change_tw.assert_not_called()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)

  @mock.patch.object(api, 'ChangeTransitiveWhitelisting')
  def testMonitor_TransitiveEnabled(self, mock_change_tw):
    host_key = test_utils.CreateSantaHost(
        client_mode=_SANTA_MODE.LOCKDOWN,
        last_postflight_dt=datetime.datetime.now(),
        primary_user='aaaa',
        transitive_whitelisting_enabled=True).key
    api._ChangeEnforcementInSanta(host_key.id(), _SANTA_MODE.MONITOR)
    self.assertEqual(_SANTA_MODE.MONITOR, host_key.get().client_mode)
    mock_change_tw.assert_called_once()
    self.assertFalse(mock_change_tw.call_args_list[0][0][1])
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)


class EnableLockdownTest(basetest.UpvoteTestCase):

  @mock.patch.object(api, '_ChangeEnforcementInBit9')
  def testBit9(self, mock_change):
    host_id = test_utils.CreateBit9Host().key.id()
    exm_key = test_utils.CreateExemption(host_id)
    api._EnableLockdown(exm_key)
    mock_change.assert_called_once_with(host_id, _BIT9_LEVEL.LOCKDOWN)

  @mock.patch.object(api, '_ChangeEnforcementInSanta')
  def testSanta(self, mock_change):
    host_id = test_utils.CreateSantaHost().key.id()
    exm_key = test_utils.CreateExemption(host_id)
    api._EnableLockdown(exm_key)
    mock_change.assert_called_once_with(host_id, _SANTA_MODE.LOCKDOWN)


class DisableLockdownTest(basetest.UpvoteTestCase):

  @mock.patch.object(api, '_ChangeEnforcementInBit9')
  def testBit9(self, mock_change):
    host_id = test_utils.CreateBit9Host().key.id()
    exm_key = test_utils.CreateExemption(host_id)
    api._DisableLockdown(exm_key)
    mock_change.assert_called_once_with(host_id, _BIT9_LEVEL.MONITOR)

  @mock.patch.object(api, '_ChangeEnforcementInSanta')
  def testSanta(self, mock_change):
    host_id = test_utils.CreateSantaHost().key.id()
    exm_key = test_utils.CreateExemption(host_id)
    api._DisableLockdown(exm_key)
    mock_change.assert_called_once_with(host_id, _SANTA_MODE.MONITOR)


@checks.PolicyCheck
def _ApprovingPolicyCheck(_):
  return (_STATE.APPROVED, None)


@checks.PolicyCheck
def _DenyingPolicyCheck(_):
  return (_STATE.DENIED, 'HA HA HA NO')


@checks.PolicyCheck
def _EscalatingPolicyCheck(_):
  return (_STATE.ESCALATED, 'TBD')


@checks.PolicyCheck
def _InvalidResultPolicyCheck(_):
  return ('PURPLE', None)


@checks.PolicyCheck
def _ExceptionPolicyCheck(_):
  raise Exception('OMGWTF')


class RequestTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(RequestTest, self).setUp()
    self.mock_send = self.Patch(api.notify.mail_utils, 'Send')

  def testInvalidReasonError(self):
    with self.assertRaises(api.InvalidReasonError):
      api.Request('host_id', 'some_reason', 'other text', _DURATION.DAY)
    self.mock_send.assert_not_called()

  def testInvalidDurationError(self):
    with self.assertRaises(api.InvalidDurationError):
      api.Request('host_id', _REASON.DEVELOPER_MACOS, 'other text', 'FOREVER')
    self.mock_send.assert_not_called()

  def testFirstRequest(self):

    host_id = test_utils.CreateBit9Host().key.id()
    self.assertIsNone(exemption_models.Exemption.Get(host_id))

    api.Request(host_id, _REASON.DEVELOPER_MACOS, 'other text', _DURATION.DAY)
    self.assertIsNotNone(exemption_models.Exemption.Get(host_id))
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()

  def testRenew_Success_AlreadyExpired(self):

    host_id = test_utils.CreateBit9Host().key.id()
    test_utils.CreateExemption(host_id, initial_state=_STATE.EXPIRED)

    api.Request(host_id, _REASON.DEVELOPER_MACOS, 'other text', _DURATION.DAY)
    exm = exemption_models.Exemption.Get(host_id)
    self.assertEqual(_STATE.REQUESTED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()

  def testRenew_Success_NotYetExpired(self):

    host_id = test_utils.CreateBit9Host().key.id()
    test_utils.CreateExemption(host_id, initial_state=_STATE.APPROVED)

    api.Request(host_id, _REASON.DEVELOPER_MACOS, 'other text', _DURATION.DAY)
    exm = exemption_models.Exemption.Get(host_id)
    self.assertEqual(_STATE.REQUESTED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()

  def testRenew_Failure(self):

    host_id = test_utils.CreateBit9Host().key.id()
    test_utils.CreateExemption(host_id, initial_state=_STATE.ESCALATED)

    with self.assertRaises(api.InvalidRenewalError):
      api.Request(host_id, _REASON.DEVELOPER_MACOS, 'other text', _DURATION.DAY)
    self.mock_send.assert_not_called()

  def testRenew_NoOtherText(self):

    host_id = test_utils.CreateBit9Host().key.id()
    test_utils.CreateExemption(host_id, initial_state=_STATE.CANCELLED)

    api.Request(host_id, _REASON.DEVELOPER_MACOS, None, _DURATION.DAY)
    self.assertIsNotNone(exemption_models.Exemption.Get(host_id))
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()


class ProcessTest(basetest.UpvoteTestCase):

  def _PatchPolicyChecks(self, *args):
    values = {constants.PLATFORM.MACOS: args}
    patcher = mock.patch.dict(api._POLICY_CHECKS, values=values, clear=True)
    self.addCleanup(patcher.stop)
    patcher.start()

  @mock.patch.object(api.monitoring, 'processing_errors')
  def testInitialStateChange_InvalidStateChangeError(self, mock_metric):

    # Simulate a user creating a new Exemption in the REQUESTED state.
    exm_key = test_utils.CreateExemption('12345')
    self.assertEqual(_STATE.REQUESTED, exm_key.get().state)

    # Simulate the Exemption transitioning to PENDING due to either the user
    # request, or the processing cron. Both end up calling Process().
    exemption_models.Exemption.ChangeState(exm_key, _STATE.PENDING)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

    # If the user request and processing cron occur around the same time,
    # they will both be trying to transition from REQUESTED to PENDING, a benign
    # race condition that shouldn't make noise.
    api.Process(exm_key)
    self.assertEqual(_STATE.PENDING, exm_key.get().state)
    mock_metric.Increment.assert_not_called()

  @mock.patch.object(api.monitoring, 'processing_errors')
  @mock.patch.object(api.exemption_models.Exemption, 'ChangeState')
  def testInitialStateChange_Exception(self, mock_change_state, mock_metric):

    exm_key = test_utils.CreateExemption('12345')
    self.assertEqual(_STATE.REQUESTED, exm_key.get().state)

    # If the initial state change fails unexpectedly, ensure that the state
    # remains as REQUESTED, and noise is made.
    mock_change_state.side_effect = Exception

    api.Process(exm_key)
    self.assertEqual(_STATE.REQUESTED, exm_key.get().state)
    mock_metric.Increment.assert_called_once()

  @mock.patch.object(api.monitoring, 'processing_errors')
  def testCannotDeterminePlatform(self, mock_metric):

    MysteryHost(id='host_id').put()
    exm_key = test_utils.CreateExemption('host_id')

    api.Process(exm_key)
    self.assertEqual(_STATE.DENIED, exm_key.get().state)
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)
    mock_metric.Increment.assert_called_once()

  @mock.patch.object(api.monitoring, 'processing_errors')
  def testPolicyNotDefinedForPlatform(self, mock_metric):

    self._PatchPolicyChecks()

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(host_key.id())

    api.Process(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.DENIED, exm.state)
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)
    mock_metric.Increment.assert_called_once()

  @mock.patch.object(api, '_DisableLockdown')
  def testEmptyPolicy(self, mock_disable):

    self._PatchPolicyChecks()

    host_key = test_utils.CreateSantaHost().key
    exm_key = test_utils.CreateExemption(host_key.id())

    api.Process(exm_key)
    exm = exm_key.get()

    mock_disable.assert_called()
    self.assertEqual(_STATE.APPROVED, exm.state)
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)

  @mock.patch.object(api.monitoring, 'processing_errors')
  def testException_PolicyCheckException(self, mock_metric):

    host_key = test_utils.CreateSantaHost().key
    exm_key = test_utils.CreateExemption(host_key.id())

    self._PatchPolicyChecks(
        _ApprovingPolicyCheck,
        _ApprovingPolicyCheck,
        _ExceptionPolicyCheck)

    api.Process(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.REQUESTED, exm.state)
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)
    mock_metric.Increment.assert_called_once()

  @mock.patch.object(api.monitoring, 'processing_errors')
  def testInvalidResultState(self, mock_metric):

    host_key = test_utils.CreateSantaHost().key
    exm_key = test_utils.CreateExemption(host_key.id())

    self._PatchPolicyChecks(
        _ApprovingPolicyCheck,
        _InvalidResultPolicyCheck)

    api.Process(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.DENIED, exm.state)
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)
    mock_metric.Increment.assert_called_once()

  @mock.patch.object(api, '_DisableLockdown')
  def testApproved(self, mock_disable):

    host_key = test_utils.CreateSantaHost().key
    exm_key = test_utils.CreateExemption(host_key.id())

    self._PatchPolicyChecks(
        _ApprovingPolicyCheck,
        _ApprovingPolicyCheck)

    api.Process(exm_key)
    exm = exm_key.get()

    mock_disable.assert_called()
    self.assertEqual(_STATE.APPROVED, exm.state)
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)

  @mock.patch.object(api, '_EnableLockdown')
  @mock.patch.object(api, '_DisableLockdown')
  def testEscalated(self, mock_disable, mock_enable):

    host_key = test_utils.CreateSantaHost().key
    exm_key = test_utils.CreateExemption(host_key.id())

    self._PatchPolicyChecks(
        _ApprovingPolicyCheck,
        _EscalatingPolicyCheck,
        _ApprovingPolicyCheck)

    api.Process(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.ESCALATED, exm.state)
    mock_disable.assert_not_called()
    mock_enable.assert_not_called()
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)

  @mock.patch.object(api, '_EnableLockdown')
  @mock.patch.object(api, '_DisableLockdown')
  def testDenied(self, mock_disable, mock_enable):

    host_key = test_utils.CreateSantaHost().key
    exm_key = test_utils.CreateExemption(host_key.id())

    self._PatchPolicyChecks(
        _ApprovingPolicyCheck,
        _EscalatingPolicyCheck,
        _DenyingPolicyCheck)

    api.Process(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.DENIED, exm.state)
    mock_disable.assert_not_called()
    mock_enable.assert_not_called()
    self.assertBigQueryInsertions([constants.BIGQUERY_TABLE.EXEMPTION] * 2)


class ApproveTest(bit9test.Bit9TestCase):

  def setUp(self):
    super(ApproveTest, self).setUp()
    self.mock_send = self.Patch(api.notify.mail_utils, 'Send')

  @mock.patch.object(api, '_DisableLockdown')
  def testInvalidStateChangeError(self, mock_disable):

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.DENIED)

    with self.assertRaises(api.InvalidStateChangeError):
      api.Approve(exm_key)
    mock_disable.assert_not_called()
    self.assertEqual(_STATE.DENIED, exm_key.get().state)
    self.mock_send.assert_not_called()

  def testSuccess_Santa(self):

    host_key = test_utils.CreateSantaHost(primary_user='aaaa').key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.PENDING)

    api.Approve(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.APPROVED, exm.state)
    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST, constants.BIGQUERY_TABLE.EXEMPTION])
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()


class DenyTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(DenyTest, self).setUp()
    self.mock_send = self.Patch(api.notify.mail_utils, 'Send')

  def testInvalidStateChangeError(self):

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.APPROVED)

    with self.assertRaises(api.InvalidStateChangeError):
      api.Deny(exm_key)
    self.assertEqual(_STATE.APPROVED, exm_key.get().state)
    self.mock_send.assert_not_called()

  def testSuccess(self):

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.PENDING)

    api.Deny(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.DENIED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()


class EscalateTest(basetest.UpvoteTestCase):

  def testInvalidStateChangeError(self):

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.APPROVED)

    with self.assertRaises(api.InvalidStateChangeError):
      api.Escalate(exm_key)
    self.assertEqual(_STATE.APPROVED, exm_key.get().state)

  def testSuccess(self):
    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.PENDING)

    api.Escalate(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.ESCALATED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)


class ExpireTest(bit9test.Bit9TestCase):

  def setUp(self):
    super(ExpireTest, self).setUp()
    self.mock_send = self.Patch(api.notify.mail_utils, 'Send')

  @mock.patch.object(api, '_EnableLockdown')
  def testInvalidStateChangeError(self, mock_enable):

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.ESCALATED)

    with self.assertRaises(api.InvalidStateChangeError):
      api.Expire(exm_key)
    mock_enable.assert_not_called()
    self.assertEqual(_STATE.ESCALATED, exm_key.get().state)
    self.mock_send.assert_not_called()

  def testSuccess_Santa(self):

    host_key = test_utils.CreateSantaHost(primary_user='aaaa').key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.APPROVED)

    api.Expire(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.EXPIRED, exm.state)
    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST, constants.BIGQUERY_TABLE.EXEMPTION])
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()


class RevokeTest(bit9test.Bit9TestCase):

  def setUp(self):
    super(RevokeTest, self).setUp()
    self.mock_send = self.Patch(api.notify.mail_utils, 'Send')

  @mock.patch.object(api, '_EnableLockdown')
  def testInvalidStateChangeError(self, mock_enable):

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.CANCELLED)

    with self.assertRaises(api.InvalidStateChangeError):
      api.Revoke(exm_key, ['justification'])
    mock_enable.assert_not_called()
    self.assertEqual(_STATE.CANCELLED, exm_key.get().state)
    self.mock_send.assert_not_called()

  def testSuccess_Santa(self):

    host_key = test_utils.CreateSantaHost(primary_user='aaaa').key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.APPROVED)

    api.Revoke(exm_key, ['reasons'])
    exm = exm_key.get()

    self.assertEqual(_STATE.REVOKED, exm.state)
    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST, constants.BIGQUERY_TABLE.EXEMPTION])
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()


class CancelTest(bit9test.Bit9TestCase):

  def setUp(self):
    super(CancelTest, self).setUp()
    self.mock_send = self.Patch(api.notify.mail_utils, 'Send')

  @mock.patch.object(api, '_EnableLockdown')
  def testInvalidStateChangeError(self, mock_enable):

    host_key = test_utils.CreateBit9Host().key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.DENIED)

    with self.assertRaises(api.InvalidStateChangeError):
      api.Cancel(exm_key)
    mock_enable.assert_not_called()
    self.assertEqual(_STATE.DENIED, exm_key.get().state)
    self.mock_send.assert_not_called()

  def testSuccess_Santa(self):

    host_key = test_utils.CreateSantaHost(primary_user='aaaa').key
    exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.APPROVED)

    api.Cancel(exm_key)
    exm = exm_key.get()

    self.assertEqual(_STATE.CANCELLED, exm.state)
    self.assertBigQueryInsertions([
        constants.BIGQUERY_TABLE.HOST, constants.BIGQUERY_TABLE.EXEMPTION])
    self.DrainTaskQueue(constants.TASK_QUEUE.EXEMPTIONS)
    self.mock_send.assert_called_once()


class ChangeTransitiveWhitelistingTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(ChangeTransitiveWhitelistingTest, self).setUp()

  def testNotSantaClient(self):
    host = test_utils.CreateBit9Host()
    with self.assertRaises(api.UnsupportedClientError):
      api.ChangeTransitiveWhitelisting(host.key.id(), True)

  @mock.patch.object(api.mail_utils, 'Send')
  def testNoChange(self, mock_send):

    host = test_utils.CreateSantaHost(transitive_whitelisting_enabled=True)

    api.ChangeTransitiveWhitelisting(host.key.id(), True)

    self.assertTrue(host.key.get().transitive_whitelisting_enabled)
    mock_send.assert_not_called()
    self.assertNoBigQueryInsertions()

  @mock.patch.object(api.mail_utils, 'Send')
  def testEnable_NoExemption(self, mock_send):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(
        primary_user=user.nickname, transitive_whitelisting_enabled=False)

    api.ChangeTransitiveWhitelisting(host.key.id(), True)

    self.assertTrue(host.key.get().transitive_whitelisting_enabled)
    mock_send.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)

  @mock.patch.object(api, 'Cancel')
  @mock.patch.object(api.mail_utils, 'Send')
  def testEnable_InactiveExemption(self, mock_send, mock_cancel):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(
        primary_user=user.nickname, transitive_whitelisting_enabled=False)
    test_utils.CreateExemption(
        host.key.id(), initial_state=constants.EXEMPTION_STATE.CANCELLED)

    api.ChangeTransitiveWhitelisting(host.key.id(), True)

    self.assertTrue(host.key.get().transitive_whitelisting_enabled)
    mock_send.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)
    mock_cancel.assert_not_called()

  @mock.patch.object(api, 'Cancel')
  @mock.patch.object(api.mail_utils, 'Send')
  def testEnable_ActiveExemption(self, mock_send, mock_cancel):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(
        primary_user=user.nickname, transitive_whitelisting_enabled=False)
    test_utils.CreateExemption(
        host.key.id(), initial_state=constants.EXEMPTION_STATE.APPROVED)

    api.ChangeTransitiveWhitelisting(host.key.id(), True)

    self.assertTrue(host.key.get().transitive_whitelisting_enabled)
    mock_send.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)
    mock_cancel.assert_called_once()

  @mock.patch.object(api.mail_utils, 'Send')
  def testDisable(self, mock_send):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(
        primary_user=user.nickname, transitive_whitelisting_enabled=True)

    api.ChangeTransitiveWhitelisting(host.key.id(), False)

    self.assertFalse(host.key.get().transitive_whitelisting_enabled)
    mock_send.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.HOST)


if __name__ == '__main__':
  basetest.main()

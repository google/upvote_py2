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

"""Unit tests for Exemptions handlers."""

import httplib
import mock

import webapp2

from upvote.gae.datastore import test_utils
from upvote.gae.datastore.models import exemption as exemption_models
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.web import exemptions
from upvote.shared import constants


_STATE = constants.EXEMPTION_STATE  # Done for brevity.


class ExemptionsTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication(routes=[exemptions.ROUTES])
    super(ExemptionsTest, self).setUp(wsgi_app=app)
    self.PatchValidateXSRFToken()


class GetExemptionHandlerTest(ExemptionsTest):

  ROUTE = '/exemptions/%s'

  def testGet_AsUser_Success(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())

    with self.LoggedInUser(user=user):
      self.testapp.get(self.ROUTE % host.key.id(), status=httplib.OK)

  def testGet_AsUser_Forbidden(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())

    with self.LoggedInUser():  # Without arguments, will log in as a new user.
      self.testapp.get(self.ROUTE % host.key.id(), status=httplib.FORBIDDEN)

  def testGet_AsAdmin_Success(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    test_utils.CreateExemption(host.key.id())

    with self.LoggedInUser(admin=True):
      self.testapp.get(self.ROUTE % host.key.id(), status=httplib.OK)

  def testGet_HostNotFound(self):
    with self.LoggedInUser():
      self.testapp.get(self.ROUTE % 'invalid_host_id', status=httplib.NOT_FOUND)

  def testGet_ExemptionNotFound(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    with self.LoggedInUser(user=user):
      self.testapp.get(self.ROUTE % host.key.id(), status=httplib.NOT_FOUND)


class RequestExemptionHandlerTest(ExemptionsTest):

  ROUTE = '/exemptions/%s/request'

  def setUp(self):
    super(RequestExemptionHandlerTest, self).setUp()
    self.mock_process = self.Patch(exemptions.exemption_api, 'Process')

  def testPost_NoPermission(self):
    user = test_utils.CreateUser(roles=[constants.USER_ROLE.UNTRUSTED_USER])
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    with self.LoggedInUser(user=user):
      self.testapp.post(self.ROUTE % host.key.id(), status=httplib.FORBIDDEN)
    self.mock_process.assert_not_called()

  def testPost_HostNotFound(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % 'invalid_host_id', status=httplib.NOT_FOUND)
    self.mock_process.assert_not_called()

  def testPost_UnsupportedPlatformError(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)
    self.Patch(host, 'GetPlatformName', return_value='PlayStation 4')

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), status=httplib.NOT_IMPLEMENTED)
    self.mock_process.assert_not_called()

  def testPost_WindowsNotSupported(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateBit9Host(users=[user.nickname])

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), status=httplib.NOT_IMPLEMENTED)
    self.mock_process.assert_not_called()

  def testPost_Forbidden(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    with self.LoggedInUser():  # Without arguments, will log in as a new user.
      self.testapp.post(self.ROUTE % host.key.id(), status=httplib.FORBIDDEN)
    self.mock_process.assert_not_called()

  def testPost_BadRequest_NoReasonProvided(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {'term': 'DAY'}

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.BAD_REQUEST)
    self.mock_process.assert_not_called()

  def testPost_BadRequest_InvalidReasonErrorProvided(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {
        'term': 'DAY',
        'reason': 'some_invalid_reason'}

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.BAD_REQUEST)
    self.mock_process.assert_not_called()

  def testPost_BadRequest_NoOtherExplanationProvided(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {
        'term': 'DAY',
        'reason': constants.EXEMPTION_REASON.OTHER}

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.BAD_REQUEST)
    self.mock_process.assert_not_called()

  def testPost_BadRequest_NoDurationProvided(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {
        'reason': constants.EXEMPTION_REASON.DEVELOPER_MACOS}

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.BAD_REQUEST)
    self.mock_process.assert_not_called()

  def testPost_BadRequest_InvalidDurationErrorProvided(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {
        'duration': 'some_invalid_duration',
        'reason': constants.EXEMPTION_REASON.DEVELOPER_MACOS}

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.BAD_REQUEST)
    self.mock_process.assert_not_called()

  def testPost_BadRequest_InvalidRenewalError(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {
        'duration': 'DAY',
        'reason': constants.EXEMPTION_REASON.DEVELOPER_MACOS}

    with self.LoggedInUser(user=user):
      self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.OK)
      self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.BAD_REQUEST)

    exm = exemption_models.Exemption.Get(host.key.id())
    self.assertEqual(constants.EXEMPTION_STATE.REQUESTED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.mock_process.assert_called_once()

  def testPost_AsUser_Success(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {
        'duration': 'DAY',
        'reason': constants.EXEMPTION_REASON.DEVELOPER_MACOS}

    with self.LoggedInUser(user=user):
      response = self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.OK)

    output = response.json
    exm = exemption_models.Exemption.Get(host.key.id())

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(constants.EXEMPTION_STATE.REQUESTED, output['state'])
    self.assertEqual(constants.EXEMPTION_STATE.REQUESTED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.mock_process.assert_called_once()

  def testPost_AsAdmin_Success(self):

    user = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(primary_user=user.nickname)

    params = {
        'duration': 'DAY',
        'reason': constants.EXEMPTION_REASON.DEVELOPER_MACOS}

    with self.LoggedInUser(admin=True):
      response = self.testapp.post(
          self.ROUTE % host.key.id(), params=params, status=httplib.OK)

    output = response.json
    exm = exemption_models.Exemption.Get(host.key.id())

    self.assertIn('application/json', response.headers['Content-type'])
    self.assertIsInstance(output, dict)
    self.assertEqual(constants.EXEMPTION_STATE.REQUESTED, output['state'])
    self.assertEqual(constants.EXEMPTION_STATE.REQUESTED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)
    self.mock_process.assert_called_once()


class EscalateExemptionHandlerTest(ExemptionsTest):

  ROUTE = '/exemptions/%s/escalate'

  def setUp(self):
    super(EscalateExemptionHandlerTest, self).setUp()

    self.user = test_utils.CreateUser()
    host_key = test_utils.CreateSantaHost(primary_user=self.user.nickname).key
    self.host_id = host_key.id()
    self.exm_key = test_utils.CreateExemption(
        self.host_id, initial_state=_STATE.DENIED)

  def testPost_Success(self):

    with self.LoggedInUser(user=self.user):
      self.testapp.post(self.ROUTE % self.host_id, status=httplib.OK)

    exm = exemption_models.Exemption.Get(self.host_id)
    self.assertEqual(constants.EXEMPTION_STATE.ESCALATED, exm.state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

  def testPost_HostNotFound(self):
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          self.ROUTE % 'invalid_host_id', status=httplib.NOT_FOUND)

  def testPost_ExemptionNotFound(self):

    other_host_key = test_utils.CreateSantaHost(
        primary_user=self.user.nickname).key
    other_host_id = other_host_key.id()

    with self.LoggedInUser(user=self.user):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.NOT_FOUND)

  def testPost_Forbidden_Pending(self):

    other_host_key = test_utils.CreateSantaHost(
        primary_user=self.user.nickname).key
    other_host_id = other_host_key.id()
    test_utils.CreateExemption(other_host_id, initial_state=_STATE.PENDING)

    with self.LoggedInUser(user=self.user):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.FORBIDDEN)

  @mock.patch.object(
      exemptions.exemption_api, 'Escalate', side_effect=Exception)
  def testPost_Exception(self, mock_escalate):
    with self.LoggedInUser(user=self.user):
      self.testapp.post(
          self.ROUTE % self.host_id, status=httplib.INTERNAL_SERVER_ERROR)


class ApproveExemptionHandlerTest(ExemptionsTest):

  ROUTE = '/exemptions/%s/approve'

  def setUp(self):
    super(ApproveExemptionHandlerTest, self).setUp()

    host_key = test_utils.CreateSantaHost().key
    self.host_id = host_key.id()
    self.exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.ESCALATED)

  @mock.patch.object(exemptions.exemption_api, '_DisableLockdown')
  def testPost_Success(self, mock_disable):

    with self.LoggedInUser(admin=True):
      params = {'justification': 'I want to'}
      self.testapp.post(self.ROUTE % self.host_id, params, status=httplib.OK)

    self.assertEqual(
        constants.EXEMPTION_STATE.APPROVED, self.exm_key.get().state)
    mock_disable.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

  @mock.patch.object(exemptions.exemption_api, 'Approve', side_effect=Exception)
  def testPost_Exception(self, mock_approve):

    with self.LoggedInUser(admin=True):
      params = {'justification': 'I want to'}
      self.testapp.post(
          self.ROUTE % self.host_id,
          params, status=httplib.INTERNAL_SERVER_ERROR)

    self.assertEqual(
        constants.EXEMPTION_STATE.ESCALATED, self.exm_key.get().state)
    mock_approve.assert_called_once()

  def testPost_Forbidden_NonAdmin(self):

    with self.LoggedInUser():
      params = {'justification': 'I want to'}
      self.testapp.post(
          self.ROUTE % self.host_id, params, status=httplib.FORBIDDEN)

    self.assertEqual(
        constants.EXEMPTION_STATE.ESCALATED, self.exm_key.get().state)

  def testPost_BadRequest_JustificationMissing(self):

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % self.host_id, status=httplib.BAD_REQUEST)

    self.assertEqual(
        constants.EXEMPTION_STATE.ESCALATED, self.exm_key.get().state)

  def testPost_HostNotFound(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % 'invalid_host_id', status=httplib.NOT_FOUND)

  def testPost_Forbidden_Pending(self):

    other_host_key = test_utils.CreateSantaHost().key
    other_host_id = other_host_key.id()
    test_utils.CreateExemption(other_host_id, initial_state=_STATE.PENDING)

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.FORBIDDEN)

  def testPost_ExemptionNotFound(self):

    other_host_key = test_utils.CreateSantaHost().key
    other_host_id = other_host_key.id()

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.NOT_FOUND)


class DenyExemptionHandlerTest(ExemptionsTest):

  ROUTE = '/exemptions/%s/deny'

  def setUp(self):
    super(DenyExemptionHandlerTest, self).setUp()

    host_key = test_utils.CreateSantaHost().key
    self.host_id = host_key.id()
    self.exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.ESCALATED)

  def testPost_Success(self):

    with self.LoggedInUser(admin=True):
      params = {'justification': 'I want to'}
      self.testapp.post(self.ROUTE % self.host_id, params, status=httplib.OK)

    self.assertEqual(constants.EXEMPTION_STATE.DENIED, self.exm_key.get().state)
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

  @mock.patch.object(exemptions.exemption_api, 'Deny', side_effect=Exception)
  def testPost_Exception(self, mock_deny):

    with self.LoggedInUser(admin=True):
      params = {'justification': 'I want to'}
      self.testapp.post(
          self.ROUTE % self.host_id, params,
          status=httplib.INTERNAL_SERVER_ERROR)

    self.assertEqual(
        constants.EXEMPTION_STATE.ESCALATED, self.exm_key.get().state)
    mock_deny.assert_called_once()
    self.assertNoBigQueryInsertions()

  def testPost_Forbidden_NonAdmin(self):

    with self.LoggedInUser():
      params = {'justification': 'I want to'}
      self.testapp.post(
          self.ROUTE % self.host_id, params, status=httplib.FORBIDDEN)

    self.assertEqual(
        constants.EXEMPTION_STATE.ESCALATED, self.exm_key.get().state)

  def testPost_BadRequest_JustificationMissing(self):

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % self.host_id, status=httplib.BAD_REQUEST)

    self.assertEqual(
        constants.EXEMPTION_STATE.ESCALATED, self.exm_key.get().state)

  def testPost_HostNotFound(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % 'invalid_host_id', status=httplib.NOT_FOUND)

  def testPost_Forbidden_Pending(self):

    other_host_key = test_utils.CreateSantaHost().key
    other_host_id = other_host_key.id()
    test_utils.CreateExemption(other_host_id, initial_state=_STATE.PENDING)

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.FORBIDDEN)

  def testPost_ExemptionNotFound(self):

    other_host_key = test_utils.CreateSantaHost().key
    other_host_id = other_host_key.id()

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.NOT_FOUND)


class RevokeExemptionHandlerTest(ExemptionsTest):

  ROUTE = '/exemptions/%s/revoke'

  def setUp(self):
    super(RevokeExemptionHandlerTest, self).setUp()

    host_key = test_utils.CreateSantaHost().key
    self.host_id = host_key.id()
    self.exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.APPROVED)

  @mock.patch.object(exemptions.exemption_api, '_EnableLockdown')
  def testPost_Success(self, mock_enable):

    with self.LoggedInUser(admin=True):
      params = {'justification': 'I want to'}
      self.testapp.post(
          self.ROUTE % self.host_id, params, status=httplib.OK)

    self.assertEqual(
        constants.EXEMPTION_STATE.REVOKED, self.exm_key.get().state)
    mock_enable.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

  @mock.patch.object(exemptions.exemption_api, 'Revoke', side_effect=Exception)
  def testPost_Exception(self, mock_revoke):

    with self.LoggedInUser(admin=True):
      params = {'justification': 'I want to'}
      self.testapp.post(
          self.ROUTE % self.host_id, params,
          status=httplib.INTERNAL_SERVER_ERROR)

    self.assertEqual(
        constants.EXEMPTION_STATE.APPROVED, self.exm_key.get().state)
    mock_revoke.assert_called_once()
    self.assertNoBigQueryInsertions()

  def testPost_Forbidden(self):

    with self.LoggedInUser():
      params = {'justification': 'I want to'}
      self.testapp.post(
          self.ROUTE % self.host_id, params, status=httplib.FORBIDDEN)

    self.assertEqual(
        constants.EXEMPTION_STATE.APPROVED, self.exm_key.get().state)

  def testPost_BadRequest_JustificationMissing(self):

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % self.host_id, status=httplib.BAD_REQUEST)

    self.assertEqual(
        constants.EXEMPTION_STATE.APPROVED, self.exm_key.get().state)

  def testPost_HostNotFound(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % 'invalid_host_id', status=httplib.NOT_FOUND)

  def testPost_ExemptionNotFound(self):

    other_host_key = test_utils.CreateSantaHost().key
    other_host_id = other_host_key.id()

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.NOT_FOUND)


class CancelExemptionHandlerTest(ExemptionsTest):

  ROUTE = '/exemptions/%s/cancel'

  def setUp(self):
    super(CancelExemptionHandlerTest, self).setUp()

    self.valid_user = test_utils.CreateUser()
    host_key = test_utils.CreateSantaHost(
        primary_user=self.valid_user.nickname).key
    self.host_id = host_key.id()
    self.exm_key = test_utils.CreateExemption(
        host_key.id(), initial_state=_STATE.APPROVED)

  def testPost_InvalidUser_NonAdmin(self):

    invalid_user = test_utils.CreateUser()
    with self.LoggedInUser(user=invalid_user):
      self.testapp.post(self.ROUTE % self.host_id, status=httplib.FORBIDDEN)

    self.assertEqual(
        constants.EXEMPTION_STATE.APPROVED, self.exm_key.get().state)
    self.assertNoBigQueryInsertions()

  def testPost_InvalidUser_Admin(self):

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % self.host_id, status=httplib.FORBIDDEN)

    self.assertEqual(
        constants.EXEMPTION_STATE.APPROVED, self.exm_key.get().state)
    self.assertNoBigQueryInsertions()

  @mock.patch.object(exemptions.exemption_api, 'Cancel', side_effect=Exception)
  def testPost_Exception(self, mock_cancel):

    with self.LoggedInUser(user=self.valid_user):
      self.testapp.post(
          self.ROUTE % self.host_id, status=httplib.INTERNAL_SERVER_ERROR)

    mock_cancel.assert_called_once()
    self.assertEqual(
        constants.EXEMPTION_STATE.APPROVED, self.exm_key.get().state)
    self.assertNoBigQueryInsertions()

  @mock.patch.object(exemptions.exemption_api, '_EnableLockdown')
  def testPost_ValidUser(self, mock_enable):

    with self.LoggedInUser(user=self.valid_user):
      self.testapp.post(self.ROUTE % self.host_id, status=httplib.OK)

    self.assertEqual(
        constants.EXEMPTION_STATE.CANCELLED, self.exm_key.get().state)
    mock_enable.assert_called_once()
    self.assertBigQueryInsertion(constants.BIGQUERY_TABLE.EXEMPTION)

  def testPost_HostNotFound(self):
    with self.LoggedInUser():
      self.testapp.post(
          self.ROUTE % 'invalid_host_id', status=httplib.NOT_FOUND)

  def testPost_ExemptionNotFound(self):

    other_host_key = test_utils.CreateSantaHost().key
    other_host_id = other_host_key.id()

    with self.LoggedInUser(admin=True):
      self.testapp.post(self.ROUTE % other_host_id, status=httplib.NOT_FOUND)


if __name__ == '__main__':
  basetest.main()

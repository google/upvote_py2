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

import datetime
import httplib
import json
import uuid
import zlib

import mock
import webapp2
from google.appengine.ext import ndb

from upvote.gae import settings
from upvote.gae.datastore import test_utils
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import host as host_models
from upvote.gae.datastore.models import package as package_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.datastore.models import user as user_models
from upvote.gae.lib.testing import basetest
from upvote.gae.modules.upvote_app.api.santa import auth
from upvote.gae.modules.upvote_app.api.santa import sync
from upvote.gae.utils import user_utils
from upvote.gae.utils import xsrf_utils
from upvote.shared import constants


# Done for the sake of brevity.
CLIENT_MODE = constants.CLIENT_MODE
TABLE = constants.BIGQUERY_TABLE
PREFLIGHT = sync._PREFLIGHT
EVENT_UPLOAD = sync._EVENT_UPLOAD
RULE_DOWNLOAD = sync._RULE_DOWNLOAD


class XsrfHandlerTest(basetest.UpvoteTestCase):

  ROUTE = '/api/santa/xsrf/%s'

  def setUp(self):

    app = webapp2.WSGIApplication(routes=sync.ROUTES)
    super(XsrfHandlerTest, self).setUp(wsgi_app=app)

    self.mock_request_metric = mock.Mock()
    self.Patch(
        sync.XsrfHandler,
        'RequestCounter',
        new_callable=mock.PropertyMock,
        return_value=self.mock_request_metric)

  @mock.patch.object(sync.xsrf_utils, 'GenerateToken')
  def testPost(self, mock_generate):
    mock_generate.return_value = 'fake_token'
    fake_uuid = str(uuid.uuid4()).upper()
    response = self.testapp.post(self.ROUTE % fake_uuid, status=httplib.OK)
    self.assertEqual('fake_token', response.headers[xsrf_utils.DEFAULT_HEADER])
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)


class SantaApiTestCase(basetest.UpvoteTestCase):

  def setUp(self, wsgi_app=None):
    super(SantaApiTestCase, self).setUp(wsgi_app=wsgi_app)
    self.mock_request_metric = mock.Mock()
    self.PatchValidateXSRFToken()
    self.Patch(auth, 'ValidateClient')


class SantaRequestHandlerTest(SantaApiTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/(.*)', sync.SantaRequestHandler)])
    super(SantaRequestHandlerTest, self).setUp(wsgi_app=app)

    self.Patch(
        sync.SantaRequestHandler,
        'RequestCounter',
        new_callable=mock.PropertyMock,
        return_value=self.mock_request_metric)

    self.Patch(sync.monitoring, 'client_validations')

    sync.SantaRequestHandler.post = lambda x, y: 'A'

  def tearDown(self):
    super(SantaRequestHandlerTest, self).tearDown()
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = True
    sync.SantaRequestHandler.SHOULD_PARSE_JSON = True

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  @mock.patch.object(sync.auth, 'ValidateClient', return_value=True)
  def testDispatch_ClientValidation_Success(self, mock_validate):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False

    self.PatchSetting(
        'SANTA_CLIENT_VALIDATION', constants.VALIDATION_MODE.FAIL_CLOSED)
    headers = {'Foo': 'bar'}
    self.testapp.post_json('/my-uuid', {}, headers=headers)

    mock_validate.assert_called_once_with(mock.ANY, 'my-uuid')
    self.assertContainsSubset(headers, mock_validate.call_args[0][0])
    sync.monitoring.client_validations.Success.assert_called_once()

  @mock.patch.object(sync.auth, 'ValidateClient', return_value=False)
  def testDispatch_ClientValidation_Failure(self, mock_validate):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False

    self.PatchSetting(
        'SANTA_CLIENT_VALIDATION', constants.VALIDATION_MODE.FAIL_CLOSED)
    self.testapp.post_json(
        '/my-uuid', {}, headers={'Foo': 'bar'}, status=httplib.FORBIDDEN)
    sync.monitoring.client_validations.Failure.assert_called_once()

  @mock.patch.object(sync.auth, 'ValidateClient', return_value=False)
  def testDispatch_ClientValidation_NoValidation(self, mock_validate):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False

    self.PatchSetting(
        'SANTA_CLIENT_VALIDATION', constants.VALIDATION_MODE.NONE)
    headers = {'Foo': 'bar'}
    self.testapp.post_json('/my-uuid', {}, headers=headers)

    self.assertFalse(mock_validate.called)
    sync.monitoring.client_validations.Success.assert_not_called()
    sync.monitoring.client_validations.Failure.assert_not_called()

  @mock.patch.object(sync.auth, 'ValidateClient', side_effect=Exception)
  def testDispatch_ClientValidation_FailOpen(self, mock_validate):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False

    self.PatchSetting(
        'SANTA_CLIENT_VALIDATION', constants.VALIDATION_MODE.FAIL_OPEN)
    headers = {'Foo': 'bar'}
    self.testapp.post_json('/my-uuid', {}, headers=headers)

    mock_validate.assert_called_once_with(mock.ANY, 'my-uuid')
    self.assertContainsSubset(headers, mock_validate.call_args[0][0])
    sync.monitoring.client_validations.Success.assert_called_once()

  @mock.patch.object(sync.auth, 'ValidateClient', side_effect=Exception)
  def testDispatch_ClientValidation_FailClosed(self, mock_validate):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False

    self.PatchSetting(
        'SANTA_CLIENT_VALIDATION', constants.VALIDATION_MODE.FAIL_CLOSED)
    headers = {'Foo': 'bar'}
    self.testapp.post_json(
        '/my-uuid', {}, headers=headers, status=httplib.FORBIDDEN)

    mock_validate.assert_called_once_with(mock.ANY, 'my-uuid')
    self.assertContainsSubset(headers, mock_validate.call_args[0][0])
    sync.monitoring.client_validations.Failure.assert_called_once()

  @mock.patch.object(sync.auth, 'ValidateClient', side_effect=Exception)
  def testDispatch_ClientValidation_BadMode(self, mock_validate):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False

    self.PatchSetting('SANTA_CLIENT_VALIDATION', 'not a real value')
    headers = {'Foo': 'bar'}
    self.testapp.post_json(
        '/my-uuid', {}, headers=headers, status=httplib.FORBIDDEN)

    mock_validate.assert_called_once_with(mock.ANY, 'my-uuid')
    self.assertContainsSubset(headers, mock_validate.call_args[0][0])
    sync.monitoring.client_validations.Success.assert_not_called()
    sync.monitoring.client_validations.Failure.assert_called_once()

  def testDispatch_RejectNoComputer(self):
    response = self.testapp.post('/', {}, status=httplib.BAD_REQUEST)
    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.BAD_REQUEST)

  def testDispatch_RejectUnknownComputer(self):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = True

    response = self.testapp.post('/my-uuid', {}, status=httplib.FORBIDDEN)

    self.assertEqual(httplib.FORBIDDEN, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.FORBIDDEN)

  def testDispatch_AllowKnownComputer(self):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = True
    sync.SantaRequestHandler.SHOULD_PARSE_JSON = False

    host_models.SantaHost(key=ndb.Key('Host', 'my-uuid')).put()

    self.testapp.post('/my-uuid', {})

  def testDispatch_ParseJson_NoCompression(self):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False
    sync.SantaRequestHandler.SHOULD_PARSE_JSON = True

    self.testapp.post_json('/my-uuid', {'some-json-key': 'some-json-value'})

  def testDispatch_ParseJson_ZlibCompression(self):
    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False
    sync.SantaRequestHandler.SHOULD_PARSE_JSON = True

    json_data = json.dumps({'some-json-key': 'some-json-value'})
    compressed_data = zlib.compress(json_data)

    self.testapp.post(
        '/my-uuid', compressed_data, headers={'Content-Encoding': 'zlib'})

  def testDispatch_ParseJson_BadJson(self):

    sync.SantaRequestHandler.REQUIRE_HOST_OBJECT = False
    sync.SantaRequestHandler.SHOULD_PARSE_JSON = True

    response = self.testapp.post(
        '/my-uuid', 'this{is}bad{json}', status=httplib.BAD_REQUEST)

    self.assertEqual(httplib.BAD_REQUEST, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.BAD_REQUEST)


class CopyLocalRulesTest(SantaApiTestCase):

  def testSuccess(self):

    blockable_count = 10

    # Create a user and some corresponding SantaHosts.
    user = test_utils.CreateUser()
    now = datetime.datetime.utcnow()
    host_1 = test_utils.CreateSantaHost(
        id='1111', primary_user=user.nickname, last_postflight_dt=now)
    host_2 = test_utils.CreateSantaHost(
        id='2222', primary_user=user.nickname, last_postflight_dt=now)
    host_3 = test_utils.CreateSantaHost(
        id='3333', primary_user=user.nickname, last_postflight_dt=now)

    # Create some SantaBlockables, each with a SantaRule for host_1 and host_2.
    blockables = test_utils.CreateSantaBlockables(blockable_count)
    for blockable in blockables:
      test_utils.CreateSantaRule(
          blockable.key, host_id=host_1.key.id(), user_key=user.key,
          in_effect=True)
      test_utils.CreateSantaRule(
          blockable.key, host_id=host_2.key.id(), user_key=user.key,
          in_effect=True)

    # Verify all the rule counts.
    self.assertEntityCount(rule_models.SantaRule, blockable_count * 2)
    host_1_rules = rule_models.SantaRule.query(
        rule_models.SantaRule.host_id == host_1.key.id()).fetch()
    self.assertLen(host_1_rules, blockable_count)
    host_2_rules = rule_models.SantaRule.query(
        rule_models.SantaRule.host_id == host_2.key.id()).fetch()
    self.assertLen(host_2_rules, blockable_count)
    host_3_rules = rule_models.SantaRule.query(
        rule_models.SantaRule.host_id == host_3.key.id()).fetch()
    self.assertLen(host_3_rules, 0)

    self.assertNoBigQueryInsertions()

    sync._CopyLocalRules(user.key, host_3.key.id()).get_result()

    # Verify all the rule counts again.
    self.assertEntityCount(rule_models.SantaRule, blockable_count * 3)
    host_1_rules = rule_models.SantaRule.query(
        rule_models.SantaRule.host_id == host_1.key.id()).fetch()
    self.assertLen(host_1_rules, blockable_count)
    host_2_rules = rule_models.SantaRule.query(
        rule_models.SantaRule.host_id == host_2.key.id()).fetch()
    self.assertLen(host_2_rules, blockable_count)
    host_3_rules = rule_models.SantaRule.query(
        rule_models.SantaRule.host_id == host_3.key.id()).fetch()
    self.assertLen(host_3_rules, blockable_count)

    self.assertBigQueryInsertions([TABLE.RULE] * blockable_count)


class PreflightHandlerTest(SantaApiTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/(.*)', sync.PreflightHandler)])
    super(PreflightHandlerTest, self).setUp(wsgi_app=app)
    self.Patch(
        sync.PreflightHandler,
        'RequestCounter',
        new_callable=mock.PropertyMock,
        return_value=self.mock_request_metric)

    self.request_json = {
        PREFLIGHT.SERIAL_NUM: 'serial',
        PREFLIGHT.HOSTNAME: 'vogon',
        PREFLIGHT.PRIMARY_USER: 'user',
        PREFLIGHT.SANTA_VERSION: '1.0.0',
        PREFLIGHT.OS_VERSION: '10.9.3',
        PREFLIGHT.OS_BUILD: '13D65',
        PREFLIGHT.CLIENT_MODE: CLIENT_MODE.LOCKDOWN}


  def testFirstCheckin_Success(self):

    self.PatchSetting('SANTA_EVENT_BATCH_SIZE', 42)

    other_host = test_utils.CreateSantaHost(
        primary_user='user', last_postflight_dt=datetime.datetime.utcnow())
    blockable = test_utils.CreateSantaBlockable()
    user_key = ndb.Key(
        user_models.User, user_utils.UsernameToEmail('user'))
    test_utils.CreateSantaRule(
        blockable.key, user_key=user_key, host_id=other_host.key.id(),
        in_effect=True)

    response = self.testapp.post_json('/my-uuid', self.request_json)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertEntityCount(host_models.SantaHost, 2)
    self.assertBigQueryInsertions([TABLE.USER, TABLE.HOST, TABLE.RULE])

    self.assertEqual(
        CLIENT_MODE.LOCKDOWN,
        response.json[PREFLIGHT.CLIENT_MODE])
    self.assertEqual(42, response.json[PREFLIGHT.BATCH_SIZE])
    self.assertTrue(response.json[PREFLIGHT.CLEAN_SYNC])

    new_host = host_models.SantaHost.get_by_id('my-uuid')
    self.assertEqual('serial', new_host.serial_num)
    self.assertEqual('vogon', new_host.hostname)
    self.assertFalse(new_host.transitive_whitelisting_enabled)

    # Ensure the new rule was created.
    self.assertEqual(
        2, rule_models.SantaRule.query(ancestor=blockable.key).count())

  def testFirstCheckin_OtherHostNotSynced(self):

    unsynced_host = test_utils.CreateSantaHost(primary_user='user')
    blockable = test_utils.CreateSantaBlockable()
    user_key = ndb.Key(
        user_models.User, user_utils.UsernameToEmail('user'))
    test_utils.CreateSantaRule(
        blockable.key, user_key=user_key, host_id=unsynced_host.key.id(),
        in_effect=True)

    response = self.testapp.post_json('/my-uuid', self.request_json)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertEntityCount(host_models.SantaHost, 2)
    self.assertBigQueryInsertions([TABLE.USER, TABLE.HOST])

    # Ensure the existing rule wasn't copied from the unsynced host.
    self.assertEntityCount(rule_models.SantaRule, 1)

  def testFirstCheckin_NoPreexistingHost(self):

    response = self.testapp.post_json('/my-uuid', self.request_json)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertEntityCount(host_models.SantaHost, 1)
    self.assertBigQueryInsertions([TABLE.USER, TABLE.HOST])

    # Ensure no rules were copied because none existed.
    self.assertEntityCount(rule_models.SantaRule, 0)

  def testFirstCheckin_SantaHostCreation(self):

    self.assertEqual(0, host_models.SantaHost.query().count())

    # First checkin should create the SantaHost.
    response = self.testapp.post_json('/my-uuid', self.request_json)
    self.assertEqual(1, host_models.SantaHost.query().count())
    self.assertBigQueryInsertions([TABLE.USER, TABLE.HOST])
    self.assertEqual(httplib.OK, response.status_int)

    # Next checkin should not.
    response = self.testapp.post_json('/my-uuid', self.request_json)
    self.assertEqual(1, host_models.SantaHost.query().count())
    self.assertNoBigQueryInsertions()
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK, httplib.OK)

  def testFirstCheckin_UserCreation(self):

    before_count = user_models.User.query().count()

    # First checkin should create the User.
    response = self.testapp.post_json('/my-uuid', self.request_json)
    self.assertEqual(1, user_models.User.query().count() - before_count)
    self.assertBigQueryInsertions([TABLE.USER, TABLE.HOST])
    self.assertEqual(httplib.OK, response.status_int)

    # Next checkin should not.
    response = self.testapp.post_json('/my-uuid', self.request_json)
    self.assertEqual(1, user_models.User.query().count() - before_count)
    self.assertNoBigQueryInsertions()
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK, httplib.OK)

  def testCheckin_Success(self):
    host_models.SantaHost(
        key=ndb.Key('Host', 'my-uuid'),
        client_mode=constants.CLIENT_MODE.LOCKDOWN,
        directory_whitelist_regex='^/[Bb]uild/.*',
        transitive_whitelisting_enabled=True,
        primary_user='user').put()

    response = self.testapp.post_json('/my-uuid', self.request_json)

    self.assertEqual(
        constants.CLIENT_MODE.LOCKDOWN,
        response.json[PREFLIGHT.CLIENT_MODE])
    self.assertEqual(
        '^/[Bb]uild/.*',
        response.json[PREFLIGHT.WHITELIST_REGEX])
    self.assertTrue(
        response.json[PREFLIGHT.TRANSITIVE_WHITELISTING_ENABLED])
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    host = host_models.SantaHost.get_by_id('my-uuid')
    self.assertEqual('serial', host.serial_num)

    self.assertBigQueryInsertion(TABLE.USER)

  def testCheckin_DefaultDirectoryRegex(self):
    host_models.SantaHost(id='my-uuid', primary_user='user').put()
    self.PatchSetting('SANTA_DIRECTORY_WHITELIST_REGEX', '^/[Bb]uild/.*')

    response = self.testapp.post_json('/my-uuid', self.request_json)

    self.assertEqual(
        '^/[Bb]uild/.*',
        response.json[PREFLIGHT.WHITELIST_REGEX])
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertBigQueryInsertion(TABLE.USER)

  def testCheckin_RequestCleanSync(self):
    host_models.SantaHost(
        key=ndb.Key('Host', 'my-uuid'),
        rule_sync_dt=datetime.datetime.now(),
        primary_user='user').put()

    self.request_json[PREFLIGHT.REQUEST_CLEAN_SYNC] = True

    response = self.testapp.post_json('/my-uuid', self.request_json)

    host = host_models.SantaHost.get_by_id('my-uuid')
    self.assertIsNone(host.rule_sync_dt)
    self.assertTrue(response.json[PREFLIGHT.CLEAN_SYNC])
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertBigQueryInsertion(TABLE.USER)

  def testCheckin_ModeMismatch(self):

    user = test_utils.CreateUser()
    host_models.SantaHost(
        key=ndb.Key('Host', 'my-uuid'),
        client_mode=CLIENT_MODE.LOCKDOWN,
        primary_user=user.nickname).put()
    request_json = {
        PREFLIGHT.SERIAL_NUM: 'serial',
        PREFLIGHT.HOSTNAME: 'vogon',
        PREFLIGHT.PRIMARY_USER: user.nickname,
        PREFLIGHT.SANTA_VERSION: '1.0.0',
        PREFLIGHT.OS_VERSION: '10.9.3',
        PREFLIGHT.OS_BUILD: '13D65',
        PREFLIGHT.CLIENT_MODE: CLIENT_MODE.MONITOR}

    response = self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)
    self.assertBigQueryInsertion(TABLE.HOST)

  def testCheckin_ClientModeUnsupported(self):
    user = test_utils.CreateUser()
    host_models.SantaHost(
        key=ndb.Key('Host', 'my-uuid'),
        client_mode=CLIENT_MODE.LOCKDOWN,
        primary_user=user.nickname).put()
    request_json = {
        PREFLIGHT.SERIAL_NUM: 'serial',
        PREFLIGHT.HOSTNAME: 'vogon',
        PREFLIGHT.PRIMARY_USER: user.nickname,
        PREFLIGHT.SANTA_VERSION: '1.0.0',
        PREFLIGHT.OS_VERSION: '10.9.3',
        PREFLIGHT.OS_BUILD: '13D65',
        PREFLIGHT.CLIENT_MODE: 'pineapple'}

    response = self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertBigQueryInsertion(TABLE.HOST, reset_mock=False)
    calls = self.GetBigQueryCalls()
    self.assertEqual(constants.HOST_MODE.UNKNOWN, calls[0][1].get('mode'))

  def testCheckin_ClientModeMissing(self):
    user = test_utils.CreateUser()
    host_models.SantaHost(
        key=ndb.Key('Host', 'my-uuid'),
        client_mode=CLIENT_MODE.LOCKDOWN,
        primary_user=user.nickname).put()
    request_json = {
        PREFLIGHT.SERIAL_NUM: 'serial',
        PREFLIGHT.HOSTNAME: 'vogon',
        PREFLIGHT.PRIMARY_USER: user.nickname,
        PREFLIGHT.SANTA_VERSION: '1.0.0',
        PREFLIGHT.OS_VERSION: '10.9.3',
        PREFLIGHT.OS_BUILD: '13D65'}

    response = self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)
    self.assertBigQueryInsertion(TABLE.HOST, reset_mock=False)
    calls = self.GetBigQueryCalls()
    self.assertEqual(constants.HOST_MODE.UNKNOWN, calls[0][1].get('mode'))

  def testCheckin_PrimaryUserChange(self):

    user1 = test_utils.CreateUser()
    user2 = test_utils.CreateUser()
    host = test_utils.CreateSantaHost(
        primary_user=user1.nickname, client_mode=CLIENT_MODE.LOCKDOWN)

    request_json = {
        PREFLIGHT.SERIAL_NUM: 'serial',
        PREFLIGHT.HOSTNAME: 'vogon',
        PREFLIGHT.PRIMARY_USER: user2.nickname,
        PREFLIGHT.SANTA_VERSION: '1.0.0',
        PREFLIGHT.OS_VERSION: '10.9.3',
        PREFLIGHT.OS_BUILD: '13D65',
        PREFLIGHT.CLIENT_MODE: CLIENT_MODE.LOCKDOWN}

    response = self.testapp.post_json('/%s' % host.key.id(), request_json)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)
    self.assertBigQueryInsertion(TABLE.HOST, reset_mock=False)
    calls = self.GetBigQueryCalls()
    self.assertEqual(
        constants.HOST_ACTION.USERS_CHANGE, calls[0][1].get('action'))
    self.assertEqual([user2.nickname], calls[0][1].get('users'))


class EventUploadHandlerTest(SantaApiTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/(.*)', sync.EventUploadHandler)])
    super(EventUploadHandlerTest, self).setUp(wsgi_app=app)
    self.Patch(
        sync.EventUploadHandler,
        'RequestCounter',
        new_callable=mock.PropertyMock,
        return_value=self.mock_request_metric)

    now = datetime.datetime.utcnow()
    before = now - datetime.timedelta(seconds=10)
    self.host = host_models.SantaHost(
        id='my-uuid',
        primary_user='user',
        last_preflight_dt=before,
        rule_sync_dt=now,
        last_postflight_dt=now)
    self.host.put()

  def _CreateEvent(self, file_hash):
    return {
        EVENT_UPLOAD.FILE_SHA256: file_hash,
        EVENT_UPLOAD.FILE_NAME: 'fname',
        EVENT_UPLOAD.FILE_PATH: '/usr/bin',
        EVENT_UPLOAD.EXECUTION_TIME: 1404162158,
        EVENT_UPLOAD.EXECUTING_USER: 'user',
        EVENT_UPLOAD.LOGGED_IN_USERS: ['user'],
        EVENT_UPLOAD.CURRENT_SESSIONS: ['user@console'],
        EVENT_UPLOAD.DECISION: 'BLOCK_UNKNOWN',
        EVENT_UPLOAD.PID: 123,
        EVENT_UPLOAD.PPID: 321,
        EVENT_UPLOAD.SIGNING_CHAIN: [],
    }

  def _CreateBundleEvent(
      self, bundle_id, binary_id, bundle_root='/Foo.app',
      rel_path='Contents/MacOS', file_name='foo',
      main_executable_rel_path=None):
    if main_executable_rel_path is None:
      main_executable_rel_path = '/'.join((rel_path, file_name))
    event = self._CreateEvent(binary_id)
    event.update({
        EVENT_UPLOAD.FILE_BUNDLE_HASH: bundle_id,
        EVENT_UPLOAD.FILE_BUNDLE_PATH: bundle_root,
        EVENT_UPLOAD.FILE_PATH: '/'.join((bundle_root, rel_path)),
        EVENT_UPLOAD.FILE_BUNDLE_EXECUTABLE_REL_PATH:
            main_executable_rel_path,
        EVENT_UPLOAD.FILE_NAME: file_name,
        EVENT_UPLOAD.FILE_BUNDLE_BINARY_COUNT: 1,
        EVENT_UPLOAD.DECISION:
            constants.EVENT_TYPE.BUNDLE_BINARY,
    })
    return event

  def _CreateSigningChain(self, cert_hash):
    return [{
        EVENT_UPLOAD.SHA256: 'cert-sha256',
        EVENT_UPLOAD.ORG: 'Acme Corp.',
        EVENT_UPLOAD.OU: 'Acme Evil Web Systems',
        EVENT_UPLOAD.CN: 'Acme Evil App 1.0',
        EVENT_UPLOAD.VALID_FROM: 564810420,
        EVENT_UPLOAD.VALID_UNTIL: 1404218863
    }, {
        EVENT_UPLOAD.SHA256: 'other-' + cert_hash,
        EVENT_UPLOAD.ORG: 'Acme Corp.',
        EVENT_UPLOAD.OU: 'Acme Evil Systems',
        EVENT_UPLOAD.VALID_FROM: 564810420,
        EVENT_UPLOAD.VALID_UNTIL: 1404218863
    }, {
        EVENT_UPLOAD.SHA256: 'other-other-' + cert_hash,
        EVENT_UPLOAD.ORG: 'Apple',
        EVENT_UPLOAD.OU: 'Developer whatsits',
        EVENT_UPLOAD.VALID_FROM: 564810420,
        EVENT_UPLOAD.VALID_UNTIL: 1404218863
    }]

  def testFirstCheckin_IgnoreEvents(self):
    # Simulate first checkin by removing rule rule_sync_dt.
    self.host.last_postflight_dt = None
    self.host.put()

    event = self._CreateEvent('the-sha256')
    request_json = {EVENT_UPLOAD.EVENTS: [event]}

    response = self.testapp.post_json('/my-uuid', request_json)
    self.assertEqual(httplib.OK, response.status_int)

    self.assertLen(event_models.SantaEvent.query().fetch(), 0)

    self.assertNoBigQueryInsertions()

  def testSingleEvent_ExistingBinary_NoCertificate(self):
    event = self._CreateEvent('the-sha256')
    request_json = {EVENT_UPLOAD.EVENTS: [event]}

    # Upload event once to get blockable created
    response = self.testapp.post_json('/my-uuid', request_json)
    self.assertEqual(httplib.OK, response.status_int)

    # Now upload a second time and capture response
    response = self.testapp.post_json('/my-uuid', request_json)
    self.assertEqual(httplib.OK, response.status_int)

    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK, httplib.OK)

    self.assertBigQueryInsertions([TABLE.BINARY] + [TABLE.EXECUTION] * 2)

  def testSingleEvent_NewBinary_NoCertificate(self):
    event = self._CreateEvent('the-sha256')
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    response = self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(1, event_models.SantaEvent.query().count())

    parent = ndb.Key(user_models.User, user_utils.UsernameToEmail('user'),
                     host_models.SantaHost, 'my-uuid',
                     santa_models.SantaBlockable, 'the-sha256')
    event = event_models.SantaEvent.query(ancestor=parent).get()
    self.assertEqual('my-uuid', event.host_id)
    self.assertEqual('fname', event.file_name)
    self.assertEqual('user', event.executing_user)
    self.assertIsNone(event.bundle_key)
    self.assertIsNone(event.cert_key)
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertBigQueryInsertions([TABLE.BINARY, TABLE.EXECUTION])

  def testSingleEvent_NewBinary_NewCertificate(self):
    event = self._CreateEvent('the-sha256')
    chain = self._CreateSigningChain('cert-sha256')

    event[EVENT_UPLOAD.SIGNING_CHAIN] = chain
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    response = self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(1, event_models.SantaEvent.query().count())

    parent = ndb.Key(user_models.User, user_utils.UsernameToEmail('user'),
                     host_models.SantaHost, 'my-uuid',
                     santa_models.SantaBlockable, 'the-sha256')
    event = event_models.SantaEvent.query(ancestor=parent).get()
    self.assertEqual('my-uuid', event.host_id)
    self.assertEqual('fname', event.file_name)
    self.assertEqual('user', event.executing_user)

    self.assertEntityCount(santa_models.SantaCertificate, 3)
    cert = santa_models.SantaCertificate.get_by_id('cert-sha256')
    self.assertIsNotNone(cert)
    self.assertEqual('Acme Evil App 1.0', cert.common_name)
    self.assertEqual('Acme Corp.', cert.organization)
    self.assertEqual(event.cert_key, cert.key)
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertBigQueryInsertions(
        [TABLE.BINARY, TABLE.EXECUTION] + [TABLE.CERTIFICATE] * 3)

  def testSingleEvent_NewBinary_ExistingCertificate(self):
    event = self._CreateEvent('the-sha256')
    chain = self._CreateSigningChain('cert-sha256')

    event[EVENT_UPLOAD.SIGNING_CHAIN] = chain
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    response = self.testapp.post_json('/my-uuid', request_json)

    cert = santa_models.SantaCertificate.get_by_id('cert-sha256')
    self.assertIsNotNone(cert)
    created = cert.recorded_dt
    self.assertEqual('Acme Corp.', cert.organization)
    self.assertEqual(httplib.OK, response.status_int)

    # Upload the same Event again and ensure the Cert wasn't re-created.
    response = self.testapp.post_json('/my-uuid', request_json)

    cert = santa_models.SantaCertificate.get_by_id('cert-sha256')
    self.assertIsNotNone(cert)
    self.assertEqual(created, cert.recorded_dt)
    self.assertEqual(httplib.OK, response.status_int)

    self.assertBigQueryInsertions(
        [TABLE.BINARY] + [TABLE.EXECUTION] * 2 + [TABLE.CERTIFICATE] * 3)

  def testSingleEvent_NewBinary_BundlePath(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)

    event = self._CreateEvent(blockable.key.id())
    event.update({
        EVENT_UPLOAD.FILE_BUNDLE_HASH: bundle.key.id(),
        EVENT_UPLOAD.FILE_BUNDLE_PATH: '/Foo.app',
        EVENT_UPLOAD.FILE_PATH: '/Foo.app/Contents/MacOS/bar',
        EVENT_UPLOAD.FILE_NAME: 'baz',
        EVENT_UPLOAD.DECISION: constants.EVENT_TYPE.BUNDLE_BINARY
    })
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(1, package_models.SantaBundleBinary.query().count())

    member = package_models.SantaBundleBinary.query().get()
    self.assertEqual('Contents/MacOS/bar', member.rel_path)
    self.assertEqual('Contents/MacOS/bar/baz', member.full_path)

    self.assertBigQueryInsertion(TABLE.BUNDLE_BINARY)

  def testSingleEvent_NewBinary_BadBundlePath(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)

    # Create an event where the bundle path isn't a prefix of the bundle path.
    event = self._CreateBundleEvent(bundle.key.id(), blockable.key.id())
    event.update({
        EVENT_UPLOAD.FILE_BUNDLE_PATH: '/Foo.app',
        EVENT_UPLOAD.FILE_PATH: '/Baz.app/Contents/MacOS/bar',
        EVENT_UPLOAD.FILE_NAME: 'baz',
    })
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    # Bundle binary should have been skipped.
    self.assertEqual(0, package_models.SantaBundleBinary.query().count())

    # No Tasks should be triggered.
    self.assertNoBigQueryInsertions()

  def testSingleEvent_NewBinary_NoBundleHash(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)

    event = self._CreateBundleEvent(bundle.key.id(), blockable.key.id())
    # Omit the BUNDLE_HASH argument to ensure no member is created.
    del event[EVENT_UPLOAD.FILE_BUNDLE_HASH]

    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(0, package_models.SantaBundleBinary.query().count())

    # No Tasks should be triggered.
    self.assertNoBigQueryInsertions()

  def testSingleEvent_NewBinary_WithCert(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)

    event = self._CreateBundleEvent(bundle.key.id(), blockable.key.id())
    chain = self._CreateSigningChain('cert-sha256')
    event.update({
        EVENT_UPLOAD.SIGNING_CHAIN: chain,
        EVENT_UPLOAD.FILE_BUNDLE_BINARY_COUNT: 1,
    })

    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEntityCount(santa_models.SantaCertificate, 3)
    self.assertEntityCount(package_models.SantaBundleBinary, 1)

    self.assertFalse(bundle.key.get().has_unsigned_contents)

    bundle_binary = package_models.SantaBundleBinary.query().get()
    self.assertEqual('Contents/MacOS', bundle_binary.rel_path)
    self.assertEqual('Contents/MacOS/foo', bundle_binary.full_path)
    self.assertEqual('cert-sha256', bundle_binary.cert_key.id())

    self.assertBigQueryInsertions(
        [TABLE.BUNDLE_BINARY] + [TABLE.CERTIFICATE] * 3)

  def testSingleEvent_NewBinary_NewBundle(self):
    event = self._CreateEvent('the-sha256')
    event.update({
        EVENT_UPLOAD.FILE_BUNDLE_HASH: 'foo',
        EVENT_UPLOAD.FILE_BUNDLE_ID: 'foo',
        EVENT_UPLOAD.FILE_BUNDLE_VERSION: 'bar',
        EVENT_UPLOAD.FILE_BUNDLE_NAME: 'foobar',
        EVENT_UPLOAD.FILE_BUNDLE_PATH: '/a/b/c',
    })
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    response = self.testapp.post_json('/my-uuid', request_json)
    output = response.json  # pylint: disable=unused-variable

    self.assertEqual(1, event_models.SantaEvent.query().count())

    # Validate the created event.
    parent = ndb.Key(user_models.User, user_utils.UsernameToEmail('user'),
                     host_models.SantaHost, 'my-uuid',
                     santa_models.SantaBlockable, 'the-sha256')
    event = event_models.SantaEvent.query(ancestor=parent).get()
    self.assertEqual('my-uuid', event.host_id)
    self.assertEqual('foo', event.bundle_key.id())
    self.assertEqual(
        ndb.Key(santa_models.SantaBlockable, 'the-sha256'), event.blockable_key)
    # Bundle SHOULD have been created.
    self.assertIsNotNone(event.bundle_key.get())
    # Binary SHOULD have been created.
    self.assertIsNotNone(event.blockable_key.get())
    # SantaBundleBinary SHOULD NOT have been created.
    member_key = ndb.Key(
        package_models.SantaBundle, 'foo', package_models.SantaBundleBinary,
        'the-sha256')
    self.assertIsNone(member_key.get())

    # Validate the created bundle.
    self.assertEqual(
        ndb.Key(package_models.SantaBundle, 'foo'), event.bundle_key)
    bundle = event.bundle_key.get()
    self.assertEqual('foo', bundle.bundle_id)
    self.assertEqual('bar', bundle.version)
    self.assertEqual('foobar', bundle.name)
    self.assertFalse(bundle.has_been_uploaded)

    # Ensure response provides the bundle hash that requires upload.
    self.assertSameElements(
        ['foo'],
        output[EVENT_UPLOAD.EVENT_UPLOAD_BUNDLE_BINARIES])

    self.assertBigQueryInsertions([TABLE.BINARY, TABLE.BUNDLE, TABLE.EXECUTION])

  def testSingleEvent_ExistingBinary_ExistingBundle(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None, binary_count=2)
    self.assertFalse(bundle.has_been_uploaded)

    event = self._CreateBundleEvent(bundle.key.id(), blockable.key.id())

    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    response = self.testapp.post_json('/my-uuid', request_json)
    output = response.json  # pylint: disable=unused-variable

    self.assertEntityCount(event_models.SantaEvent, 0)
    self.assertEntityCount(package_models.SantaBundleBinary, 1)

    # Ensure the bundle hasn't been marked as uploaded.
    bundle = bundle.key.get()
    self.assertFalse(bundle.has_been_uploaded)
    self.assertTrue(bundle.has_unsigned_contents)

    # Ensure the response requests the bundle be uploaded even though it was
    # previously known to Upvote.
    self.assertSameElements(
        [bundle.key.id()],
        output[EVENT_UPLOAD.EVENT_UPLOAD_BUNDLE_BINARIES])

    self.assertBigQueryInsertion(TABLE.BUNDLE_BINARY)

  def testSingleEvent_NewBinary_ExistingUploadedBundle(self):
    # Create a bundle with a single binary and mark it uploaded.
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(bundle_binaries=[blockable])
    self.assertTrue(bundle.has_been_uploaded)

    event = self._CreateBundleEvent(bundle.key.id(), '3vilHash')

    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    # Ensure the new blockable doesn't get added to the bundle.
    self.assertEntityCount(event_models.SantaEvent, 0)
    self.assertEntityCount(
        package_models.SantaBundleBinary, 1, ancestor=bundle.key)

    self.assertBigQueryInsertion(TABLE.BINARY)

  def testMultipleEvents_ExistingBlockable(self):
    event1 = self._CreateEvent('the-sha256')
    event2 = event1.copy()
    later_timestamp = event1[EVENT_UPLOAD.EXECUTION_TIME] + 1
    event2[EVENT_UPLOAD.EXECUTION_TIME] = later_timestamp
    event3 = event1.copy()
    latest_timestamp = event2[EVENT_UPLOAD.EXECUTION_TIME] + 1
    event3[EVENT_UPLOAD.EXECUTION_TIME] = latest_timestamp

    # Request the first event.
    request_json = {EVENT_UPLOAD.EVENTS: [event1]}
    response = self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(1, event_models.SantaEvent.query().count())

    # Request the second event.
    request_json = {EVENT_UPLOAD.EVENTS: [event2]}
    response = self.testapp.post_json('/my-uuid', request_json)

    # We expect 1 extra old-style Event.
    self.assertEqual(1, event_models.SantaEvent.query().count())

    # Request the final event.
    request_json = {EVENT_UPLOAD.EVENTS: [event3]}
    response = self.testapp.post_json('/my-uuid', request_json)
    self.assertFalse(response.json)
    self.assertEqual(httplib.OK, response.status_int)

    self.assertEqual(1, event_models.SantaEvent.query().count())

    parent = ndb.Key(user_models.User, user_utils.UsernameToEmail('user'),
                     host_models.SantaHost, 'my-uuid',
                     santa_models.SantaBlockable, 'the-sha256')
    event = event_models.SantaEvent.query(ancestor=parent).get()
    expected_time = datetime.datetime.utcfromtimestamp(latest_timestamp)
    self.assertEqual(expected_time, event.last_blocked_dt)

    self.assertBigQueryInsertions([TABLE.BINARY] + [TABLE.EXECUTION] * 3)

  def testMultipleEvents_DifferentUserTxns(self):
    self.PatchSetting(
        'EVENT_CREATION', constants.EVENT_CREATION.EXECUTING_USER)
    event1 = self._CreateEvent('the-sha256')
    event2 = event1.copy()
    event2[EVENT_UPLOAD.EXECUTING_USER] = 'anotheruser'
    event2[EVENT_UPLOAD.LOGGED_IN_USERS] = ['anotheruser']

    with mock.patch.object(sync.ndb, 'put_multi_async') as put_multi_mock:
      # It ain't pretty but it works: Wrap put_multi_async such that it behaves
      # like a synchronous version and we have the ability to track its calls.
      def fake_put_multi_async(seq):
        result = ndb.put_multi(seq)
        # Return an ndb.Future that is guaranteed to be done.
        return datastore_utils.GetNoOpFuture(result)
      put_multi_mock.side_effect = fake_put_multi_async

      request_json = {EVENT_UPLOAD.EVENTS: [event1, event2]}
      self.testapp.post_json('/my-uuid', request_json)

      # 1 from creating Certificate entities + 2 from events
      self.assertEqual(3, put_multi_mock.call_count)

    self.assertBigQueryInsertions([TABLE.BINARY] + [TABLE.EXECUTION] * 2)

  def testMultipleEvents_UpdateSequential(self):
    self.PatchSetting(
        'EVENT_CREATION', constants.EVENT_CREATION.EXECUTING_USER)
    event1 = self._CreateEvent('the-sha256')
    event2 = event1.copy()
    event2[EVENT_UPLOAD.EXECUTING_USER] = 'other'
    event2[EVENT_UPLOAD.LOGGED_IN_USERS] = ['other']

    request_json = {EVENT_UPLOAD.EVENTS: [event1, event2]}
    self.testapp.post_json('/my-uuid', request_json)

    event3 = event1.copy()
    event4 = event2.copy()

    request_json = {EVENT_UPLOAD.EVENTS: [event3, event4]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(2, event_models.SantaEvent.query().count())

    parent = ndb.Key(user_models.User, user_utils.UsernameToEmail('user'),
                     host_models.SantaHost, 'my-uuid',
                     santa_models.SantaBlockable, 'the-sha256')
    event = event_models.SantaEvent.query(ancestor=parent).get()
    self.assertEqual(2, event.count)
    email = user_utils.UsernameToEmail('other')
    parent = ndb.Key(user_models.User, email,
                     host_models.SantaHost, 'my-uuid',
                     santa_models.SantaBlockable, 'the-sha256')
    event = event_models.SantaEvent.query(ancestor=parent).get()
    self.assertEqual(2, event.count)

    self.assertBigQueryInsertions([TABLE.BINARY] + [TABLE.EXECUTION] * 4)

  def testMultipleEvents_Dedupe(self):
    event1 = self._CreateEvent('the-sha256')
    event2 = event1.copy()
    later_timestamp = event1[EVENT_UPLOAD.EXECUTION_TIME] + 1
    event2[EVENT_UPLOAD.EXECUTION_TIME] = later_timestamp
    request_json = {EVENT_UPLOAD.EVENTS: [event1, event2]}
    response = self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(1, event_models.SantaEvent.query().count())

    parent = ndb.Key(user_models.User, user_utils.UsernameToEmail('user'),
                     host_models.SantaHost, 'my-uuid',
                     santa_models.SantaBlockable, 'the-sha256')
    event = event_models.SantaEvent.query(ancestor=parent).get()
    self.assertEqual('my-uuid', event.host_id)
    self.assertEqual('fname', event.file_name)
    self.assertEqual('user', event.executing_user)
    expected_time = datetime.datetime.utcfromtimestamp(later_timestamp)
    self.assertEqual(expected_time, event.last_blocked_dt)
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

    self.assertBigQueryInsertions([TABLE.BINARY] + [TABLE.EXECUTION] * 2)

  def testMultipleEvents_RetriedTxn(self):
    user = test_utils.CreateUser()
    blockable = test_utils.CreateSantaBlockable()
    host = test_utils.CreateSantaHost()

    event_key = ndb.Key(user_models.User, user.key.id(),
                        host_models.SantaHost, host.key.id(),
                        santa_models.SantaBlockable, blockable.key.id(),
                        event_models.SantaEvent, '1')

    # This Event will already exist in the datastore but calling
    # _DedupeExistingAndPut on it will simulate an identical Event being synced.
    event = test_utils.CreateSantaEvent(
        key=event_key, blockable=blockable, host_id=host.key.id(),
        executing_user=user.nickname, count=10)

    # Simulate a retried transaction.
    # We use an exception to exit before committing the put_multi because,
    # according to the docs: "There is no mechanism to force a retry."
    # See https://cloud.google.com/appengine/docs/python/ndb/transactions
    with mock.patch.object(sync.ndb, 'put_multi_async', side_effect=Exception):
      with self.assertRaises(Exception):
        sync.EventUploadHandler()._DedupeExistingAndPut([event]).get_result()

    # And now retry...
    sync.EventUploadHandler()._DedupeExistingAndPut([event]).get_result()

    # Test that no additional event counts were added as a result of the retry.
    put_event = event_key.get()
    self.assertEqual(20, put_event.count)

    self.assertNoBigQueryInsertions()

  def testBundleUpload_SingleBinary(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None, binary_count=2)

    event = self._CreateEvent(blockable.key.id())
    event.update({
        EVENT_UPLOAD.FILE_BUNDLE_HASH: bundle.key.id(),
        EVENT_UPLOAD.FILE_BUNDLE_PATH: '/Foo.app',
        EVENT_UPLOAD.FILE_PATH: '/Foo.app/Content/MacOS',
        EVENT_UPLOAD.FILE_NAME: 'foo',
        EVENT_UPLOAD.DECISION: constants.EVENT_TYPE.BUNDLE_BINARY
    })
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(0, event_models.SantaEvent.query().count())
    self.assertEqual(
        1, package_models.SantaBundleBinary.query(ancestor=bundle.key).count())
    self.assertFalse(bundle.key.get().has_been_uploaded)

    self.assertBigQueryInsertion(TABLE.BUNDLE_BINARY)

  def testBundleUpload_MultipleBinaries(self):
    num_binaries = 20
    bundle = test_utils.CreateSantaBundle(
        uploaded_dt=None, binary_count=num_binaries)

    common_kwargs = {
        'bundle_root': '/Foo.app',
        'rel_path': 'Contents/MacOS',
        'main_executable_rel_path': 'Contents/MacOS/foo'}
    events = [self._CreateBundleEvent(
        bundle.key.id(), 'foo', file_name='foo', **common_kwargs)]
    for i in xrange(num_binaries - 1):
      events.append(self._CreateBundleEvent(
          bundle.key.id(), 'bar%s' % i, file_name='bar%s' % i, **common_kwargs))

    request_json = {EVENT_UPLOAD.EVENTS: events}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(0, event_models.SantaEvent.query().count())

    # Should have created the blockables.
    self.assertIsNotNone(santa_models.SantaBlockable.get_by_id('foo'))
    for i in xrange(num_binaries - 1):
      self.assertIsNotNone(santa_models.SantaBlockable.get_by_id('bar%s' % i))
    self.assertEqual(
        num_binaries,
        package_models.SantaBundleBinary.query(ancestor=bundle.key).count())

    # Should have marked the bundle as uploaded
    self.assertTrue(bundle.key.get().has_been_uploaded)

    self.assertBigQueryInsertions(
        [TABLE.BINARY, TABLE.BUNDLE_BINARY] * num_binaries)

  def testBundleUpload_MultipleBundles(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)

    other_blockable = test_utils.CreateSantaBlockable()
    other_bundle = test_utils.CreateSantaBundle(uploaded_dt=None)

    event = self._CreateBundleEvent(
        bundle.key.id(),
        blockable.key.id(),
        bundle_root='/Foo.app',
        rel_path='Contents/MacOS',
        main_executable_rel_path='Contents/MacOS/foo',
        file_name='foo',)
    other_event = self._CreateBundleEvent(
        other_bundle.key.id(),
        other_blockable.key.id(),
        bundle_root='/Bar.app',
        rel_path='Contents/MacOS',
        main_executable_rel_path='Contents/MacOS/bar',
        file_name='bar',)

    request_json = {EVENT_UPLOAD.EVENTS: [event, other_event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(0, event_models.SantaEvent.query().count())

    self.assertEntityCount(
        package_models.SantaBundleBinary, 1, ancestor=bundle.key)
    self.assertEntityCount(
        package_models.SantaBundleBinary, 1, ancestor=other_bundle.key)
    self.assertTrue(bundle.key.get().has_been_uploaded)
    self.assertTrue(other_bundle.key.get().has_been_uploaded)

    self.assertBigQueryInsertions([TABLE.BUNDLE_BINARY] * 2)

  def testBundleUpload_PreviouslyUnknownBundle(self):
    event_hash = test_utils.RandomSHA256()
    bundle_hash = test_utils.RandomSHA256()
    event = self._CreateEvent(event_hash)
    event.update({
        EVENT_UPLOAD.FILE_BUNDLE_HASH: bundle_hash,
        EVENT_UPLOAD.FILE_BUNDLE_PATH: '/Unknown.app',
        EVENT_UPLOAD.FILE_BUNDLE_BINARY_COUNT: 1,
        EVENT_UPLOAD.FILE_BUNDLE_EXECUTABLE_REL_PATH:
            'Content/MacOS/unknown',
        EVENT_UPLOAD.FILE_PATH: '/Unknown.app/Content/MacOS',
        EVENT_UPLOAD.FILE_NAME: 'unknown',
        EVENT_UPLOAD.DECISION: constants.EVENT_TYPE.BUNDLE_BINARY
    })
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(0, event_models.SantaEvent.query().count())

    # Should have created the bundle.
    bundle = package_models.SantaBundle.get_by_id(bundle_hash)
    self.assertIsNotNone(bundle)

    # Should have created the bundle member.
    expected_binary_key = datastore_utils.ConcatenateKeys(
        bundle.key, ndb.Key(package_models.SantaBundleBinary, event_hash))
    self.assertIsNotNone(expected_binary_key.get())
    self.assertEqual(
        1, package_models.SantaBundleBinary.query(ancestor=bundle.key).count())

    self.assertBigQueryInsertions(
        [TABLE.BINARY, TABLE.BUNDLE, TABLE.BUNDLE_BINARY])

  def testBundleUpload_Mixed(self):
    blockable = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(uploaded_dt=None)

    normal_event = self._CreateEvent('blah')
    upload_event = self._CreateEvent(blockable.key.id())
    upload_event.update({
        EVENT_UPLOAD.FILE_BUNDLE_HASH: bundle.key.id(),
        EVENT_UPLOAD.FILE_BUNDLE_PATH: '/Foo.app',
        EVENT_UPLOAD.FILE_BUNDLE_EXECUTABLE_REL_PATH:
            'Content/MacOS/foo',
        EVENT_UPLOAD.FILE_PATH: '/Foo.app/Content/MacOS',
        EVENT_UPLOAD.FILE_NAME: 'foo',
        EVENT_UPLOAD.DECISION: constants.EVENT_TYPE.BUNDLE_BINARY
    })
    request_json = {
        EVENT_UPLOAD.EVENTS: [normal_event, upload_event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(1, event_models.SantaEvent.query().count())
    self.assertIsNotNone(santa_models.SantaBlockable.get_by_id('blah'))

    self.assertEqual(
        1, package_models.SantaBundleBinary.query(ancestor=bundle.key).count())
    self.assertTrue(bundle.key.get().has_been_uploaded)

    self.assertBigQueryInsertions(
        [TABLE.BINARY, TABLE.BUNDLE_BINARY, TABLE.EXECUTION])

  def testBundleUpload_IndexedValueTooLong(self):
    event_hash = test_utils.RandomSHA256()
    bundle_hash = test_utils.RandomSHA256()
    event = self._CreateEvent(event_hash)
    event.update({
        EVENT_UPLOAD.FILE_BUNDLE_HASH: bundle_hash,
        EVENT_UPLOAD.FILE_BUNDLE_PATH: '/Unknown.app',
        EVENT_UPLOAD.FILE_BUNDLE_NAME: 'x' * 2000,
        EVENT_UPLOAD.FILE_BUNDLE_BINARY_COUNT: 1,
        EVENT_UPLOAD.FILE_BUNDLE_EXECUTABLE_REL_PATH:
            'Content/MacOS/unknown',
        EVENT_UPLOAD.FILE_PATH: '/Unknown.app/Content/MacOS',
        EVENT_UPLOAD.FILE_NAME: 'unknown',
        EVENT_UPLOAD.DECISION: constants.EVENT_TYPE.BUNDLE_BINARY
    })
    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    self.assertEqual(0, event_models.SantaEvent.query().count())

    # Should have created the bundle.
    bundle = package_models.SantaBundle.get_by_id(bundle_hash)
    self.assertIsNotNone(bundle)

    # Should have created the bundle member.
    expected_binary_key = datastore_utils.ConcatenateKeys(
        bundle.key, ndb.Key(package_models.SantaBundleBinary, event_hash))
    self.assertIsNotNone(expected_binary_key.get())
    self.assertEqual(
        1, package_models.SantaBundleBinary.query(ancestor=bundle.key).count())

    self.assertBigQueryInsertions(
        [TABLE.BINARY, TABLE.BUNDLE, TABLE.BUNDLE_BINARY])

  def testQuarantine(self):
    event = self._CreateEvent('the-sha256')
    event.update({
        EVENT_UPLOAD.QUARANTINE_TIMESTAMP: 1234567,
        EVENT_UPLOAD.QUARANTINE_DATA_URL: 'http://a.com',
        EVENT_UPLOAD.QUARANTINE_REFERER_URL: 'http://',
        EVENT_UPLOAD.QUARANTINE_AGENT_BUNDLE_ID: '1',
    })

    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    event_entity = event_models.SantaEvent.query().get()

    self.assertEqual('http://a.com', event_entity.quarantine.data_url)
    self.assertEqual('http://', event_entity.quarantine.referer_url)
    self.assertEqual(
        datetime.datetime.utcfromtimestamp(1234567),
        event_entity.quarantine.downloaded_dt)

    self.assertBigQueryInsertions([TABLE.BINARY, TABLE.EXECUTION])

  def testQuarantine_NoData(self):
    event = self._CreateEvent('the-sha256')

    request_json = {EVENT_UPLOAD.EVENTS: [event]}
    self.testapp.post_json('/my-uuid', request_json)

    event_entity = event_models.SantaEvent.query().get()

    self.assertIsNone(event_entity.quarantine)

    self.assertBigQueryInsertions([TABLE.BINARY, TABLE.EXECUTION])

  def testGenerateSantaEventsFromJsonEvent_NoExecutingUser(self):

    malformed_event = {
        EVENT_UPLOAD.FILE_SHA256: '12345',
        EVENT_UPLOAD.FILE_NAME: 'fname',
        EVENT_UPLOAD.FILE_PATH: '/usr/bin',
        EVENT_UPLOAD.EXECUTION_TIME: 1404162158,
        EVENT_UPLOAD.EXECUTING_USER: None,
        EVENT_UPLOAD.LOGGED_IN_USERS: ['user'],
        EVENT_UPLOAD.CURRENT_SESSIONS: ['user@console'],
        EVENT_UPLOAD.DECISION: 'BLOCK_UNKNOWN',
        EVENT_UPLOAD.PID: 123,
        EVENT_UPLOAD.PPID: 321,
        EVENT_UPLOAD.SIGNING_CHAIN: []}

    sync.EventUploadHandler._GenerateSantaEventsFromJsonEvent(
        malformed_event, self.host)

    self.assertBigQueryInsertion(TABLE.EXECUTION)


class RuleDownloadHandlerTest(SantaApiTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/(.*)', sync.RuleDownloadHandler)])
    super(RuleDownloadHandlerTest, self).setUp(wsgi_app=app)
    self.Patch(
        sync.RuleDownloadHandler,
        'RequestCounter',
        new_callable=mock.PropertyMock,
        return_value=self.mock_request_metric)

    self.host = host_models.SantaHost(
        key=ndb.Key('Host', 'my-uuid'),
        rule_sync_dt=datetime.datetime(2001, 01, 01, 0, 0, 0))
    self.host.put()

    self.blockable = test_utils.CreateBlockable(
        id='aaaaaaaaaabbbbbbbbbbcccccccccdddddddddd')
    self.rule = rule_models.SantaRule(
        parent=self.blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST)
    self.rule.put()

  def testDownloadRules(self):
    response = self.testapp.post_json('/my-uuid', {})
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)
    self.assertFalse(RULE_DOWNLOAD.CURSOR in response.json)

    rules = response.json[RULE_DOWNLOAD.RULES]

    self.assertLen(rules, 1)
    rule = rules[0]
    self.assertEqual(
        self.blockable.key.id(), rule[RULE_DOWNLOAD.SHA256])
    self.assertEqual(
        self.rule.rule_type, rule[RULE_DOWNLOAD.RULE_TYPE])
    self.assertEqual(
        self.rule.policy, rule[RULE_DOWNLOAD.POLICY])
    self.assertEqual(
        self.rule.custom_msg, rule[RULE_DOWNLOAD.CUSTOM_MSG])
    ts = rule[RULE_DOWNLOAD.CREATION_TIME]
    self.assertEqual(
        self.rule.updated_dt, datetime.datetime.utcfromtimestamp(ts))

  def testGlobalRule(self):
    response = self.testapp.post_json('/my-uuid', {})
    self.assertLen(response.json[RULE_DOWNLOAD.RULES], 1)
    self.assertFalse(RULE_DOWNLOAD.CURSOR in response.json)
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

  def testOnlySyncNewRules(self):
    self.host.rule_sync_dt = datetime.datetime.utcnow()
    self.host.put()

    response = self.testapp.post_json('/my-uuid', {})
    self.assertLen(response.json[RULE_DOWNLOAD.RULES], 0)
    self.assertFalse(RULE_DOWNLOAD.CURSOR in response.json)
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

  def testLocalRule(self):
    self.rule.host_id = 'my-uuid'
    self.rule.put()

    second_comp = host_models.SantaHost(
        key=ndb.Key('Host', 'my-other-uuid'),
        rule_sync_dt=datetime.datetime(2001, 01, 01, 0, 0, 0))
    second_comp.put()

    response = self.testapp.post_json('/my-uuid', {})
    self.assertLen(response.json[RULE_DOWNLOAD.RULES], 1)
    self.assertFalse(RULE_DOWNLOAD.CURSOR in response.json)
    self.assertEqual(httplib.OK, response.status_int)

    response = self.testapp.post_json('/my-other-uuid', {})
    self.assertLen(response.json[RULE_DOWNLOAD.RULES], 0)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK, httplib.OK)

  def testReplacedRule(self):
    self.host.rule_sync_dt = datetime.datetime.utcnow()
    self.host.put()

    blockable = test_utils.CreateBlockable()
    rule_models.SantaRule(
        parent=blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.BLACKLIST).put()
    rule_models.SantaRule(
        parent=blockable.key,
        rule_type=constants.RULE_TYPE.BINARY,
        policy=constants.RULE_POLICY.WHITELIST).put()

    response = self.testapp.post_json('/my-uuid', {})

    self.assertLen(response.json[RULE_DOWNLOAD.RULES], 2)
    latest_rule = response.json[RULE_DOWNLOAD.RULES][1]
    self.assertEqual(
        constants.RULE_POLICY.WHITELIST, latest_rule[RULE_DOWNLOAD.POLICY])
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

  def testBundleRule(self):
    self.rule.key.delete()

    blockable1 = test_utils.CreateSantaBlockable()
    blockable2 = test_utils.CreateSantaBlockable()
    bundle = test_utils.CreateSantaBundle(
        bundle_binaries=[blockable1, blockable2])
    test_utils.CreateSantaRule(
        bundle.key, rule_type=constants.RULE_TYPE.PACKAGE)

    response = self.testapp.post_json('/my-uuid', {})
    self.assertEqual(httplib.OK, response.status_int)

    rules = response.json[RULE_DOWNLOAD.RULES]
    # We expect just the BINARY rules.
    self.assertLen(rules, 2)

    self.assertSameElements(
        [blockable1.key.id(), blockable2.key.id()],
        [rule[RULE_DOWNLOAD.SHA256] for rule in rules])

    for rule in rules:
      self.assertEqual(
          constants.RULE_TYPE.BINARY,
          rule[RULE_DOWNLOAD.RULE_TYPE])
      self.assertEqual(
          2, rule[RULE_DOWNLOAD.FILE_BUNDLE_BINARY_COUNT])
      self.assertEqual(
          bundle.key.id(), rule[RULE_DOWNLOAD.FILE_BUNDLE_HASH])

    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)

  def testCursor(self):
    blockable = test_utils.CreateBlockable()
    rule_models.SantaRule(
        parent=blockable.key,
        rule_type=constants.RULE_TYPE.CERTIFICATE,
        policy=constants.RULE_POLICY.BLACKLIST).put()

    self.PatchSetting('SANTA_RULE_BATCH_SIZE', 1)

    response = self.testapp.post_json('/my-uuid', {})
    self.assertLen(response.json[RULE_DOWNLOAD.RULES], 1)
    self.assertTrue(response.json[RULE_DOWNLOAD.CURSOR])
    self.assertEqual(httplib.OK, response.status_int)

    response = self.testapp.post_json(
        '/my-uuid', {
            RULE_DOWNLOAD.CURSOR:
                response.json[RULE_DOWNLOAD.CURSOR]
        }
    )
    self.assertLen(response.json[RULE_DOWNLOAD.RULES], 1)
    self.assertFalse(RULE_DOWNLOAD.CURSOR in response.json)
    self.assertEqual(httplib.OK, response.status_int)

    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK, httplib.OK)


class PostflightHandlerTest(SantaApiTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/(.*)', sync.PostflightHandler)])
    super(PostflightHandlerTest, self).setUp(wsgi_app=app)
    self.Patch(
        sync.PostflightHandler,
        'RequestCounter',
        new_callable=mock.PropertyMock,
        return_value=self.mock_request_metric)

    self.preflight_dt = datetime.datetime.utcnow()

    self.host = test_utils.CreateSantaHost(
        id='MY-UUID', last_preflight_dt=self.preflight_dt, primary_user='user')

  def testUpdateRuleSyncTimestamp(self):

    response = self.testapp.post('/%s' % self.host.key.id())

    host = host_models.SantaHost.get_by_id('MY-UUID')
    self.assertEqual(host.rule_sync_dt, self.preflight_dt)
    self.assertTrue(host.last_postflight_dt)
    self.assertEqual(httplib.OK, response.status_int)
    self.VerifyIncrementCalls(self.mock_request_metric, httplib.OK)
    self.assertBigQueryInsertion(TABLE.HOST)


if __name__ == '__main__':
  basetest.main()

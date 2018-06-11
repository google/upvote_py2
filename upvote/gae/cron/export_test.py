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

"""Unit tests for export.py."""

import datetime
import httplib

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud.bigquery import table as bq_table
import mock
import webapp2

from google.appengine.api import taskqueue
from google.appengine.ext import db
from google.appengine.ext import ndb
from upvote.gae.cron import export
from upvote.gae.modules.upvote_app.lib import bigquery_schema
from upvote.gae.shared.common import basetest
from upvote.gae.shared.common import settings
from upvote.gae.shared.common import settings_utils
from upvote.gae.shared.common import utils
from upvote.gae.datastore.models import bigquery as bq_models
from upvote.gae.datastore import test_utils
from upvote.shared import constants


class FakeBackup(db.Model):
  name = db.ByteStringProperty()
  complete_time = db.DateTimeProperty()

  @classmethod
  def kind(cls):
    return '_AE_Backup_Information'


class TableDispatchEntryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(TableDispatchEntryTest, self).setUp()
    self._entry = export.TableDispatchEntry(
        constants.GAE_STREAMING_TABLES.EXECUTION)

  def testMissingEntity_One(self):

    # Create some entities in chronological order, and then delete the "most
    # recent" one.
    now = datetime.datetime.utcnow()
    keys = []
    entity_count = 10
    for i in xrange(entity_count):
      timestamp = now + datetime.timedelta(seconds=i)
      key = test_utils.RandomDatastoreEntity(
          bq_models.ExecutionRow, timestamp=timestamp).put()
      keys.append(key)
    key.delete()

    # The "most recent" timestamp should end up being updated to the timestamp
    # of second-to-last entity.
    expected_most_recent = keys[-2].get().timestamp

    mock_query = mock.Mock(spec=ndb.Query)
    mock_query.fetch_page.return_value = (keys, None, False)
    self.Patch(self._entry, '_BuildKeyPageQuery', return_value=mock_query)

    self.assertIsNone(self._entry._most_recent)
    key_page, finished = self._entry.FetchNextKeyPage()

    self.assertEqual(entity_count, len(key_page))
    self.assertTrue(finished)
    self.assertEqual(expected_most_recent, self._entry._most_recent)

  def testMissingEntity_All(self):

    # Create some entities in chronological order, and then delete them.
    now = datetime.datetime.utcnow()
    keys = []
    entity_count = 10
    for i in xrange(entity_count):
      timestamp = now + datetime.timedelta(seconds=i)
      key = test_utils.RandomDatastoreEntity(
          bq_models.ExecutionRow, timestamp=timestamp).put()
      keys.append(key)
    ndb.delete_multi(keys)

    mock_query = mock.Mock(spec=ndb.Query)
    mock_query.fetch_page.return_value = (keys, None, False)
    self.Patch(self._entry, '_BuildKeyPageQuery', return_value=mock_query)

    self.assertIsNone(self._entry._most_recent)
    key_page, finished = self._entry.FetchNextKeyPage()

    self.assertEqual(entity_count, len(key_page))
    self.assertTrue(finished)
    self.assertIsNone(self._entry._most_recent)

  def testNoMoreEntities(self):

    # Simulate an elevated max_page_count.
    self._entry._max_page_count = 16

    mock_query = mock.Mock(spec=ndb.Query)
    mock_query.fetch_page.return_value = ([], None, False)
    self.Patch(self._entry, '_BuildKeyPageQuery', return_value=mock_query)

    key_page, finished = self._entry.FetchNextKeyPage()

    self.assertEqual(0, len(key_page))
    self.assertTrue(finished)
    self.assertIsNone(self._entry._cursor)
    self.assertEqual(0, self._entry._page_count)
    self.assertEqual(8, self._entry._max_page_count)

  def testMaxPageCountReached(self):

    entities = test_utils.RandomDatastoreEntities(
        bq_models.ExecutionRow, export._MAX_PAGE_SIZE)
    keys = ndb.put_multi(entities)

    # Simulate an elevated page_count and max_page_count.
    self._entry._page_count = 15
    self._entry._max_page_count = 16

    mock_query = mock.Mock(spec=ndb.Query)
    mock_query.fetch_page.return_value = (keys, None, True)
    self.Patch(self._entry, '_BuildKeyPageQuery', return_value=mock_query)

    key_page, finished = self._entry.FetchNextKeyPage()

    self.assertEqual(export._MAX_PAGE_SIZE, len(key_page))
    self.assertTrue(finished)
    self.assertIsNone(self._entry._cursor)
    self.assertEqual(0, self._entry._page_count)
    self.assertEqual(17, self._entry._max_page_count)


class TestHandler(export.BaseHandler):

  def get(self):
    pass


class BaseHandlerTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', TestHandler)])
    super(BaseHandlerTest, self).setUp(wsgi_app=app)

  def testInProd_Cron(self):
    self.Patch(export.utils, 'RunningInProd', return_value=True)
    self.Logout()  # Ensures that get_current_user() returns None.
    self.testapp.get('/', status=httplib.OK)

  def testInProd_AuthorizedUser(self):
    self.Patch(export.utils, 'RunningInProd', return_value=True)
    with self.LoggedInUser(admin=True):
      self.testapp.get('/', status=httplib.OK)

  def testInProd_UnauthorizedUser(self):
    self.Patch(export.utils, 'RunningInProd', return_value=True)
    with self.LoggedInUser():
      self.testapp.get('/', expect_errors=True, status=httplib.FORBIDDEN)

  def testNotInProd_Cron(self):
    self.Patch(export.utils, 'RunningInProd', return_value=False)
    self.Logout()  # Ensures that get_current_user() returns None.
    self.testapp.get('/', expect_errors=True, status=httplib.FORBIDDEN)

  def testNotInProd_Authorized(self):
    self.Patch(export.utils, 'RunningInProd', return_value=False)
    with self.LoggedInUser(admin=True):
      self.testapp.get('/', status=httplib.OK)

  def testNotInProd_Unauthorized(self):
    self.Patch(export.utils, 'RunningInProd', return_value=False)
    with self.LoggedInUser():
      self.testapp.get('/', expect_errors=True, status=httplib.FORBIDDEN)


class DatastoreToGCSTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/somerequest', export.DatastoreToGCS)])
    super(DatastoreToGCSTest, self).setUp(wsgi_app=app)
    self.date1 = datetime.datetime.utcnow()
    self.date2 = datetime.datetime(2012, 12, 12, 8, 45)
    todaystr1 = self.date1.strftime('%Y_%m_%d')
    todaystr2 = self.date2.strftime('%Y_%m_%d')
    self.expected_name1 = '%s_%s' % (export._BACKUP_PREFIX, todaystr1)
    self.expected_name2 = '%s_%s' % (export._BACKUP_PREFIX, todaystr2)

  def testNoDailyBackupExists(self):
    self.assertFalse(export._DailyBackupExists())

  def testDailyBackupExists(self):
    FakeBackup(name=self.expected_name1, complete_time=self.date1).put()
    self.assertTrue(export._DailyBackupExists())

  @mock.patch.object(taskqueue, 'add')
  @mock.patch.object(export, '_DailyBackupExists', return_value=True)
  @mock.patch.object(export.users, 'get_current_user', return_value=None)
  @mock.patch.object(utils, 'RunningInProd', return_value=True)
  def testBackupExists(self, mock_prod, mock_user, mock_exists, mock_add):
    self.testapp.get('/somerequest', status=httplib.OK)
    self.assertEqual(0, mock_add.call_count)

  @mock.patch.object(taskqueue, 'add')
  @mock.patch.object(
      settings_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  @mock.patch.object(export, '_DailyBackupExists', return_value=False)
  @mock.patch.object(export.users, 'get_current_user', return_value=None)
  @mock.patch.object(utils, 'RunningInProd', return_value=True)
  def testSuccessfulBackup(
      self, mock_prod, mock_user, mock_exists, mock_env, mock_add):
    self.testapp.get('/somerequest', status=httplib.OK)
    self.assertEqual(1, mock_add.call_count)


class DispatchTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(DispatchTest, self).setUp()
    self.Patch(export, '_MAX_PAGE_SIZE', new=10)

  def _CreateBigQueryRows(self, model_cls, count):

    now = datetime.datetime.utcnow()
    entities = []

    for i in xrange(count):
      timestamp = now + datetime.timedelta(seconds=i)
      entity = test_utils.RandomDatastoreEntity(model_cls, timestamp=timestamp)
      entities.append(entity)

    ndb.put_multi(entities)
    return entities

  @mock.patch.object(
      export.time_utils, 'TimeRemains', side_effect=[True] * 28 + [False])
  def testDispatching(self, mock_time_remains):

    self._CreateBigQueryRows(bq_models.BinaryRow, export._MAX_PAGE_SIZE - 1)
    self._CreateBigQueryRows(bq_models.ExecutionRow, export._MAX_PAGE_SIZE * 4)
    self._CreateBigQueryRows(bq_models.HostRow, export._MAX_PAGE_SIZE + 1)
    self._CreateBigQueryRows(bq_models.VoteRow, export._MAX_PAGE_SIZE * 2)
    self._CreateBigQueryRows(bq_models.UserRow, export._MAX_PAGE_SIZE)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_ROW_STREAMING, 0)

    export._Dispatch()

    self.assertEqual(29, mock_time_remains.call_count)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_ROW_STREAMING, 10)

    expected_defers = [
        (constants.GAE_STREAMING_TABLES.BINARY, export._MAX_PAGE_SIZE - 1),
        (constants.GAE_STREAMING_TABLES.EXECUTION, export._MAX_PAGE_SIZE),
        (constants.GAE_STREAMING_TABLES.HOST, export._MAX_PAGE_SIZE),
        (constants.GAE_STREAMING_TABLES.USER, export._MAX_PAGE_SIZE),
        (constants.GAE_STREAMING_TABLES.VOTE, export._MAX_PAGE_SIZE),
        (constants.GAE_STREAMING_TABLES.EXECUTION, export._MAX_PAGE_SIZE),
        (constants.GAE_STREAMING_TABLES.EXECUTION, export._MAX_PAGE_SIZE),
        (constants.GAE_STREAMING_TABLES.HOST, 1),
        (constants.GAE_STREAMING_TABLES.VOTE, export._MAX_PAGE_SIZE),
        (constants.GAE_STREAMING_TABLES.EXECUTION, export._MAX_PAGE_SIZE)]
    tasks = self.UnpackTaskQueue(constants.TASK_QUEUE.BQ_ROW_STREAMING)
    actual_defers = [(t[1][0], len(t[1][1])) for t in tasks]
    self.assertEqual(expected_defers, actual_defers)


class EntityToTupleTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(EntityToTupleTest, self).setUp()
    self.table = bq_table.Table('Black Mesa', None)
    self.table.schema = bigquery_schema.TABLE_SCHEMAS[
        constants.GAE_STREAMING_TABLES.EXECUTION]

  def testSuccess(self):
    sha256 = 'themostsecretsha'
    device_id = 'user-kiwi'
    timestamp = datetime.datetime.utcnow()
    platform = constants.PLATFORM.MACOS
    client = constants.CLIENT.SANTA
    bundle_path = '//path/to/bundle'
    file_path = '//file/path/secret.exe'
    file_name = 'secret.exe'
    executing_user = 'user'
    associated_users = [executing_user]
    decision = constants.EVENT_TYPE.ALLOW_UNKNOWN
    comment = 'The Big Board'

    execution_row = bq_models.ExecutionRow(
        sha256=sha256, device_id=device_id, timestamp=timestamp,
        platform=platform, client=client, bundle_path=bundle_path,
        file_path=file_path, file_name=file_name, executing_user=executing_user,
        decision=decision, comment=comment, associated_users=associated_users)
    execution_row.put()

    actual_tuple = export._EntityToTuple(self.table, execution_row)
    expected_tuple = (
        sha256, device_id, timestamp, platform, client, bundle_path,
        file_path, file_name, executing_user, associated_users,
        decision, comment)
    self.assertEqual(expected_tuple, actual_tuple)


class StreamPageTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(StreamPageTest, self).setUp()
    export._BQ_PAGE_STREAM_LIMIT = 1
    self.table = bq_table.Table('Black Mesa', None)
    self.table.schema = bigquery_schema.TABLE_SCHEMAS[
        constants.GAE_STREAMING_TABLES.EXECUTION]
    self.exec_1 = test_utils.RandomDatastoreEntity(bq_models.ExecutionRow)
    self.exec_2 = test_utils.RandomDatastoreEntity(bq_models.ExecutionRow)
    self.exec_3 = test_utils.RandomDatastoreEntity(bq_models.ExecutionRow)

  @mock.patch.object(
      export.bigquery.dataset.Dataset, 'exists', autospec=True)
  @mock.patch.object(
      export.bigquery.table.Table, 'reload', autospec=True)
  @mock.patch.object(
      export.bigquery.table.Table, 'insert_data',
      return_value=False, autospec=True)
  @mock.patch.object(
      settings_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  def testStreamsAll(self, *_):
    self.exec_1.put()
    self.exec_2.put()
    self.exec_3.put()
    export._StreamPage(
        constants.GAE_STREAMING_TABLES.EXECUTION,
        [self.exec_1.key, self.exec_2.key, self.exec_3.key])
    # Stream successful, so all entities should be gone.
    self.assertEntityCount(bq_models.ExecutionRow, 0)

  @mock.patch.object(
      export.bigquery.dataset.Dataset, 'exists', autospec=True)
  @mock.patch.object(
      export.bigquery.table.Table, 'reload', autospec=True)
  @mock.patch.object(
      export.bigquery.table.Table, 'insert_data',
      return_value=True, autospec=True)
  @mock.patch.object(
      settings_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  def testStreamsPartial(self, *_):
    self.exec_1.put()
    export._StreamPage(
        constants.GAE_STREAMING_TABLES.EXECUTION,
        [self.exec_1.key])
    # Failed to stream, so it should still exist.
    self.assertEntityCount(bq_models.ExecutionRow, 1)

  @mock.patch.object(
      export.bigquery.dataset.Dataset, 'exists',
      return_value=False, autospec=True)
  @mock.patch.object(
      settings_utils, 'CurrentEnvironment', return_value=settings.ProdEnv)
  def testMissingDatasetError(self, *_):
    with self.assertRaises(export.MissingDatasetError):
      export._StreamPage(constants.GAE_STREAMING_TABLES.EXECUTION, [])

  @mock.patch.object(
      export.bigquery.table.Table, 'insert_data',
      return_value=True, autospec=True)
  @mock.patch.object(
      export.bigquery.table.Table, 'reload', autospec=True)
  @mock.patch.object(
      export.bigquery.dataset.Dataset, 'exists', autospec=True)
  def testRowsAlreadyDeferred(self, mock_exists, mock_reload, mock_insert_data):

    mock_exists.return_value = True

    # Create some test rows, but then delete some of them. This simulates the
    # scenario where some entities have been queued for streaming in a
    # just-completed dispatch task, but weren't processed and deleted until
    # after we've already gathered up their Keys again in a new dispatch task.
    total_rows = 20
    repeat_rows = 7
    entities = test_utils.RandomDatastoreEntities(
        bq_models.ExecutionRow, total_rows)
    keys = ndb.put_multi(entities)
    ndb.delete_multi(keys[:repeat_rows])

    export._StreamPage(constants.GAE_STREAMING_TABLES.EXECUTION, keys)

    expected_inserts = total_rows - repeat_rows
    actual_inserts = len(mock_insert_data.call_args_list[0][0][1])
    self.assertEqual(expected_inserts, actual_inserts)


class StreamToBigQueryTest(basetest.UpvoteTestCase):

  def setUp(self):
    super(StreamToBigQueryTest, self).setUp()

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  def testDefers(self):
    export.StreamToBigQuery().get()
    self.assertTaskCount(constants.TASK_QUEUE.BQ_DISPATCH, 1)


class CountRowsToStreamTest(basetest.UpvoteTestCase):

  def setUp(self):
    app = webapp2.WSGIApplication([('/', export.CountRowsToStream)])
    super(CountRowsToStreamTest, self).setUp(wsgi_app=app)

    self.PatchEnv(settings.ProdEnv, ENABLE_BIGQUERY_STREAMING=True)

  @mock.patch.object(export.monitoring, 'rows_to_stream')
  def testSuccess(self, mock_metric):

    vote_count = 20
    host_count = 10
    expected_count = vote_count + host_count
    ndb.put_multi(
        test_utils.RandomDatastoreEntities(bq_models.VoteRow, vote_count))
    ndb.put_multi(
        test_utils.RandomDatastoreEntities(bq_models.HostRow, host_count))

    self.assertEntityCount(bq_models.BigQueryRow, expected_count)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_COUNTING, 0)

    response = self.testapp.get('/')

    self.assertEqual(httplib.OK, response.status_int)
    self.assertTaskCount(constants.TASK_QUEUE.BQ_COUNTING, 1)
    self.RunDeferredTasks(constants.TASK_QUEUE.BQ_COUNTING)

    self.assertTaskCount(constants.TASK_QUEUE.BQ_COUNTING, 0)
    self.assertEqual(1, mock_metric.Set.call_count)
    actual_count = mock_metric.Set.call_args_list[0][0][0]
    self.assertEqual(expected_count, actual_count)


if __name__ == '__main__':
  basetest.main()

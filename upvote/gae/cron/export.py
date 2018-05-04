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

"""Handler for performing scheduled datastore tasks."""

import collections
import datetime
import httplib
import logging

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud import bigquery

from google.appengine.api import datastore
from google.appengine.api import taskqueue
from google.appengine.api import users
from google.appengine.ext import deferred
from google.appengine.ext import ndb
from google.appengine.ext.ndb import metadata
from upvote.gae.cron import monitoring
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import settings
from upvote.gae.taskqueue import utils as taskqueue_utils
from upvote.gae.shared.common import utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import bigquery as bigquery_models
from upvote.shared import constants
from upvote.shared import time_utils


_BACKUP_PREFIX = 'datastore_backup'
_BIGQUERY_SCOPE = 'https://www.googleapis.com/auth/bigquery'

_MAX_PAGE_SIZE = 500

_DISPATCH_DURATION = datetime.timedelta(minutes=9, seconds=30)

_BIGQUERY_ROW_MAP = {
    constants.GAE_STREAMING_TABLES.VOTE:
    bigquery_models.VoteRow,

    constants.GAE_STREAMING_TABLES.HOST:
    bigquery_models.HostRow,

    constants.GAE_STREAMING_TABLES.BINARY:
    bigquery_models.BinaryRow,

    constants.GAE_STREAMING_TABLES.EXECUTION:
    bigquery_models.ExecutionRow,

    constants.GAE_STREAMING_TABLES.CERTIFICATE:
    bigquery_models.CertificateRow,

    constants.GAE_STREAMING_TABLES.BUNDLE:
    bigquery_models.BundleRow,

    constants.GAE_STREAMING_TABLES.BUNDLE_BINARY:
    bigquery_models.BundleBinaryRow,

    constants.GAE_STREAMING_TABLES.USER:
    bigquery_models.UserRow}


class TableDispatchEntry(object):
  """Class for tracking per-table metadata within the dispatch task."""

  def __init__(self, name):
    self._name = name
    self._cursor = None
    self._most_recent = None
    self._page_count = 0
    self._max_page_count = 1

  @property
  def name(self):
    return self._name

  def _BuildKeyPageQuery(self):
    """Helper method for building a Query for a page of NDB Keys.

    Exists primarily for easier unit testing.

    Returns:
      An NDB Query.
    """
    # Build a query for the next page of Keys of the current NDB Model.
    model_cls = _BIGQUERY_ROW_MAP[self._name]
    query = model_cls.query().order(model_cls.timestamp)

    # If we have a "most recent" timestamp, but not a cursor, that means we
    # exhausted a query for this Model in an earlier fetch, so we should filter
    # for only entities older than that timestamp, otherwise we run the risk of
    # deferring Keys that have already been deferred for streaming.
    if self._most_recent and not self._cursor:
      query = query.filter(model_cls.timestamp > self._most_recent)

    return query

  def FetchNextKeyPage(self):
    """Fetches the next page of NDB Keys for BigQuery streaming.

    Returns:
      A tuple of the form (list, boolean). The list contains NDB Keys whose
      entities are to be streamed to BigQuery, and may be empty. The boolean
      indicates if fetching for this Model has finished (either no entities
      remain to be streamed, or we've fetched the maximum number of pages of
      this Model)
    """
    # Fetch a page of Keys for this Model.
    query = self._BuildKeyPageQuery()
    key_page, self._cursor, more = query.fetch_page(
        _MAX_PAGE_SIZE, start_cursor=self._cursor, keys_only=True)

    page_size = len(key_page)
    self._page_count += 1
    finished = False

    if key_page:

      logging.info(
          'Fetched %d %s entities to be streamed (page %d of %d)', page_size,
          self._name, self._page_count, self._max_page_count)

      # Update the "most recent" timestamp from the last non-None entity in the
      # page. There's a very small chance that some entities were streamed and
      # deleted, which we have to account for. In the even more unlikely case of
      # all of these entities coming back None, we'll leave the timestamp as-is,
      # nothing will get streamed from this page, and we'll just try again with
      # this timestamp next time.
      for key in reversed(key_page):
        entity = key.get()
        if entity is not None:
          self._most_recent = entity.timestamp
          break

    # We've run out of entities for this Model.
    if page_size < _MAX_PAGE_SIZE or not more:
      finished = True
      logging.info('There are no more %s entities to stream', self._name)
      self._cursor = None
      self._page_count = 0

      # Cut the max_page_count in half.
      new_max_page_count = max(self._max_page_count / 2, 1)
      if new_max_page_count != self._max_page_count:
        self._max_page_count = new_max_page_count
        logging.info(
            'Decreasing the max_page_count of %s to %d', self._name,
            self._max_page_count)

    # The page was the maximum size, but we hit the page limit.
    elif self._page_count >= self._max_page_count:
      finished = True
      self._page_count = 0

      # There's still a backlog for this Model, so increase the max_page_count.
      self._max_page_count += 1
      logging.info(
          'Increasing the max_page_count of %s to %d', self._name,
          self._max_page_count)

    return key_page, finished


class Error(Exception):
  """Base error class for this module."""


class MissingDatasetError(Error):
  """Raised if a required dataset does not exist."""


def _CreateDayString(dt=None):
  if not dt:
    dt = datetime.datetime.utcnow()
  return dt.strftime('%Y_%m_%d')


def _DailyBackupExists():
  expected_backup_name = '%s_%s' % (_BACKUP_PREFIX, _CreateDayString())
  query = datastore.Query(kind='_AE_Backup_Information', keys_only=True)
  query['name ='] = expected_backup_name
  return query.Get(1)


# The following module-level functions are only for (at the moment) BigQuery
# streaming. They're required to be module-level in order to be compatible with
# deferred.defer's pickling. :)


def _Dispatch():
  """Continuously creates tasks which stream batches of entities to BigQuery.

  The goal of this implementation is to keep the bigquery-row-streaming queue as
  full as possible, even if we have a large number of entities distributed among
  a small number of Models (e.g. Execution).

  We do this by continually looping over all the BigQueryRow Models, querying
  for any new entities, in pages of up to 500. Each page of entity Keys is then
  deferred to a separate task queue to be streamed to BigQuery.

  When a full page of Keys is retrieved, we react to the load by increasing
  the number of pages (max_page_count) that get streamed for that particular
  Model on the next iteration. When we run out of Keys, we drawn down the
  max_page_count by dividing it in half.
  """
  start_time = datetime.datetime.utcnow()

  # Create a queue of TableDispatchEntry objects. Each entry corresponds to a
  # BigQueryRow subclass, its corresponding BigQuery table, and the current
  # state of the streaming of those rows to their table. Items are sorted for
  # more predictability in unit tests.
  dispatch_queue = collections.deque(
      TableDispatchEntry(name)
      for name in sorted(constants.GAE_STREAMING_TABLES.SET_ALL))

  entry = dispatch_queue.popleft()
  logging.info('Querying for %s entities to stream', entry.name)

  # Dispatch jobs to the streaming queue until the task queue deadline nears.
  while time_utils.TimeRemains(start_time, _DISPATCH_DURATION):

    key_page, finished = entry.FetchNextKeyPage()

    if key_page:

      # Defer a task to take the current page of Keys and stream the
      # corresponding rows to BigQuery.
      deferred.defer(
          _StreamPage, entry.name, key_page,
          _queue=constants.TASK_QUEUE.BQ_STREAMING)

    # If this TableDispatchEntry is finished, pop the next one and start over.
    if finished:
      dispatch_queue.append(entry)
      entry = dispatch_queue.popleft()
      logging.info('Querying for %s entities to stream', entry.name)

  logging.info('Task deadline reached')


def _EntityToTuple(table, entity):
  entity_dict = entity.to_dict()
  return tuple(entity_dict[field.name] for field in table.schema)


def _StreamPage(table_name, key_page):
  """Streams page to table associated with table_name.

  Raises:
    MissingDatasetError: If any datasets are non-existent.

  Args:
    table_name: str, table to stream to.
    key_page: list[ndb.Key], list of rows to stream.
  """
  page_size = len(key_page)
  logging.info('Streaming %d %s entities...', page_size, table_name)

  bq_client = bigquery.Client()
  dataset = bq_client.dataset(constants.GAE_STREAMING_DATASET)

  if not dataset.exists():
    logging.error('Dataset %s does not exist.', dataset.name)
    raise MissingDatasetError(dataset.name)

  table = dataset.table(table_name)

  # Reload to get the table schema.
  table.reload()

  # Convert all row entities into tuples, and collect Key IDs to be used by
  # BigQuery for best-effort deduplication.
  rows = []
  row_ids = []
  for entity in ndb.get_multi(key_page):

    # Only stream if we actually get an entity back for this Key. It's possible
    # that some rows were already streamed and deleted, in which case we can
    # safely ignore them.
    if entity is not None:
      rows.append(_EntityToTuple(table, entity))
      row_ids.append(entity.key.id())

  errors = table.insert_data(rows, row_ids=row_ids)

  if errors:
    logging.error(
        'Failed to stream %d rows into %s table:\nErrors: %s\nRows: %s',
        page_size, table_name, errors, rows)
  else:
    monitoring.rows_streamed.IncrementBy(page_size)
    logging.info('Deleting %d %s entities...', page_size, table_name)
    ndb.delete_multi(key_page)


class BaseHandler(handlers.UpvoteRequestHandler):

  def dispatch(self):

    appengine_user = users.get_current_user()
    logging.info(
        'Request initiated by %s',
        appengine_user.email() if appengine_user else 'cron')

    # Cron-triggered exports will not have a requesting user. Only allow these
    # in prod.
    prod_cron_export = utils.RunningInProd() and not appengine_user
    logging.info(
        'This is%s an automatic production export',
        '' if prod_cron_export else ' not')

    # If there is a requesting user, only proceed if the user has manual export
    # permissions.
    user_has_permission = False
    if appengine_user:
      current_user = base.User.GetOrInsert(appengine_user=appengine_user)
      user_has_permission = current_user.HasPermissionTo(
          constants.PERMISSIONS.TRIGGER_MANUAL_DATA_EXPORT)
      logging.info(
          'User %s does%s have permission to perform a manual export',
          appengine_user.email(), '' if user_has_permission else ' not')

    if prod_cron_export or user_has_permission:
      super(BaseHandler, self).dispatch()
    else:
      self.abort(httplib.FORBIDDEN)


class DatastoreToGCS(BaseHandler):
  """Handler for performing Datastore backups.

  NOTE: This backup does not pause writes to datastore during processing so the
  resulting backup does not reflect a snapshot of a single point in time. As
  such, there may be inconsistencies in the data across entity types.
  """

  def get(self):  # pylint: disable=g-bad-name

    # Only run one backup per day.
    if _DailyBackupExists():
      logging.info('A backup was already performed today.')
      return

    kinds = [k for k in metadata.get_kinds() if not k.startswith('_')]
    bucket = '%s/%s' % (settings.ENV.DATASTORE_BACKUP_BUCKET,
                        _CreateDayString())
    params = {
        'kind': kinds,
        'name': _BACKUP_PREFIX + '_',  # Date suffix is automatically added.
        'filesystem': 'gs',
        'gs_bucket_name': bucket,
        'queue': 'backup',
    }

    # Dump the backup onto a task queue. Don't worry about catching Exceptions,
    # anything that gets raised will be dealt with in UpvoteRequestHandler and
    # reported as a 500.
    taskqueue.add(
        url='/_ah/datastore_admin/backup.create',
        params=params,
        target='ah-builtin-python-bundle',
        queue_name='backup')


class StreamToBigQuery(BaseHandler):
  """Handler for streaming BigQueryRow models to Bigquery."""

  def get(self):
    if not settings.ENV.ENABLE_BIGQUERY_STREAMING:
      return
    deferred.defer(
        _Dispatch,
        _queue=constants.TASK_QUEUE.BQ_DISPATCH)


class CountRowsToPersist(handlers.UpvoteRequestHandler):

  def get(self):
    if not settings.ENV.ENABLE_BIGQUERY_STREAMING:
      return
    # Don't exceed the 60s request deadline.
    rows_to_persist = taskqueue_utils.QueueSize(
        queue=constants.TASK_QUEUE.BQ_PERSISTENCE, deadline=55)
    logging.info('There are currently %d rows to persist', rows_to_persist)
    monitoring.rows_to_persist.Set(rows_to_persist)


def _CountRows():
  """Counts the number of BigQueryRows in Datastore."""

  rows_to_stream = 0

  start_time = datetime.datetime.utcnow()
  duration = datetime.timedelta(minutes=9, seconds=45)

  cursor = None
  more = True

  # Counting starts hitting the 10 minute taskqueue limit as we approach 500k
  # rows, so count as many as we can in the time allotted.
  while time_utils.TimeRemains(start_time, duration) and more:
    results, cursor, more = bigquery_models.BigQueryRow.query().fetch_page(
        500, keys_only=True, start_cursor=cursor)
    rows_to_stream += len(results)

  logging.info('There are currently %d rows to stream', rows_to_stream)
  monitoring.rows_to_stream.Set(rows_to_stream)


class CountRowsToStream(handlers.UpvoteRequestHandler):

  def get(self):
    if not settings.ENV.ENABLE_BIGQUERY_STREAMING:
      return
    taskqueue_utils.CappedDefer(
        _CountRows, 5, queue=constants.TASK_QUEUE.BQ_COUNTING)

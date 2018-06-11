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

"""Representations of the BigQuery tables Upvote streams to."""

import collections
import datetime
import hashlib
import logging

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud import bigquery

from google.appengine.ext import deferred

from upvote.gae.datastore.models import bigquery as bigquery_models
from upvote.gae.bigquery import monitoring
from upvote.shared import constants


FIELD_TYPE = constants.UppercaseNamespace([
    'BOOLEAN', 'INTEGER', 'STRING', 'TIMESTAMP'])

FIELD_TYPE_MAP = {
    FIELD_TYPE.BOOLEAN: {bool},
    FIELD_TYPE.INTEGER: {int, long},
    FIELD_TYPE.STRING: {str, unicode},
    FIELD_TYPE.TIMESTAMP: {datetime.datetime},
}

MODE = constants.UppercaseNamespace(['NULLABLE', 'REPEATED', 'REQUIRED'])


Column = collections.namedtuple('Column', ['name', 'field_type', 'mode'])
Column.__new__.__defaults__ = (None, FIELD_TYPE.STRING, MODE.REQUIRED)  # pylint: disable=protected-access


class Error(Exception):
  """Base Exception class."""


class UnexpectedColumn(Error):
  """Raised when an unexpected column is provided."""


class MissingColumn(Error):
  """Raised when an expected column is not provided."""


class UnexpectedNull(Error):
  """Raised when a non-nullable column is null."""


class InvalidRepeated(Error):
  """Raised when an invalid value is provided for a REPEATED column."""


class InvalidType(Error):
  """Raised when an invalid type is provided for a column."""


class BigQueryTable(object):
  """Base class for all Upvote BigQuery table definitions."""

  def __init__(self, table_name, columns):
    self._table_name = table_name
    self._columns = columns

  def _ValidateInsertion(self, **kwargs):
    """Verifies that the row can be inserted into the target table.

    Verifies that the contents of kwargs matches up with the expectations of
    this particular table (e.g. names, types, required columns). If something
    doesn't match, raise an exception. This allows us to verify inserts in unit
    tests, and even if we miss something, we end up with a pile of
    FailedInsertion entities which can be repaired and/or retried.

    Args:
      **kwargs: Key/value pairs which correspond to the row being inserted.

    Raises:
      UnexpectedColumn: if an unexpected column is provided.
      MissingColumn: if an expected column is not provided.
      UnexpectedNull: if a non-nullable column is null.
      InvalidRepeated: if an invalid value is provided for a REPEATED column.
      InvalidType: if an invalid type is provided for a column.
    """
    column_map = {c.name: c for c in self._columns}

    # Verify that no unexpected columns are passed in.
    unexpected_columns = set(kwargs.keys()) - {c.name for c in self._columns}
    if unexpected_columns:
      raise UnexpectedColumn(sorted(list(unexpected_columns)))

    # Verify that all REQUIRED columns are present.
    required_columns = {
        c.name for c in self._columns if c.mode == MODE.REQUIRED}
    missing_columns = required_columns - set(kwargs.keys())
    if missing_columns:
      raise MissingColumn(sorted(list(missing_columns)))

    for k, v in kwargs.iteritems():

      column = column_map[k]
      expected_types = FIELD_TYPE_MAP[column.field_type]

      # Verify that all non-NULLABLE columns have values.
      if column.mode != MODE.NULLABLE and v is None:
        raise UnexpectedNull('Column %s is None' % k)

      # Verify that all REPEATED columns are lists.
      if column.mode == MODE.REPEATED and not isinstance(v, list):
        raise InvalidRepeated('Column %s is not a list' % k)

      # Verify that all REPEATED lists contain the correct type.
      if column.mode == MODE.REPEATED:
        for item in v:
          actual_type = type(item)
          if actual_type not in expected_types:
            raise InvalidType(
                'Column %s contains a value of type %s, must be one of %s' % (
                    k, actual_type.__name__, sorted(list(expected_types))))

      # Verify that all other field types match up.
      if column.mode != MODE.REPEATED:
        actual_type = type(v)
        if actual_type not in expected_types:
          raise InvalidType(
              'Column %s is of type %s, must be one of %s' % (
                  k, actual_type.__name__, sorted(list(expected_types))))

  def _CreateInsertionID(self, **kwargs):
    """Creates a unique insertion ID so BigQuery can dedupe repeated inserts.

    For more details, see:
    https://cloud.google.com/bigquery/streaming-data-into-bigquery#dataconsistency

    Args:
      **kwargs: The kwargs that InsertRow() is called with, representing the
          individual values of this particular row.

    Returns:
      A SHA256 hash of the provided row data.
    """
    # Collect all values for this row and join them into a single string. Ensure
    # that empty/omitted columns are represented as 'None'. Then SHA256 the
    # resulting string.
    row_str = '|'.join(str(kwargs.get(c.name)) for c in self._columns)
    return hashlib.sha256(row_str).hexdigest()

  def _DoInsertRow(self, **kwargs):
    """Performs the actual BigQuery row insertion.

    Args:
      **kwargs: The kwargs that InsertRow() is called with, representing the
          individual values of this particular row.
    """
    try:

      self._ValidateInsertion(**kwargs)
      row_id = self._CreateInsertionID(**kwargs)

      # Create the client and stream the row.
      bq_client = bigquery.Client()
      dataset = bq_client.dataset(constants.GAE_STREAMING_DATASET)
      table = dataset.table(self._table_name)
      table.insert_data([kwargs.items()], row_ids=[row_id])

      monitoring.row_insertions.Success()

    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while inserting row: %s', str(kwargs))
      monitoring.row_insertions.Failure()

      # If something breaks, dump the row into NDB so we can recover it.
      bigquery_models.FailedInsertion.Create(
          row_id, self._table_name, **kwargs)

  def InsertRow(self, **kwargs):
    deferred.defer(
        self._DoInsertRow, _queue=constants.TASK_QUEUE.BIGQUERY_STREAMING,
        **kwargs)


BINARY = BigQueryTable(
    constants.GAE_STREAMING_TABLES.BINARY, [
        Column(name='sha256'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action'),
        Column(name='state'),
        Column(name='score', field_type=FIELD_TYPE.INTEGER),
        Column(name='platform'),
        Column(name='client'),
        Column(name='first_seen_file_name', mode=MODE.NULLABLE),
        Column(name='cert_fingerprint', mode=MODE.NULLABLE),
        Column(name='comment', mode=MODE.NULLABLE)])


BUNDLE = BigQueryTable(
    constants.GAE_STREAMING_TABLES.BUNDLE, [
        Column(name='bundle_hash'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action'),
        Column(name='bundle_id'),
        Column(name='version'),
        Column(name='state'),
        Column(name='score', field_type=FIELD_TYPE.INTEGER),
        Column(name='comment', mode=MODE.NULLABLE)])


BUNDLE_BINARY = BigQueryTable(
    constants.GAE_STREAMING_TABLES.BUNDLE_BINARY, [
        Column(name='bundle_hash'),
        Column(name='sha256'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action'),
        Column(name='cert_fingerprint', mode=MODE.NULLABLE),
        Column(name='relative_path'),
        Column(name='file_name')])


CERTIFICATE = BigQueryTable(
    constants.GAE_STREAMING_TABLES.CERTIFICATE, [
        Column(name='fingerprint'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action'),
        Column(name='common_name'),
        Column(name='organization'),
        Column(name='organizational_unit'),
        Column(name='not_before', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='not_after', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='state'),
        Column(name='score', field_type=FIELD_TYPE.INTEGER),
        Column(name='comment', mode=MODE.NULLABLE)])


EXECUTION = BigQueryTable(
    constants.GAE_STREAMING_TABLES.EXECUTION, [
        Column(name='sha256'),
        Column(name='device_id'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='platform'),
        Column(name='client'),
        Column(name='bundle_path'),
        Column(name='file_path'),
        Column(name='file_name'),
        Column(name='executing_user'),
        Column(name='associated_users', mode=MODE.REPEATED),
        Column(name='decision'),
        Column(name='comment', mode=MODE.NULLABLE)])

HOST = BigQueryTable(
    constants.GAE_STREAMING_TABLES.HOST, [
        Column(name='device_id'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action'),
        Column(name='hostname'),
        Column(name='platform'),
        Column(name='users', mode=MODE.REPEATED),
        Column(name='mode'),
        Column(name='comment', mode=MODE.NULLABLE)])


USER = BigQueryTable(
    constants.GAE_STREAMING_TABLES.USER, [
        Column(name='email'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action'),
        Column(name='roles', mode=MODE.REPEATED),
        Column(name='comment', mode=MODE.NULLABLE)])


VOTE = BigQueryTable(
    constants.GAE_STREAMING_TABLES.VOTE, [
        Column(name='sha256'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='upvote', field_type=FIELD_TYPE.BOOLEAN),
        Column(name='weight', field_type=FIELD_TYPE.INTEGER),
        Column(name='platform'),
        Column(name='target_type'),
        Column(name='voter')])

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
import time

import upvote.gae.shared.common.google_cloud_lib_fixer  # pylint: disable=unused-import
# pylint: disable=g-bad-import-order,g-import-not-at-top
from google.cloud import bigquery
from google.cloud import exceptions

from google.appengine.ext import deferred

from upvote.gae.bigquery import monitoring
from upvote.gae.shared.common import settings
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


Column = collections.namedtuple(
    'Column', ['name', 'field_type', 'mode', 'choices'])
Column.__new__.__defaults__ = (None, FIELD_TYPE.STRING, MODE.REQUIRED, set())  # pylint: disable=protected-access


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


class InvalidValue(Error):
  """Raised when an invalid value is provided for a column."""


class StreamingFailure(Error):
  """Raised when the BigQuery client returns an error while streaming a row."""


def _Sleep(mins):
  """Calls time.sleep(). Exists solely for better unit testing.

  Args:
    mins: The number of minutes to sleep().
  """
  time.sleep(mins * 60)


def _RowValueToStr(v):
  """Converts a row value to a string, primarily for safe row ID creation.

  Args:
    v: The row value to convert to a string.

  Returns:
    A string representation of the provided value.
  """
  if isinstance(v, list):
    return str([_RowValueToStr(i) for i in v])
  elif isinstance(v, unicode):
    return v.encode('ascii', 'replace')
  else:
    return str(v)


def _SendToBigQuery(table, row_dict):
  """Sends a row to BigQuery.

  For a reference of the possible errors that the BigQuery API can return, see:
  https://cloud.google.com/bigquery/troubleshooting-errors#errortable

  Args:
    table: The BigQueryTable object doing the sending.
    row_dict: A dict representing the row to be sent.

  Raises:
    StreamingFailure: if the row could not be sent to BigQuery.
  """
  client = bigquery.Client()

  # Attempt the initial row insertion.
  try:
    dataset_ref = client.dataset(constants.BIGQUERY_DATASET)
    table_ref = dataset_ref.table(table.name)
    schema = table.schema
    row_id = table.CreateRowId(**row_dict)
    errors = client.insert_rows(
        table_ref, [row_dict], selected_fields=schema, row_ids=[row_id])

  # If we get a 404, ensure the dataset and table exist, then try again.
  except exceptions.NotFound:

    # See if the destination dataset exists.
    try:
      client.get_dataset(dataset_ref)
      logging.info('Dataset "%s" exists', constants.BIGQUERY_DATASET)

    # If it doesn't, then try to create it. We're probably racing against other
    # rows, so just ignore 409s.
    except exceptions.NotFound:
      logging.info('Creating dataset "%s"', constants.BIGQUERY_DATASET)
      try:
        client.create_dataset(bigquery.Dataset(dataset_ref))
      except exceptions.Conflict:
        logging.info(
            'Dataset "%s" was already created', constants.BIGQUERY_DATASET)
      else:
        logging.info('Dataset "%s" created', constants.BIGQUERY_DATASET)

    # See if the destination table exists.
    try:
      client.get_table(table_ref)
      logging.info('Table "%s" exists', table.name)

    # If it doesn't, then try to create it. We're probably racing against other
    # rows, so just ignore 409s.
    except exceptions.NotFound:
      logging.info('Creating table "%s"', table.name)
      try:
        client.create_table(bigquery.Table(table_ref, schema=schema))
      except exceptions.Conflict:
        logging.info('Table "%s" has already been created', table.name)
      else:
        logging.info('Table "%s" successfully created', table.name)

    # Attempt the row insertion again. Apparently insertion 404s are cached
    # until the table creation fully propagates, so attempt the insertion a few
    # times with increasing delays before giving up and letting the taskqueue
    # retry it.
    for mins in xrange(1, 6):
      logging.info(
          'Waiting %dm for table "%s" to be ready', mins, table.name)
      _Sleep(mins)
      try:
        errors = client.insert_rows(
            table_ref, [row_dict], selected_fields=schema, row_ids=[row_id])
      except exceptions.NotFound:
        logging.info('Table "%s" is still not ready', table.name)
      else:
        break

  # If the client returns errors, raise a StreamingFailure.
  if errors:
    error_str = ', '.join(str(e) for e in errors)
    msg = 'The BigQuery client returned errors: %s' % error_str
    logging.error(msg)
    raise StreamingFailure(msg)

  logging.info('Successfully streamed row to "%s" table', table.name)


class BigQueryTable(object):
  """Base class for all Upvote BigQuery table definitions."""

  def __init__(self, name, columns):
    self._name = name
    self._columns = columns

  @property
  def name(self):
    return self._name

  @property
  def schema(self):
    return [
        bigquery.SchemaField(column.name, column.field_type, mode=column.mode)
        for column in self._columns]

  def _ValidateInsertion(self, **kwargs):
    """Verifies that the row can be inserted into the target table.

    Verifies that the contents of kwargs matches up with the expectations of
    this particular table (e.g. names, types, columns). If something doesn't
    match, raise an exception.

    Args:
      **kwargs: Key/value pairs which correspond to the row being inserted.

    Raises:
      UnexpectedColumn: if an unexpected column is provided.
      MissingColumn: if an expected column is not provided.
      UnexpectedNull: if a non-nullable column is null.
      InvalidRepeated: if an invalid value is provided for a REPEATED column.
      InvalidType: if an invalid type is provided for a column.
      InvalidValue: if an invalid value is provided for a column.
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
        raise UnexpectedNull('Column "%s" is None' % k)

      # Verify that all REPEATED columns are lists.
      if column.mode == MODE.REPEATED and not isinstance(v, list):
        raise InvalidRepeated('Column "%s" is not a list' % k)

      # Verify that all REPEATED lists contain the correct type.
      if column.mode == MODE.REPEATED:
        for item in v:
          actual_type = type(item)
          if actual_type not in expected_types:
            raise InvalidType(
                'Column "%s" contains a value of type %s, must be one of %s' % (
                    k, actual_type.__name__, sorted(list(expected_types))))

      # Verify that all REQUIRED fields contain the correct type.
      if column.mode == MODE.REQUIRED:
        actual_type = type(v)
        if actual_type not in expected_types:
          raise InvalidType(
              'Column "%s" is of type %s, must be one of %s' % (
                  k, actual_type.__name__, sorted(list(expected_types))))

      # Verify that all values are allowed if the column specifies choices.
      if column.choices:
        v = v if column.mode == MODE.REPEATED else [v]
        for item in v:
          if item not in column.choices:
            raise InvalidValue(
                'Column "%s" contains an invalid value: %s' % (k, item))

  def CreateRowId(self, **kwargs):
    """Creates a unique row ID so BigQuery can dedupe repeated inserts.

    For more details, see:
    https://cloud.google.com/bigquery/streaming-data-into-bigquery#dataconsistency

    Args:
      **kwargs: The kwargs that InsertRow() is called with, representing the
          individual values of this particular row.

    Returns:
      A SHA256 hash of the provided row data.
    """
    # Collect all values for this row and join them into a single string. Ensure
    # that empty/omitted columns are represented as 'None'. Then concatenate
    # everything and SHA256 the resulting string.
    row_values = [_RowValueToStr(kwargs.get(c.name)) for c in self._columns]
    row_str = '|'.join(row_values)
    return hashlib.sha256(row_str).hexdigest()

  def _DoInsertRow(self, **kwargs):
    """Performs the actual BigQuery row insertion.

    Args:
      **kwargs: The kwargs that InsertRow() is called with, representing the
          individual values of this particular row.
    """
    try:
      self._ValidateInsertion(**kwargs)
      _SendToBigQuery(self, kwargs)
      monitoring.row_insertions.Success()

    except Exception:  # pylint: disable=broad-except
      logging.exception(
          'Error encountered while inserting the following row into the %s '
          'table: %s', self.name, str(kwargs))
      monitoring.row_insertions.Failure()

  def InsertRow(self, **kwargs):
    if settings.ENV.ENABLE_BIGQUERY_STREAMING:
      logging.info('Sending a row to BigQuery %s table', self.name)
      deferred.defer(
          self._DoInsertRow, _queue=constants.TASK_QUEUE.BIGQUERY_STREAMING,
          **kwargs)
    else:
      logging.info('Skipping row for BigQuery %s table', self.name)


BINARY = BigQueryTable(
    constants.BIGQUERY_TABLE.BINARY, [
        Column(name='sha256'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action', choices=constants.BLOCK_ACTION.SET_ALL),
        Column(name='state', choices=constants.STATE.SET_ALL),
        Column(name='score', field_type=FIELD_TYPE.INTEGER),
        Column(name='platform', choices=constants.PLATFORM.SET_ALL),
        Column(name='client', choices=constants.CLIENT.SET_ALL),
        Column(name='first_seen_file_name', mode=MODE.NULLABLE),
        Column(name='cert_fingerprint', mode=MODE.NULLABLE),
        Column(name='comment', mode=MODE.NULLABLE)])


BUNDLE = BigQueryTable(
    constants.BIGQUERY_TABLE.BUNDLE, [
        Column(name='bundle_hash'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action', choices=constants.BLOCK_ACTION.SET_ALL),
        Column(name='bundle_id', mode=MODE.NULLABLE),
        Column(name='version', mode=MODE.NULLABLE),
        Column(name='state', choices=constants.STATE.SET_ALL),
        Column(name='score', field_type=FIELD_TYPE.INTEGER),
        Column(name='comment', mode=MODE.NULLABLE)])


BUNDLE_BINARY = BigQueryTable(
    constants.BIGQUERY_TABLE.BUNDLE_BINARY, [
        Column(name='bundle_hash'),
        Column(name='sha256'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action', choices=constants.BLOCK_ACTION.SET_ALL),
        Column(name='cert_fingerprint', mode=MODE.NULLABLE),
        Column(name='relative_path'),
        Column(name='file_name')])


# A number of Certificate columns must be NULLABLE in order to support
# administratively-created Certificate entities which won't have full X.509
# metadata.
CERTIFICATE = BigQueryTable(
    constants.BIGQUERY_TABLE.CERTIFICATE, [
        Column(name='fingerprint'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action', choices=constants.BLOCK_ACTION.SET_ALL),
        Column(name='common_name', mode=MODE.NULLABLE),
        Column(name='organization', mode=MODE.NULLABLE),
        Column(name='organizational_unit', mode=MODE.NULLABLE),
        Column(
            name='not_before',
            field_type=FIELD_TYPE.TIMESTAMP,
            mode=MODE.NULLABLE),
        Column(
            name='not_after',
            field_type=FIELD_TYPE.TIMESTAMP,
            mode=MODE.NULLABLE),
        Column(name='state', choices=constants.STATE.SET_ALL),
        Column(name='score', field_type=FIELD_TYPE.INTEGER),
        Column(name='comment', mode=MODE.NULLABLE)])


EXECUTION = BigQueryTable(
    constants.BIGQUERY_TABLE.EXECUTION, [
        Column(name='sha256'),
        Column(name='device_id'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='platform', choices=constants.PLATFORM.SET_ALL),
        Column(name='client', choices=constants.CLIENT.SET_ALL),
        Column(name='bundle_path', mode=MODE.NULLABLE),  # Not on all platforms.
        Column(name='file_path'),
        Column(name='file_name'),
        Column(name='executing_user'),
        Column(name='associated_users', mode=MODE.REPEATED),
        Column(name='decision', choices=constants.EVENT_TYPE.SET_ALL),
        Column(name='comment', mode=MODE.NULLABLE)])

HOST = BigQueryTable(
    constants.BIGQUERY_TABLE.HOST, [
        Column(name='device_id'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action', choices=constants.HOST_ACTION.SET_ALL),
        Column(name='hostname'),
        Column(name='platform', choices=constants.PLATFORM.SET_ALL),
        Column(name='users', mode=MODE.REPEATED),
        Column(name='mode', choices=constants.HOST_MODE.SET_ALL),
        Column(name='comment', mode=MODE.NULLABLE)])


USER = BigQueryTable(
    constants.BIGQUERY_TABLE.USER, [
        Column(name='email'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='action', choices=constants.USER_ACTION.SET_ALL),
        Column(name='roles', mode=MODE.REPEATED),
        Column(name='comment', mode=MODE.NULLABLE)])


VOTE = BigQueryTable(
    constants.BIGQUERY_TABLE.VOTE, [
        Column(name='sha256'),
        Column(name='timestamp', field_type=FIELD_TYPE.TIMESTAMP),
        Column(name='upvote', field_type=FIELD_TYPE.BOOLEAN),
        Column(name='weight', field_type=FIELD_TYPE.INTEGER),
        Column(name='platform', choices=constants.PLATFORM.SET_ALL),
        Column(name='target_type', choices=constants.RULE_TYPE.SET_ALL),
        Column(name='voter')])
